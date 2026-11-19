//! Runs the analyzers with a time limit on every call.
//!
//! A thread cannot be stopped from outside, so a call that overruns is left behind: its thread
//! keeps running, its result is ignored, the report records a limitation, and a fresh thread takes
//! over the remaining work. The run therefore always finishes; a left-behind thread ends with the
//! process.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aa_core::Limitation;
use aa_core::plugin::{Analyzer, Output};

use crate::guarded;
use crate::tree::BuiltTree;

/// How often the coordinator looks for calls that have overrun.
const WATCH_INTERVAL: Duration = Duration::from_millis(50);

pub fn timeout_detail(analyzer: &str, timeout: Duration) -> String {
    format!("{analyzer}: no result after {} seconds", timeout.as_secs())
}

/// A lock that keeps working after a thread panicked while holding it; the data is plain state.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Work waiting for a thread: `(artifact index, first analyzer still to run)`.
struct Queue {
    items: Mutex<(VecDeque<(usize, usize)>, bool)>,
    ready: Condvar,
}

impl Queue {
    fn push(&self, item: (usize, usize)) {
        lock(&self.items).0.push_back(item);
        self.ready.notify_one();
    }

    /// The next item, or `None` once the queue is closed and empty.
    fn pop(&self) -> Option<(usize, usize)> {
        let mut state = lock(&self.items);
        loop {
            if let Some(item) = state.0.pop_front() {
                return Some(item);
            }
            if state.1 {
                return None;
            }
            state = self.ready.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn close(&self) {
        lock(&self.items).1 = true;
        self.ready.notify_all();
    }
}

enum Message {
    /// One analyzer finished one artifact.
    Output { worker: usize, artifact: usize, analyzer: usize, output: Output },
    /// A worker finished every analyzer for an artifact.
    Done { worker: usize },
}

/// What a worker is running now and since when.
type Current = Arc<Mutex<Option<(usize, usize, Instant)>>>;

struct Pool {
    tree: Arc<BuiltTree>,
    analyzers: Vec<Arc<dyn Analyzer>>,
    queue: Arc<Queue>,
    results: mpsc::Sender<Message>,
    cancel: Option<Arc<AtomicBool>>,
    /// One entry per worker ever started; `None` once it was left behind.
    current: Vec<Option<Current>>,
    /// The threads, in the same order. A worker left behind is detached by dropping its handle.
    handles: Vec<Option<std::thread::JoinHandle<()>>>,
}

impl Pool {
    fn spawn(&mut self) {
        let worker = self.current.len();
        let current: Current = Arc::new(Mutex::new(None));
        self.current.push(Some(current.clone()));
        let (tree, analyzers, queue, results, cancel) =
            (self.tree.clone(), self.analyzers.clone(), self.queue.clone(), self.results.clone(), self.cancel.clone());
        let handle = std::thread::spawn(move || {
            while let Some((artifact, first)) = queue.pop() {
                let file = &tree.artifacts[artifact];
                let skip = file.digests.is_none() || cancel.as_ref().is_some_and(|flag| flag.load(Ordering::Relaxed));
                for (index, analyzer) in analyzers.iter().enumerate().skip(first) {
                    if skip {
                        break;
                    }
                    *lock(&current) = Some((artifact, index, Instant::now()));
                    let mut output = Output::default();
                    guarded(analyzer.as_ref(), Some(&file.path), &mut output, |out| analyzer.analyze_file(&*tree, file, out));
                    *lock(&current) = None;
                    if results.send(Message::Output { worker, artifact, analyzer: index, output }).is_err() {
                        return;
                    }
                }
                if results.send(Message::Done { worker }).is_err() {
                    return;
                }
            }
        });
        self.handles.push(Some(handle));
    }
}

/// Runs every analyzer over every artifact. Returns one merged output per artifact, in artifact
/// order with each artifact's results in analyzer order, and a limitation for each call given up on.
pub fn file_pass(
    tree: &Arc<BuiltTree>,
    analyzers: &[Arc<dyn Analyzer>],
    timeout: Duration,
    cancel: Option<Arc<AtomicBool>>,
) -> (Vec<Output>, Vec<Limitation>) {
    let count = tree.artifacts.len();
    let mut slots: Vec<Vec<Option<Output>>> = (0..count).map(|_| (0..analyzers.len()).map(|_| None).collect()).collect();
    let mut limitations = Vec::new();
    if count == 0 || analyzers.is_empty() {
        return (slots.into_iter().map(|_| Output::default()).collect(), limitations);
    }
    let queue = Arc::new(Queue { items: Mutex::new(((0..count).map(|artifact| (artifact, 0)).collect(), false)), ready: Condvar::new() });
    let (results, incoming) = mpsc::channel();
    let mut pool = Pool {
        tree: tree.clone(),
        analyzers: analyzers.to_vec(),
        queue: queue.clone(),
        results,
        cancel,
        current: Vec::new(),
        handles: Vec::new(),
    };
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2).min(count);
    for _ in 0..threads {
        pool.spawn();
    }

    let mut remaining = count;
    while remaining > 0 {
        match incoming.recv_timeout(WATCH_INTERVAL) {
            // Results from a worker that was left behind are ignored: its work was handed on.
            Ok(Message::Output { worker, artifact, analyzer, output }) if pool.current[worker].is_some() => {
                slots[artifact][analyzer] = Some(output);
            }
            Ok(Message::Done { worker }) if pool.current[worker].is_some() => remaining -= 1,
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        for worker in 0..pool.current.len() {
            let overrun =
                pool.current[worker].as_ref().and_then(|current| *lock(current)).filter(|(_, _, since)| since.elapsed() > timeout);
            let Some((artifact, analyzer, _)) = overrun else { continue };
            pool.current[worker] = None;
            pool.handles[worker] = None;
            let path = tree.artifacts[artifact].path.as_str();
            limitations.push(Limitation::new("analyzer_timeout", Some(path), Some(timeout_detail(analyzers[analyzer].id(), timeout))));
            // The other analyzers still get their turn on this artifact, on a fresh thread.
            queue.push((artifact, analyzer + 1));
            pool.spawn();
        }
    }
    queue.close();
    // Workers that are not stuck finish at once now that the queue is closed; wait for them, so
    // nothing of this pass is still running when it returns.
    for handle in pool.handles.drain(..).flatten() {
        let _ = handle.join();
    }

    let outputs = slots
        .into_iter()
        .map(|per_analyzer| {
            let mut merged = Output::default();
            for mut output in per_analyzer.into_iter().flatten() {
                merged.findings.append(&mut output.findings);
                merged.facts.append(&mut output.facts);
                merged.kinds.append(&mut output.kinds);
                merged.limitations.append(&mut output.limitations);
            }
            merged
        })
        .collect();
    (outputs, limitations)
}

/// Runs one analyzer over the tree as a whole. `None` when it did not finish in time.
pub fn tree_pass(tree: &BuiltTree, analyzer: &Arc<dyn Analyzer>, timeout: Duration) -> Option<Output> {
    // The call may outlive this function, so it works on its own copy of the tree.
    let snapshot = Arc::new(tree.clone());
    let analyzer = analyzer.clone();
    let (done, finished) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut output = Output::default();
        guarded(analyzer.as_ref(), None, &mut output, |out| analyzer.analyze_tree(&*snapshot, out));
        let _ = done.send(output);
    });
    let output = finished.recv_timeout(timeout).ok();
    // A call that answered is about to end; wait for it. One that did not is left behind.
    if output.is_some() {
        let _ = handle.join();
    }
    output
}
