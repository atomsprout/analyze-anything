//! The worker's side: reads requests, runs the engine, writes responses.

use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use aa_engine::{Event, Options, ProgressSink, Registry, Session};

use crate::protocol::{MAX_CHUNK, Request, Response};

/// Longest a request line may be. Requests are small; this only stops a runaway sender.
const MAX_REQUEST: usize = 1024 * 1024;
/// Per-file progress is sent at most this often: a tree of fifty thousand files would otherwise
/// produce far more lines than anyone can draw.
const PROGRESS_INTERVAL: Duration = Duration::from_millis(40);

/// A lock that keeps working after a thread panicked while holding it.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

type Out = Arc<Mutex<Box<dyn Write + Send>>>;

/// Writes one response as a line. A reader that went away is not an error worth dying for.
fn send(out: &Out, response: &Response) {
    let Ok(mut line) = serde_json::to_vec(response) else { return };
    line.push(b'\n');
    let mut out = lock(out);
    let _ = out.write_all(&line).and_then(|()| out.flush());
}

struct Forward {
    out: Out,
    last: Option<Instant>,
}

impl ProgressSink for Forward {
    fn event(&mut self, event: Event) {
        // The steps that come once per file are thinned out; everything else is always sent.
        if matches!(event, Event::Reading { .. } | Event::Analyzed { .. }) {
            if self.last.is_some_and(|at| at.elapsed() < PROGRESS_INTERVAL) {
                return;
            }
            self.last = Some(Instant::now());
        }
        send(&self.out, &Response::Progress { step: event });
    }
}

/// Serves requests from `input` until it ends or a `close` arrives, writing responses to `output`.
///
/// Returns when the conversation is over. An analysis still running at that point is told to
/// stop and is waited for, so nothing of it outlives this call.
pub fn serve(input: impl BufRead, output: impl Write + Send + 'static) {
    let out: Out = Arc::new(Mutex::new(Box::new(output)));
    let cancel = Arc::new(AtomicBool::new(false));
    let session: Arc<Mutex<Option<Session>>> = Arc::new(Mutex::new(None));
    let mut running: Option<std::thread::JoinHandle<()>> = None;
    let mut started = false;

    for line in lines(input) {
        let request = match line.and_then(|line| serde_json::from_str::<Request>(&line).map_err(|e| e.to_string())) {
            Ok(request) => request,
            Err(message) => {
                send(&out, &Response::Error { id: None, message: format!("not a request: {message}") });
                continue;
            }
        };
        match request {
            Request::Analyze { .. } if started => {
                send(&out, &Response::Error { id: None, message: "this worker already has its analysis".into() });
            }
            Request::Analyze { path, scratch, limits } => {
                started = true;
                let (out, cancel, session) = (out.clone(), cancel.clone(), session.clone());
                running = Some(std::thread::spawn(move || {
                    let options = Options { limits: limits.apply(), cancel: Some(cancel), temp_root: Some(scratch) };
                    let mut progress = Forward { out: out.clone(), last: None };
                    match aa_engine::analyze_session(&Registry::standard(), &path, &options, &mut progress) {
                        Ok(done) => {
                            let report = Box::new(done.report().clone());
                            *lock(&session) = Some(done);
                            send(&out, &Response::Report { report });
                        }
                        Err(error) => send(&out, &Response::Error { id: None, message: error.to_string() }),
                    }
                }));
            }
            Request::Cancel => cancel.store(true, Ordering::Relaxed),
            Request::ReadBytes { id, path, offset, length } => {
                let answer = match lock(&session).as_ref() {
                    None => Response::Error { id: Some(id), message: "no finished analysis to read from".into() },
                    Some(session) => {
                        let size = session.report().artifacts.iter().find(|a| a.path == path).map(|a| a.size);
                        match (size, session.read(&path, offset, length.min(MAX_CHUNK))) {
                            (Some(size), Ok(bytes)) => Response::Bytes { id, hex: hex::encode(bytes), size },
                            (None, _) => Response::Error { id: Some(id), message: format!("no artifact at {path}") },
                            (_, Err(error)) => Response::Error { id: Some(id), message: error.to_string() },
                        }
                    }
                };
                send(&out, &answer);
            }
            Request::Close => break,
        }
    }
    // The other side is gone or done with us: stop what is running and let the session go,
    // which removes what it unpacked.
    cancel.store(true, Ordering::Relaxed);
    if let Some(handle) = running {
        let _ = handle.join();
    }
    lock(&session).take();
}

/// The lines of `input`, each cut off at [`MAX_REQUEST`] bytes. Ends at end of input or on a
/// read error.
fn lines(mut input: impl BufRead) -> impl Iterator<Item = Result<String, String>> {
    std::iter::from_fn(move || {
        let mut line = Vec::new();
        let mut too_long = false;
        loop {
            let available = match input.fill_buf() {
                Ok([]) | Err(_) => return (!line.is_empty() || too_long).then(|| finish(line, too_long)),
                Ok(available) => available,
            };
            let (take, ended) = match available.iter().position(|byte| *byte == b'\n') {
                Some(newline) => (newline + 1, true),
                None => (available.len(), false),
            };
            if line.len() + take > MAX_REQUEST {
                too_long = true;
                line.clear();
            } else if !too_long {
                line.extend_from_slice(&available[..take]);
            }
            input.consume(take);
            if ended {
                return Some(finish(line, too_long));
            }
        }
    })
    .filter(|line| !matches!(line, Ok(text) if text.trim().is_empty()))
}

fn finish(line: Vec<u8>, too_long: bool) -> Result<String, String> {
    if too_long {
        return Err(format!("a request longer than {MAX_REQUEST} bytes"));
    }
    String::from_utf8(line).map_err(|_| "a request that is not UTF-8".to_string())
}
