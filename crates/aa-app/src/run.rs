//! One analysis, running in a worker process, as the user interface sees it.
//!
//! [`Run::start`] starts the worker and returns at once. What happens next arrives through the
//! callback as [`Update`]s, from a thread that belongs to the run: progress, then exactly one of
//! a report, a failure, or the word that the run was cancelled. After a report the worker is kept
//! so that the report's evidence can be read ([`Run::read`]) until the run is dropped.
//!
//! Cancelling is certain: the worker is asked to stop, and if it has not within
//! [`CANCEL_GRACE`] it is killed. Either way its scratch folder is removed.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use aa_core::Report;
use aa_engine::Event;
use aa_worker::protocol::{LimitOverrides, Request, Response};
use aa_worker::{Worker, WorkerError};

/// How long a worker that was asked to stop has before it is killed.
pub const CANCEL_GRACE: Duration = Duration::from_secs(5);
/// How long reading evidence bytes may take before the request is given up on.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the run's thread looks for commands while it waits for the worker.
const TICK: Duration = Duration::from_millis(40);

/// How to start a worker process.
#[derive(Debug, Clone)]
pub struct Program {
    pub path: PathBuf,
    pub arguments: Vec<String>,
    /// Folder in which each worker gets its scratch folder.
    pub scratch_root: PathBuf,
}

/// What a run tells whoever started it.
#[derive(Debug, Clone, PartialEq)]
pub enum Update {
    Progress(Event),
    /// The analysis finished. The run stays readable until it is dropped.
    Done(Box<Report>),
    /// The analysis could not be done, or the worker died. The text says which.
    Failed(String),
    /// The run was cancelled and has ended.
    Cancelled,
}

/// Bytes of an artifact, and how large the artifact is in all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    pub bytes: Vec<u8>,
    pub size: u64,
}

enum Command {
    Cancel,
    Read { path: String, offset: u64, length: u64, reply: Sender<Result<Chunk, String>> },
}

/// A running or finished analysis. Dropping it ends the worker and removes what it unpacked.
pub struct Run {
    commands: Sender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Run {
    /// Starts analyzing `input`. `on_update` is called from the run's own thread.
    pub fn start(
        program: &Program,
        input: &Path,
        limits: LimitOverrides,
        on_update: impl FnMut(Update) + Send + 'static,
    ) -> Result<Run, WorkerError> {
        let arguments: Vec<&str> = program.arguments.iter().map(String::as_str).collect();
        let mut worker = Worker::start(&program.path, &arguments, &program.scratch_root)?;
        worker.analyze(input, limits)?;
        let (commands, inbox) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || drive(worker, inbox, on_update));
        Ok(Run { commands, thread: Some(thread) })
    }

    /// Asks the run to stop. [`Update::Cancelled`] follows, within [`CANCEL_GRACE`] at the latest,
    /// unless the run had already ended.
    pub fn cancel(&self) {
        let _ = self.commands.send(Command::Cancel);
    }

    /// Reads up to `length` bytes of the artifact at `path` from `offset`. Works once the report
    /// has arrived.
    pub fn read(&self, path: &str, offset: u64, length: u64) -> Result<Chunk, String> {
        let (reply, answer) = std::sync::mpsc::channel();
        let gone = || "the analysis this report came from is no longer open".to_string();
        self.commands.send(Command::Read { path: path.to_string(), offset, length, reply }).map_err(|_| gone())?;
        answer.recv_timeout(READ_TIMEOUT + Duration::from_secs(1)).map_err(|_| gone())?
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        // Closing the channel ends the thread, which drops the worker: process and scratch go.
        let (closed, _) = std::sync::mpsc::channel();
        self.commands = closed;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The run's thread: carries messages between the worker and the callers until the run is dropped.
fn drive(mut worker: Worker, inbox: Receiver<Command>, mut on_update: impl FnMut(Update)) {
    let mut cancelled_at: Option<Instant> = None;
    let mut finished = false;
    let mut next_id = 0u64;
    loop {
        // Once the report is in there is nothing to wait for but commands.
        let command = if finished { inbox.recv().map_err(|_| TryRecvError::Disconnected) } else { inbox.try_recv() };
        match command {
            Ok(Command::Cancel) if !finished && cancelled_at.is_none() => {
                cancelled_at = Some(Instant::now());
                let _ = worker.send(&Request::Cancel);
            }
            Ok(Command::Cancel) => {}
            Ok(Command::Read { path, offset, length, reply }) => {
                next_id += 1;
                let _ = reply.send(read(&mut worker, finished, next_id, path, offset, length));
            }
            Err(TryRecvError::Empty) => {}
            // The run was dropped.
            Err(TryRecvError::Disconnected) => return,
        }
        if finished {
            continue;
        }
        if cancelled_at.is_some_and(|at| at.elapsed() > CANCEL_GRACE) {
            worker.stop(Duration::ZERO);
            on_update(Update::Cancelled);
            return wait_for_drop(inbox);
        }
        match worker.receive(TICK) {
            Ok(Response::Progress { step }) if cancelled_at.is_none() => on_update(Update::Progress(step)),
            Ok(Response::Progress { .. }) => {}
            // A cancelled run still reports what it had; the user asked for none of it.
            Ok(Response::Report { .. }) if cancelled_at.is_some() => {
                worker.stop(CANCEL_GRACE);
                on_update(Update::Cancelled);
                return wait_for_drop(inbox);
            }
            Ok(Response::Report { report }) => {
                finished = true;
                on_update(Update::Done(report));
            }
            Ok(Response::Error { id: None, message }) => {
                on_update(if cancelled_at.is_some() { Update::Cancelled } else { Update::Failed(message) });
                return wait_for_drop(inbox);
            }
            // Answers to reads are taken where the read is made; a stray one is of no use.
            Ok(Response::Bytes { .. } | Response::Error { id: Some(_), .. }) => {}
            Err(WorkerError::Timeout) => {}
            Err(error) => {
                on_update(if cancelled_at.is_some() { Update::Cancelled } else { Update::Failed(error.to_string()) });
                return wait_for_drop(inbox);
            }
        }
    }
}

/// After the run has ended without a report: answers reads with an error until the run is dropped.
fn wait_for_drop(inbox: Receiver<Command>) {
    for command in inbox {
        if let Command::Read { reply, .. } = command {
            let _ = reply.send(Err("the analysis did not finish, so there is nothing to read".into()));
        }
    }
}

fn read(worker: &mut Worker, finished: bool, id: u64, path: String, offset: u64, length: u64) -> Result<Chunk, String> {
    if !finished {
        return Err("the analysis is still running".into());
    }
    worker.send(&Request::ReadBytes { id, path, offset, length }).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + READ_TIMEOUT;
    loop {
        match worker.receive(deadline.saturating_duration_since(Instant::now())) {
            Ok(Response::Bytes { id: answered, hex, size }) if answered == id => {
                let bytes = decode_hex(&hex).ok_or_else(|| "the worker sent bytes that cannot be read".to_string())?;
                return Ok(Chunk { bytes, size });
            }
            Ok(Response::Error { id: Some(answered), message }) if answered == id => return Err(message),
            // Anything else is left over from before; keep waiting for our answer.
            Ok(_) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes().chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()).collect()
}
