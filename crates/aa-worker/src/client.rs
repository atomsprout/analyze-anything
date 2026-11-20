//! The app's side: starts a worker process, talks to it, and ends it for certain.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::protocol::{Request, Response};

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("cannot start the worker: {0}")]
    Start(std::io::Error),
    #[error("cannot prepare the worker's scratch folder: {0}")]
    Scratch(std::io::Error),
    #[error("the worker is gone: {0}")]
    Gone(String),
    #[error("the worker did not answer in time")]
    Timeout,
}

/// A running worker process and the scratch folder it unpacks into.
///
/// Dropping a `Worker` ends the process, by force if need be, and removes the scratch folder,
/// so nothing is left behind whatever state the worker was in.
pub struct Worker {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: Receiver<Response>,
    scratch: PathBuf,
    _ownership: std::fs::File,
}

impl Worker {
    /// Starts `program` with `arguments` as a worker. `scratch_root` is where its private
    /// scratch folder is made; the folder is removed when the worker is dropped.
    pub fn start(program: &Path, arguments: &[&str], scratch_root: &Path) -> Result<Worker, WorkerError> {
        let arguments: Vec<std::ffi::OsString> = arguments.iter().map(std::ffi::OsString::from).collect();
        Self::start_os(program, &arguments, scratch_root)
    }

    /// Like start, preserving native argument encoding for paths passed by the CLI.
    pub fn start_os(program: &Path, arguments: &[std::ffi::OsString], scratch_root: &Path) -> Result<Worker, WorkerError> {
        std::fs::create_dir_all(scratch_root).map_err(WorkerError::Scratch)?;
        crate::scratch::sweep(scratch_root);
        let scratch = unique_folder(scratch_root).map_err(WorkerError::Scratch)?;
        let ownership = crate::scratch::hold(&scratch).map_err(WorkerError::Scratch)?;
        let mut command = Command::new(program);
        command
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // What a worker writes to its error output is for whoever debugs it, not for us.
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // A desktop worker communicates through pipes and needs no console window.
            command.creation_flags(0x0800_0000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // The supervisor handles terminal cancellation before asking the worker to stop.
            command.process_group(0);
        }
        let mut child = command.spawn().map_err(|error| {
            let _ = std::fs::remove_dir_all(&scratch);
            WorkerError::Start(error)
        })?;
        let stdin = child.stdin.take();
        let (sender, responses) = std::sync::mpsc::channel();
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    // A line that is not a response is dropped: a worker cannot make us fail.
                    if let Ok(response) = serde_json::from_str::<Response>(&line)
                        && sender.send(response).is_err()
                    {
                        break;
                    }
                }
            });
        }
        Ok(Worker { child, stdin, responses, scratch, _ownership: ownership })
    }

    /// The folder the worker is told to unpack into.
    pub fn scratch(&self) -> &Path {
        &self.scratch
    }

    /// Sends a request. An error means the worker is no longer reading.
    pub fn send(&mut self, request: &Request) -> Result<(), WorkerError> {
        let stdin = self.stdin.as_mut().ok_or_else(|| WorkerError::Gone("its input is closed".into()))?;
        let mut line = serde_json::to_vec(request).map_err(|e| WorkerError::Gone(e.to_string()))?;
        line.push(b'\n');
        stdin.write_all(&line).and_then(|()| stdin.flush()).map_err(|e| WorkerError::Gone(e.to_string()))
    }

    /// Asks for the analysis of `path`, unpacking into this worker's scratch folder.
    pub fn analyze(&mut self, path: &Path, limits: crate::protocol::LimitOverrides) -> Result<(), WorkerError> {
        let request = Request::Analyze { path: path.to_path_buf(), scratch: self.scratch.clone(), limits };
        self.send(&request)
    }

    /// The next response, waiting up to `timeout` for it.
    pub fn receive(&mut self, timeout: Duration) -> Result<Response, WorkerError> {
        match self.responses.recv_timeout(timeout) {
            Ok(response) => Ok(response),
            Err(RecvTimeoutError::Timeout) => Err(WorkerError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(WorkerError::Gone(self.exit_text())),
        }
    }

    /// True while the process has not ended.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Ends the worker: asks it to close, waits up to `grace`, then kills it. Returns true when
    /// it ended on its own.
    pub fn stop(&mut self, grace: Duration) -> bool {
        let _ = self.send(&Request::Cancel);
        let _ = self.send(&Request::Close);
        // Closing its input also tells a worker that reads nothing else to finish.
        self.stdin.take();
        let deadline = Instant::now() + grace;
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return true,
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
                _ => break,
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        false
    }

    fn exit_text(&mut self) -> String {
        // A process closes its output a moment before its exit status can be read; give it
        // that moment, so that a crash is reported with its status.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return format!("it ended with {status}"),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => return "it closed its output".into(),
                Err(error) => return error.to_string(),
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stdin.take();
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// Makes a new, empty folder in `root` whose name no other worker has.
fn unique_folder(root: &Path) -> std::io::Result<PathBuf> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    for attempt in 0..100u32 {
        let path = root.join(format!("worker-{}-{stamp:x}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::other("no free name for a scratch folder"))
}
