//! The CLI owns process lifetime; only a completed worker report reaches exports or AI.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use aa_core::Report;
use aa_engine::{Limits, ProgressSink};
use aa_worker::protocol::{LimitOverrides, Request, Response};
use aa_worker::{Worker, WorkerError};

struct SignalLifetime(Arc<AtomicBool>);

impl Drop for SignalLifetime {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

pub fn analyze(path: &Path, limits: &Limits, seconds: Option<u64>, progress: &mut dyn ProgressSink) -> Result<Report, String> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    let active = Arc::new(AtomicBool::new(true));
    let _lifetime = SignalLifetime(active.clone());
    ctrlc::set_handler(move || {
        if active.load(Ordering::Relaxed) {
            signal.store(true, Ordering::Relaxed);
        } else {
            // Export and optional interpretation must remain interruptible after the worker ends.
            std::process::exit(130);
        }
    })
    .map_err(|e| format!("cannot register cancellation: {e}"))?;
    let deadline = seconds.map(|s| Instant::now().checked_add(Duration::from_secs(s)).ok_or("run timeout is too large")).transpose()?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut arguments: Vec<_> = crate::arguments().into_iter().skip(1).collect();
    arguments.push("--analysis-worker".into());
    let scratch_root = std::env::temp_dir().join("analyze-anything-workers");
    aa_engine::validate_scratch_root(path, &scratch_root).map_err(|e| e.to_string())?;
    let mut worker = Worker::start_os(&executable, &arguments, &scratch_root).map_err(|e| e.to_string())?;
    worker
        .analyze(
            path,
            LimitOverrides {
                max_files: Some(limits.max_files),
                max_depth: Some(limits.max_depth),
                max_unpacked_bytes: Some(limits.max_unpacked_bytes),
                max_entry_bytes: Some(limits.max_entry_bytes),
                analyzer_seconds: Some(limits.analyzer_seconds),
                unpack_seconds: Some(limits.unpack_seconds),
            },
        )
        .map_err(|e| e.to_string())?;
    let mut stopping: Option<(&str, Instant)> = None;
    loop {
        if stopping.is_none() && (cancelled.load(Ordering::Relaxed) || deadline.is_some_and(|end| Instant::now() >= end)) {
            let reason = if cancelled.load(Ordering::Relaxed) { "analysis cancelled" } else { "whole analysis timeout reached" };
            eprintln!("warning: {reason}; asking the worker for a partial report");
            worker.send(&Request::Cancel).map_err(|e| e.to_string())?;
            stopping = Some((reason, Instant::now() + Duration::from_secs(5)));
        }
        if let Some((reason, end)) = stopping
            && Instant::now() >= end
        {
            // Dropping the worker kills it, waits and removes its private scratch folder.
            return Err(format!("{reason}; the worker was terminated without a finished report"));
        }
        match worker.receive(Duration::from_millis(40)) {
            Ok(Response::Progress { step }) => progress.event(step),
            Ok(Response::Report { report }) => {
                worker.stop(Duration::from_millis(100));
                return Ok(*report);
            }
            Ok(Response::Error { message, .. }) => return Err(message),
            Ok(Response::Bytes { .. }) => return Err("unexpected evidence response during analysis".into()),
            Err(WorkerError::Timeout) => {}
            Err(error) => return Err(error.to_string()),
        }
    }
}
