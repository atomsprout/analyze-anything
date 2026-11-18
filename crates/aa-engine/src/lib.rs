//! The analysis engine: the one entry point the command line and the desktop app both call.
//!
//! [`analyze`] walks the input, reads every file once, and returns a [`Report`]. It never prints,
//! never exits the process and never executes anything from the input. Progress is reported as
//! [`Event`]s through a [`ProgressSink`]; a run is stopped by setting [`Options::cancel`].

mod rules;
mod scan;
mod walk;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use aa_core::{Coverage, Input, InputKind, Limitation, Report, SCHEMA_VERSION, Tool};

/// Bounds that keep a hostile or huge input from exhausting the machine.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Most files read from a folder.
    pub max_files: u64,
    /// Most bytes read in total.
    pub max_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_files: 100_000, max_total_bytes: 8 * 1024 * 1024 * 1024 }
    }
}

/// Settings for one run. Everything that changes the result is here, not in the environment.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub limits: Limits,
    /// Set to `true` from another thread to stop the run. What was finished is still returned.
    pub cancel: Option<Arc<AtomicBool>>,
}

/// A step of the run, for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The files of the input have been listed.
    Listed {
        files: u64,
    },
    /// A file is about to be read. `index` starts at 1.
    Reading {
        index: u64,
        total: u64,
        path: String,
    },
    /// Something was skipped or failed; the report records it as a limitation.
    Warning {
        code: String,
        path: Option<String>,
    },
    Finished,
}

/// Receives progress events. Implement it to draw a progress bar or update a window.
pub trait ProgressSink {
    fn event(&mut self, event: Event);
}

/// A sink that ignores every event.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn event(&mut self, _event: Event) {}
}

/// Why a run could not start at all.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("cannot read {path}: {source}")]
    InputUnreadable { path: PathBuf, source: std::io::Error },
    #[error("{path} is neither a file nor a folder")]
    UnsupportedInput { path: PathBuf },
}

/// Analyzes the file or folder at `input`.
///
/// Problems with individual files do not fail the run: each becomes a limitation in the report.
pub fn analyze(input: &Path, options: &Options, sink: &mut dyn ProgressSink) -> Result<Report, EngineError> {
    let unreadable = |source| EngineError::InputUnreadable { path: input.to_path_buf(), source };
    let metadata = std::fs::metadata(input).map_err(unreadable)?;
    let kind = if metadata.is_dir() {
        InputKind::Directory
    } else if metadata.is_file() {
        InputKind::File
    } else {
        return Err(EngineError::UnsupportedInput { path: input.to_path_buf() });
    };
    // The name of the input as given; a path such as `.` has none, so resolve it first.
    let name = match input.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => {
            let resolved = std::fs::canonicalize(input).map_err(unreadable)?;
            resolved.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into())
        }
    };

    let mut limitations: Vec<Limitation> = Vec::new();
    let mut coverage = Coverage::default();
    let files = match kind {
        InputKind::File => vec![walk::Entry { path: name.clone(), on_disk: input.to_path_buf() }],
        InputKind::Directory => {
            let listing = walk::list(input, options.limits.max_files);
            for limitation in &listing.limitations {
                sink.event(Event::Warning { code: limitation.code.clone(), path: limitation.artifact.clone() });
            }
            limitations.extend(listing.limitations);
            coverage.truncated |= listing.truncated;
            listing.entries
        }
    };
    coverage.artifacts_total = files.len() as u64;
    sink.event(Event::Listed { files: coverage.artifacts_total });

    let mut artifacts = Vec::with_capacity(files.len());
    let mut findings = Vec::new();
    for (position, file) in files.iter().enumerate() {
        let stop = if options.cancel.as_ref().is_some_and(|flag| flag.load(Ordering::Relaxed)) {
            Some("cancelled")
        } else if coverage.bytes_analyzed >= options.limits.max_total_bytes {
            Some("limit_reached")
        } else {
            None
        };
        if let Some(code) = stop {
            let detail = format!("{} of {} files were not read", files.len() - position, files.len());
            sink.event(Event::Warning { code: code.into(), path: None });
            limitations.push(Limitation { code: code.into(), artifact: None, detail: Some(detail) });
            coverage.truncated = true;
            break;
        }
        sink.event(Event::Reading { index: position as u64 + 1, total: coverage.artifacts_total, path: file.path.clone() });
        let scanned = scan::scan(&file.path, &file.on_disk);
        match scanned.failure {
            None => {
                coverage.artifacts_analyzed += 1;
                coverage.bytes_analyzed += scanned.artifact.size;
                findings.extend(rules::findings(&scanned.artifact, &scanned.head));
            }
            Some(detail) => {
                sink.event(Event::Warning { code: "read_failed".into(), path: Some(file.path.clone()) });
                limitations.push(Limitation { code: "read_failed".into(), artifact: Some(file.path.clone()), detail: Some(detail) });
            }
        }
        artifacts.push(scanned.artifact);
    }

    findings.sort_by(|a, b| (a.section, &a.rule, &a.id).cmp(&(b.section, &b.rule, &b.id)));
    limitations.sort();
    let sha256 = match kind {
        InputKind::File => artifacts.first().and_then(|a| a.digests.as_ref()).map(|d| d.sha256.clone()),
        InputKind::Directory => None,
    };
    sink.event(Event::Finished);
    Ok(Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool { name: "analyze-anything".into(), version: env!("CARGO_PKG_VERSION").into() },
        input: Input { name, kind, sha256 },
        artifacts,
        findings,
        limitations,
        coverage,
    })
}
