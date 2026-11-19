//! The messages between the app and a worker process. Each is one line of JSON.

use std::path::PathBuf;

use aa_core::Report;
use aa_engine::{Event, Limits};
use serde::{Deserialize, Serialize};

/// Most bytes one `read_bytes` request returns; a larger `length` is cut to this.
pub const MAX_CHUNK: u64 = 1024 * 1024;

/// What the app asks of the worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
pub enum Request {
    /// Analyze the file or folder at `path`. One analysis per worker.
    Analyze {
        path: PathBuf,
        /// Folder for what is unpacked along the way. The app made it and will remove it.
        scratch: PathBuf,
        /// Limits that differ from the defaults.
        #[serde(default)]
        limits: LimitOverrides,
    },
    /// Stop the analysis that is running. What was finished is still reported.
    Cancel,
    /// Read bytes of an artifact of the finished analysis. `id` comes back with the answer.
    ReadBytes { id: u64, path: String, offset: u64, length: u64 },
    /// End the worker.
    Close,
}

/// The limits of [`aa_engine::Limits`] that a request sets; the rest keep their defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LimitOverrides {
    pub max_files: Option<u64>,
    pub max_depth: Option<u32>,
    pub max_unpacked_bytes: Option<u64>,
    pub max_entry_bytes: Option<u64>,
    pub analyzer_seconds: Option<u64>,
    pub unpack_seconds: Option<u64>,
}

impl LimitOverrides {
    pub fn apply(&self) -> Limits {
        let defaults = Limits::default();
        Limits {
            max_files: self.max_files.unwrap_or(defaults.max_files),
            max_depth: self.max_depth.unwrap_or(defaults.max_depth),
            max_unpacked_bytes: self.max_unpacked_bytes.unwrap_or(defaults.max_unpacked_bytes),
            max_entry_bytes: self.max_entry_bytes.unwrap_or(defaults.max_entry_bytes),
            analyzer_seconds: self.analyzer_seconds.unwrap_or(defaults.analyzer_seconds),
            unpack_seconds: self.unpack_seconds.unwrap_or(defaults.unpack_seconds),
            ..defaults
        }
    }
}

/// What the worker tells the app.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "response", rename_all = "snake_case")]
pub enum Response {
    /// A step of the running analysis.
    Progress { step: Event },
    /// The analysis is done. Its artifacts stay readable until the worker ends.
    Report { report: Box<Report> },
    /// The answer to `read_bytes`: the bytes as hexadecimal, and the artifact's full size.
    /// Fewer bytes than asked for means the artifact ends there.
    Bytes { id: u64, hex: String, size: u64 },
    /// A request could not be carried out. `id` is set when it answers a `read_bytes`.
    Error { id: Option<u64>, message: String },
}
