//! Data model shared by every part of Analyze Anything.
//!
//! A [`Report`] is the single source of truth: every human-readable output (Markdown, text, HTML,
//! PDF) is rendered from it and from nothing else. A report holds the artifact tree, the findings
//! drawn from it, and the limitations of the analysis. Each [`Finding`] carries the evidence it
//! rests on and a [`Confidence`] level, and its id is the SHA-256 of its canonical JSON, so the
//! same observation always gets the same id.
//!
//! Rules that keep reports reproducible: no timestamps, no absolute paths, stable ordering, and a
//! value that could not be established is `None`, never zero or an empty string.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Version of the report layout. Bump on any breaking change to the JSON shape.
pub const SCHEMA_VERSION: u32 = 1;

/// How sure a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Read directly from a structure the format defines, or checked cryptographically.
    Verified,
    /// Computed from verified facts by a deterministic rule.
    Derived,
    /// A pattern match or rule hit; may be a false positive.
    Heuristic,
}

/// How much a finding matters to the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// The report chapter a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Identity,
    Provenance,
    Structure,
    Composition,
    Capabilities,
    Hardening,
    Network,
    Secrets,
    Privacy,
    Code,
    Anomalies,
}

/// Where in an artifact a piece of evidence was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// A byte range in the artifact.
    Bytes { offset: u64, length: u64 },
    /// A named field of a parsed structure, e.g. `Info.plist:CFBundleIdentifier`.
    Field(String),
    /// The artifact as a whole (its name, size or digest).
    Whole,
}

/// One observation a finding rests on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Path of the artifact inside the artifact tree.
    pub artifact: String,
    /// SHA-256 of that artifact's bytes.
    pub sha256: Option<String>,
    pub location: Location,
    /// The raw value observed there.
    pub value: Value,
}

/// A conclusion about the input, with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// SHA-256 of the finding's canonical JSON without this field. Set by [`Finding::seal`].
    pub id: String,
    pub section: Section,
    /// Analyzer that produced the finding, e.g. `content`.
    pub analyzer: String,
    /// Stable rule id, e.g. `content.high-entropy`. Also the key of the message text.
    pub rule: String,
    /// Values the message text refers to.
    pub params: BTreeMap<String, Value>,
    pub confidence: Confidence,
    pub severity: Severity,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    /// Computes and stores the id. Call once, after every other field is final.
    pub fn seal(mut self) -> Self {
        self.id = String::new();
        self.id = sha256_hex(canonical_json(&self).as_bytes());
        self
    }
}

/// Something the analysis could not establish or deliberately left out.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Limitation {
    /// Stable machine code, e.g. `read_failed`, `symlink_skipped`, `limit_reached`.
    pub code: String,
    /// Artifact path it applies to; `None` when it applies to the whole run.
    pub artifact: Option<String>,
    /// Technical detail, such as the operating system's error text.
    pub detail: Option<String>,
}

/// Digests of an artifact's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Digests {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// What an artifact's content was recognised as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// MIME type, e.g. `application/zip`.
    pub mime: String,
    /// The extension files of this type usually carry, when one is known.
    pub usual_extension: Option<String>,
}

/// One node of the artifact tree: a file of the input, or something unpacked from one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    /// Path inside the tree, with `/` separators, relative to the input.
    pub path: String,
    /// Path of the artifact this one was unpacked from; `None` for files of the input itself.
    pub parent: Option<String>,
    pub size: u64,
    /// `None` when the bytes could not be read; a limitation says why.
    pub digests: Option<Digests>,
    pub detected: Option<Detected>,
    /// Shannon entropy of the bytes, 0.0 to 8.0. `None` for empty or unreadable artifacts.
    pub entropy: Option<f64>,
}

/// Whether the input was a single file or a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    File,
    Directory,
}

/// The thing that was analyzed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    /// File or folder name, without its location on disk.
    pub name: String,
    pub kind: InputKind,
    /// SHA-256 of the input when it is a single file.
    pub sha256: Option<String>,
}

/// The program that produced a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub version: String,
}

/// How much of the input was examined.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Artifacts found in the tree.
    pub artifacts_total: u64,
    /// Artifacts whose bytes were read in full.
    pub artifacts_analyzed: u64,
    /// Bytes read.
    pub bytes_analyzed: u64,
    /// True when the run stopped early (a limit was hit or it was cancelled).
    pub truncated: bool,
}

/// The complete result of one analysis run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub input: Input,
    pub artifacts: Vec<Artifact>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<Limitation>,
    pub coverage: Coverage,
}

/// JSON with object keys in sorted order and no insignificant whitespace.
pub fn canonical_json<T: Serialize>(value: &T) -> String {
    // serde_json's default map is ordered by key, so going through `Value` sorts every object.
    serde_json::to_value(value).map(|v| v.to_string()).unwrap_or_default()
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Finding {
        Finding {
            id: String::new(),
            section: Section::Anomalies,
            analyzer: "content".into(),
            rule: "content.high-entropy".into(),
            params: BTreeMap::from([("entropy".to_string(), Value::from(7.9))]),
            confidence: Confidence::Heuristic,
            severity: Severity::Info,
            evidence: vec![Evidence {
                artifact: "a.bin".into(),
                sha256: Some("00".into()),
                location: Location::Whole,
                value: Value::from(7.9),
            }],
        }
    }

    #[test]
    fn same_finding_gets_same_id() {
        assert_eq!(sample().seal().id, sample().seal().id);
        assert_eq!(sample().seal().id.len(), 64);
    }

    #[test]
    fn sealing_twice_keeps_the_id() {
        let once = sample().seal();
        assert_eq!(once.clone().seal().id, once.id);
    }

    #[test]
    fn different_evidence_gets_different_id() {
        let mut other = sample();
        other.evidence[0].artifact = "b.bin".into();
        assert_ne!(sample().seal().id, other.seal().id);
    }
}
