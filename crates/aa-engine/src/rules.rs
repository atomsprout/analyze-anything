//! Findings that apply to any file, whatever its format.

use std::collections::BTreeMap;

use aa_core::{Artifact, Confidence, Evidence, Finding, Location, Section, Severity};
use serde_json::Value;

/// Entropy at or above this, in a file of unrecognised type, suggests packed or encrypted data.
const HIGH_ENTROPY: f64 = 7.5;
/// Small files reach high entropy by chance, so the rule ignores them.
const HIGH_ENTROPY_MIN_SIZE: u64 = 4096;

/// Types the operating system can run directly.
const EXECUTABLE_MIMES: &[&str] =
    &["application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-mach-binary"];
/// Extensions people expect to be safe to open: documents, pictures, media, text.
const HARMLESS_EXTENSIONS: &[&str] = &[
    "txt", "md", "csv", "json", "xml", "log", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "jpg", "jpeg", "png", "gif",
    "bmp", "webp", "svg", "mp3", "wav", "mp4", "mov", "avi", "mkv",
];

pub fn findings(artifact: &Artifact, head: &[u8]) -> Vec<Finding> {
    let mut found = Vec::new();
    let Some(detected) = &artifact.detected else { return found };
    let sha256 = artifact.digests.as_ref().map(|d| d.sha256.clone());

    let extension = artifact.path.rsplit('/').next().and_then(|name| name.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase());
    if let Some(extension) = extension
        && EXECUTABLE_MIMES.contains(&detected.mime.as_str())
        && HARMLESS_EXTENSIONS.contains(&extension.as_str())
    {
        let magic = &head[..head.len().min(16)];
        found.push(
            Finding {
                id: String::new(),
                section: Section::Anomalies,
                analyzer: "content".into(),
                rule: "content.executable-disguised".into(),
                params: BTreeMap::from([
                    ("path".to_string(), Value::from(artifact.path.clone())),
                    ("extension".to_string(), Value::from(extension)),
                    ("mime".to_string(), Value::from(detected.mime.clone())),
                ]),
                // The header bytes are read directly, and the rule is a fixed comparison.
                confidence: Confidence::Derived,
                severity: Severity::High,
                evidence: vec![Evidence {
                    artifact: artifact.path.clone(),
                    sha256: sha256.clone(),
                    location: Location::Bytes { offset: 0, length: magic.len() as u64 },
                    value: Value::from(hex::encode(magic)),
                }],
            }
            .seal(),
        );
    }

    if let Some(entropy) = artifact.entropy
        && entropy >= HIGH_ENTROPY
        && artifact.size >= HIGH_ENTROPY_MIN_SIZE
        && detected.mime == "application/octet-stream"
    {
        found.push(
            Finding {
                id: String::new(),
                section: Section::Anomalies,
                analyzer: "content".into(),
                rule: "content.high-entropy".into(),
                params: BTreeMap::from([
                    ("path".to_string(), Value::from(artifact.path.clone())),
                    ("entropy".to_string(), Value::from(entropy)),
                ]),
                confidence: Confidence::Heuristic,
                severity: Severity::Info,
                evidence: vec![Evidence {
                    artifact: artifact.path.clone(),
                    sha256,
                    location: Location::Whole,
                    value: Value::from(entropy),
                }],
            }
            .seal(),
        );
    }
    found
}
