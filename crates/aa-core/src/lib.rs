//! Data model and extension points shared by every part of Analyze Anything.
//!
//! A [`Report`] is the single source of truth: every human-readable output (Markdown, text, HTML,
//! PDF) is rendered from it and from nothing else. A report holds the artifact tree, the findings
//! drawn from it, the limitations of the analysis, and the text of every rule it mentions, so a
//! report can be rendered again later without the program version that wrote it.
//!
//! Each [`Finding`] carries the evidence it rests on and a [`Confidence`] level, and its id is the
//! SHA-256 of its canonical JSON, so the same observation always gets the same id.
//!
//! Rules that keep reports reproducible: no timestamps, no absolute paths, stable ordering, and a
//! value that could not be established is `None`, never zero or an empty string.
//!
//! Formats are added through [`plugin`]: an [`plugin::Unpacker`] opens a container into child
//! artifacts, an [`plugin::Analyzer`] turns artifacts into findings and facts.

pub mod plugin;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Version of the report layout. Bump on any breaking change to the JSON shape.
pub const SCHEMA_VERSION: u32 = 2;

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

/// How much a finding matters to the reader. `Info` is a neutral fact, not a problem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

/// The report chapter a finding belongs to, in the order chapters appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// What the input is, in a few lines.
    Overview,
    /// Name, identifiers, version, platform.
    Identity,
    /// Who signed it, and whether the signature holds.
    Provenance,
    /// What it is made of on disk: layout, sizes, nesting.
    Structure,
    /// Languages, frameworks, libraries, SDKs.
    Composition,
    /// Permissions, entitlements, declared capabilities, installer actions.
    Capabilities,
    /// Compiler and platform protections.
    Hardening,
    /// URLs, hosts, addresses.
    Network,
    /// Embedded keys, tokens, credentials.
    Secrets,
    /// Trackers and data collection.
    Privacy,
    /// Symbols, classes, notable strings.
    Code,
    /// Things that look wrong or unusual.
    Anomalies,
}

impl Section {
    /// Every section, in report order.
    pub const ALL: [Section; 12] = [
        Section::Overview,
        Section::Identity,
        Section::Provenance,
        Section::Structure,
        Section::Composition,
        Section::Capabilities,
        Section::Hardening,
        Section::Network,
        Section::Secrets,
        Section::Privacy,
        Section::Code,
        Section::Anomalies,
    ];
}

/// Where in an artifact a piece of evidence was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// A byte range in the artifact.
    Bytes { offset: u64, length: u64 },
    /// A named field of a parsed structure, e.g. `CFBundleIdentifier`.
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

impl Evidence {
    fn of(artifact: &Artifact, location: Location, value: impl Into<Value>) -> Self {
        Evidence {
            artifact: artifact.path.clone(),
            sha256: artifact.digests.as_ref().map(|d| d.sha256.clone()),
            location,
            value: value.into(),
        }
    }

    /// Evidence read from a byte range of `artifact`.
    pub fn bytes(artifact: &Artifact, offset: u64, length: u64, value: impl Into<Value>) -> Self {
        Self::of(artifact, Location::Bytes { offset, length }, value)
    }

    /// Evidence read from a named field of a structure parsed out of `artifact`.
    pub fn field(artifact: &Artifact, field: impl Into<String>, value: impl Into<Value>) -> Self {
        Self::of(artifact, Location::Field(field.into()), value)
    }

    /// Evidence about `artifact` as a whole.
    pub fn whole(artifact: &Artifact, value: impl Into<Value>) -> Self {
        Self::of(artifact, Location::Whole, value)
    }
}

/// A conclusion about the input, with the evidence behind it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// SHA-256 of the finding's canonical JSON without this field. Set by [`Finding::seal`].
    pub id: String,
    pub section: Section,
    /// Analyzer that produced the finding, e.g. `content`.
    pub analyzer: String,
    /// Stable rule id, e.g. `content.high-entropy`. The key of the rule's text in [`Report::rules`].
    pub rule: String,
    /// Values the rule's text refers to as `{name}`.
    pub params: BTreeMap<String, Value>,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Identifiers in outside catalogues, e.g. `CWE-798`, `MASVS-STORAGE-2`.
    pub references: Vec<String>,
    pub evidence: Vec<Evidence>,
}

impl Finding {
    /// Starts a finding. Add params and evidence, then call [`Finding::seal`].
    pub fn new(section: Section, analyzer: &str, rule: &str, confidence: Confidence, severity: Severity) -> Self {
        Finding {
            id: String::new(),
            section,
            analyzer: analyzer.to_string(),
            rule: rule.to_string(),
            params: BTreeMap::new(),
            confidence,
            severity,
            references: Vec::new(),
            evidence: Vec::new(),
        }
    }

    pub fn param(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.params.insert(name.to_string(), value.into());
        self
    }

    pub fn reference(mut self, reference: &str) -> Self {
        self.references.push(reference.to_string());
        self
    }

    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

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
    /// Stable machine code, e.g. `read_failed`. The key of its text in [`Report::rules`].
    pub code: String,
    /// Artifact path it applies to; `None` when it applies to the whole run.
    pub artifact: Option<String>,
    /// Technical detail, such as the operating system's error text.
    pub detail: Option<String>,
}

impl Limitation {
    pub fn new(code: &str, artifact: Option<&str>, detail: Option<String>) -> Self {
        Limitation { code: code.to_string(), artifact: artifact.map(str::to_string), detail }
    }
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

/// One node of the artifact tree: a file of the input, or a file unpacked from one.
///
/// A container's children live under its path: the files of `app.ipa` are `app.ipa/Payload/…`.
/// Folders are not artifacts; they exist only as path prefixes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    /// Path inside the tree, with `/` separators, relative to the input.
    pub path: String,
    /// Path of the container this was unpacked from; `None` for files of the input itself.
    pub parent: Option<String>,
    pub size: u64,
    /// `None` when the bytes could not be read; a limitation says why.
    pub digests: Option<Digests>,
    pub detected: Option<Detected>,
    /// What the artifact is, once something recognised it: `zip`, `apk`, `macho`, `nsis`, …
    pub kind: Option<String>,
    /// Shannon entropy of the bytes, 0.0 to 8.0. `None` for empty or unreadable artifacts.
    pub entropy: Option<f64>,
    /// Id of the unpacker that opened this artifact into children, if one did.
    pub unpacked_by: Option<String>,
    /// Structured data analyzers read from the artifact, keyed `<analyzer>.<name>`.
    pub facts: BTreeMap<String, Value>,
}

impl Artifact {
    /// The file name: the part of the path after the last `/`.
    pub fn name(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// The lowercase extension of the file name, without the dot.
    pub fn extension(&self) -> Option<String> {
        self.name().rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
    }

    /// The detected MIME type, or an empty string when the bytes were not read.
    pub fn mime(&self) -> &str {
        self.detected.as_ref().map(|d| d.mime.as_str()).unwrap_or("")
    }

    /// True when `kind` is set to `kind`.
    pub fn is(&self, kind: &str) -> bool {
        self.kind.as_deref() == Some(kind)
    }
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
    /// Artifacts in the tree, unpacked ones included.
    pub artifacts_total: u64,
    /// Artifacts whose bytes were read in full.
    pub artifacts_analyzed: u64,
    /// Bytes read, unpacked data included.
    pub bytes_analyzed: u64,
    /// Containers that were opened into child artifacts.
    pub containers_unpacked: u64,
    /// True when the run stopped early (a limit was hit or it was cancelled).
    pub truncated: bool,
}

/// The words for one rule or limitation code, in each language.
///
/// `text` may refer to a finding's params as `{name}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleText {
    pub title_zh: String,
    pub title_en: String,
    pub text_zh: String,
    pub text_en: String,
}

/// The complete result of one analysis run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub tool: Tool,
    pub input: Input,
    /// Facts about the input as a whole, keyed `<analyzer>.<name>`.
    pub summary: BTreeMap<String, Value>,
    pub artifacts: Vec<Artifact>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<Limitation>,
    pub coverage: Coverage,
    /// Text of every rule and limitation code this report mentions.
    pub rules: BTreeMap<String, RuleText>,
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

/// Fills the `{name}` placeholders of a rule's text from a finding's params.
///
/// Strings are inserted as they are, other values as JSON. A placeholder without a param is left
/// in place, so a mistake in a rule shows up in the report instead of vanishing.
pub fn fill(template: &str, params: &BTreeMap<String, Value>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        match after.find('}').map(|close| (&after[..close], &after[close + 1..])) {
            Some((name, tail)) if params.contains_key(name) => {
                match &params[name] {
                    Value::String(text) => out.push_str(text),
                    other => out.push_str(&other.to_string()),
                }
                rest = tail;
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> Artifact {
        Artifact {
            path: "a.bin".into(),
            parent: None,
            size: 1,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn sample() -> Finding {
        Finding::new(Section::Anomalies, "content", "content.high-entropy", Confidence::Heuristic, Severity::Info)
            .param("entropy", 7.9)
            .evidence(Evidence::whole(&artifact(), 7.9))
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

    #[test]
    fn fill_replaces_known_placeholders_only() {
        let params = BTreeMap::from([("name".to_string(), Value::from("x")), ("n".to_string(), Value::from(3))]);
        assert_eq!(fill("{name} has {n} of {missing} {", &params), "x has 3 of {missing} {");
        assert_eq!(fill("no placeholders", &params), "no placeholders");
    }

    #[test]
    fn artifact_name_and_extension() {
        let mut a = artifact();
        a.path = "x.ipa/Payload/App.app/Info.PLIST".into();
        assert_eq!(a.name(), "Info.PLIST");
        assert_eq!(a.extension().as_deref(), Some("plist"));
    }
}
