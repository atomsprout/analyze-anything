//! Extension points: how a format is taught to the engine.
//!
//! An [`Unpacker`] opens a container (an archive, a disk image, an installer) into child
//! artifacts. An [`Analyzer`] reads artifacts and reports [`Finding`]s, facts and limitations.
//! Neither may execute anything from the input, write outside what the engine hands it, or
//! print; whatever cannot be established is reported as a [`Limitation`].

use std::collections::BTreeMap;
use std::io::Read;
use std::ops::Deref;
use std::sync::Arc;

use serde_json::Value;

use crate::{Artifact, Finding, Limitation};

/// The bytes of one artifact. Cheap to clone.
#[derive(Clone)]
pub struct Bytes(Arc<dyn AsRef<[u8]> + Send + Sync>);

impl Bytes {
    pub fn new(inner: Arc<dyn AsRef<[u8]> + Send + Sync>) -> Self {
        Bytes(inner)
    }

    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Bytes(Arc::new(bytes))
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        (*self.0).as_ref()
    }
}

/// Read access to the artifact tree.
pub trait Tree: Sync {
    /// Every artifact, sorted by path.
    fn artifacts(&self) -> &[Artifact];

    /// The bytes of the artifact at `path`.
    fn read(&self, path: &str) -> std::io::Result<Bytes>;

    /// Facts about the input as a whole that analyzers have attached so far, by key.
    /// A tree that keeps none (a test double, say) reports an empty map.
    fn summary(&self) -> &BTreeMap<String, Value> {
        static NONE: BTreeMap<String, Value> = BTreeMap::new();
        &NONE
    }

    /// The name of the file or folder being analyzed, as it was given. Empty when the tree does
    /// not know (a test double, say).
    fn input_name(&self) -> &str {
        ""
    }

    /// The artifact at exactly `path`.
    fn get(&self, path: &str) -> Option<&Artifact> {
        let artifacts = self.artifacts();
        artifacts.binary_search_by(|a| a.path.as_str().cmp(path)).ok().map(|i| &artifacts[i])
    }

    /// Every artifact below the folder or container `dir`, at any depth. `""` is the whole tree.
    fn under(&self, dir: &str) -> Vec<&Artifact> {
        if dir.is_empty() {
            return self.artifacts().iter().collect();
        }
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        self.artifacts().iter().filter(|a| a.path.starts_with(&prefix)).collect()
    }
}

/// The words for one rule or limitation code. See [`crate::RuleText`].
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    /// The rule id used in [`Finding::rule`], or the code used in [`Limitation::code`].
    pub id: &'static str,
    pub title_zh: &'static str,
    pub title_en: &'static str,
    /// May refer to a finding's params as `{name}`.
    pub text_zh: &'static str,
    pub text_en: &'static str,
}

/// A fact to attach to an artifact, or to the report as a whole.
#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    /// Artifact path; `None` attaches the fact to the report's summary.
    pub artifact: Option<String>,
    /// `<analyzer>.<name>`.
    pub key: String,
    pub value: Value,
}

/// What an analyzer found.
#[derive(Debug, Default)]
pub struct Output {
    /// Sealed findings.
    pub findings: Vec<Finding>,
    pub facts: Vec<Fact>,
    /// `(artifact path, kind)`: sets [`Artifact::kind`].
    pub kinds: Vec<(String, String)>,
    pub limitations: Vec<Limitation>,
}

impl Output {
    /// Adds a finding, sealing it.
    pub fn finding(&mut self, finding: Finding) {
        self.findings.push(finding.seal());
    }

    /// Attaches a fact to `artifact`.
    pub fn fact(&mut self, artifact: &Artifact, key: &str, value: impl Into<Value>) {
        self.facts.push(Fact { artifact: Some(artifact.path.clone()), key: key.to_string(), value: value.into() });
    }

    /// Attaches a fact to the report as a whole.
    pub fn summary(&mut self, key: &str, value: impl Into<Value>) {
        self.facts.push(Fact { artifact: None, key: key.to_string(), value: value.into() });
    }

    /// Says what `artifact` is.
    pub fn kind(&mut self, artifact: &Artifact, kind: &str) {
        self.kinds.push((artifact.path.clone(), kind.to_string()));
    }

    /// Records something that could not be established about `artifact`.
    pub fn limitation(&mut self, code: &str, artifact: Option<&Artifact>, detail: Option<String>) {
        self.limitations.push(Limitation::new(code, artifact.map(|a| a.path.as_str()), detail));
    }
}

/// Reads artifacts and reports what they are and contain.
///
/// The engine first calls [`Analyzer::analyze_file`] for every artifact, possibly from several
/// threads, then merges all facts and kinds into the tree, then calls [`Analyzer::analyze_tree`]
/// once per analyzer in registration order. Tree analysis therefore sees the facts every
/// analyzer attached in the file pass.
///
/// A panic inside an analyzer is caught and reported as a limitation; it does not stop the run.
pub trait Analyzer: Send + Sync {
    /// Short stable name, e.g. `apple`. Prefix of the analyzer's rule ids and fact keys.
    fn id(&self) -> &'static str;

    /// Text for every rule id and limitation code this analyzer can emit.
    fn rules(&self) -> &'static [Rule];

    /// Looks at one artifact on its own.
    fn analyze_file(&self, _tree: &dyn Tree, _file: &Artifact, _out: &mut Output) {}

    /// Looks at the tree as a whole: bundles, relations between files.
    fn analyze_tree(&self, _tree: &dyn Tree, _out: &mut Output) {}
}

/// Why an unpacker stopped adding children.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SinkError {
    /// A size, count or depth limit was reached. Stop unpacking; the engine has recorded it.
    LimitReached,
    /// Reading the entry's data failed; the text says how. The unpacker may go on to the next entry.
    Read(String),
}

/// Receives the children an unpacker extracts. The engine enforces every limit here, so a
/// hostile archive cannot fill the disk or memory however the unpacker is written.
pub trait UnpackSink {
    /// Adds a child from `data`. `path` is the entry's name as the container records it; the
    /// engine normalises it and refuses names that would escape the container.
    fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError>;

    /// Records something about the container that could not be unpacked.
    fn limitation(&mut self, code: &str, detail: Option<String>);
}

/// The outcome of offering an artifact to an unpacker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unpack {
    /// The artifact is not a format this unpacker handles. Nothing was added.
    NotMine,
    /// The artifact was opened. `kind` says what it is, e.g. `zip`.
    Done { kind: &'static str },
    /// The artifact is this unpacker's format but could not be opened; the text says why.
    /// Children added before the failure are kept.
    Failed { kind: &'static str, detail: String },
}

/// Opens one container format into child artifacts.
pub trait Unpacker: Send + Sync {
    /// Short stable name, e.g. `zip`.
    fn id(&self) -> &'static str;

    /// Text for every limitation code this unpacker can emit through the sink.
    fn rules(&self) -> &'static [Rule] {
        &[]
    }

    /// Unpacks `bytes`, the content of `file`, if it is this unpacker's format.
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack;
}
