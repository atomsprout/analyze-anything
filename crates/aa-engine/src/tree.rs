//! Builds the artifact tree: lists the input, measures every file, and opens containers.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use aa_core::plugin::{Bytes, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Coverage, InputKind, Limitation};

use crate::store::Store;
use crate::{Event, Options, ProgressSink, scan, walk};

/// Children up to this size stay in memory, while the memory budget lasts.
const KEEP_IN_MEMORY_BELOW: usize = 256 * 1024;
/// Total size of children kept in memory before everything spills to disk.
const MEMORY_BUDGET: u64 = 512 * 1024 * 1024;

pub struct BuiltTree {
    pub artifacts: Vec<Artifact>,
    /// Facts about the input as a whole, filled in as analyzers run.
    pub summary: BTreeMap<String, serde_json::Value>,
    stores: BTreeMap<String, Store>,
    /// Holds spilled children; removed from disk when the tree is dropped.
    _temp: Option<tempfile::TempDir>,
}

impl Tree for BuiltTree {
    fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    fn summary(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.summary
    }

    fn read(&self, path: &str) -> std::io::Result<Bytes> {
        match self.stores.get(path) {
            Some(store) => store.read(),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("no artifact at {path}"))),
        }
    }
}

pub struct Built {
    pub tree: BuiltTree,
    pub limitations: Vec<Limitation>,
    pub coverage: Coverage,
}

struct Builder<'a> {
    options: &'a Options,
    unpackers: &'a [Box<dyn Unpacker>],
    sink: &'a mut dyn ProgressSink,
    artifacts: Vec<Artifact>,
    stores: BTreeMap<String, Store>,
    taken: BTreeSet<String>,
    limitations: Vec<Limitation>,
    coverage: Coverage,
    temp: Option<tempfile::TempDir>,
    spilled: u64,
    in_memory: u64,
    unpacked_bytes: u64,
    /// Limit codes already recorded, so each is reported once.
    reported: BTreeSet<&'static str>,
}

/// A child waiting to be measured and, perhaps, unpacked in turn.
struct Child {
    path: String,
    store: Store,
}

/// The top-level files of a run and where their bytes are.
pub enum Roots<'a> {
    /// A file or folder on disk.
    Disk { input: &'a Path, kind: InputKind, name: &'a str },
    /// A single file held in memory.
    Memory { name: &'a str, bytes: Arc<Vec<u8>> },
}

pub fn build(roots: Roots<'_>, options: &Options, unpackers: &[Box<dyn Unpacker>], sink: &mut dyn ProgressSink) -> Built {
    let mut builder = Builder {
        options,
        unpackers,
        sink,
        artifacts: Vec::new(),
        stores: BTreeMap::new(),
        taken: BTreeSet::new(),
        limitations: Vec::new(),
        coverage: Coverage::default(),
        temp: None,
        spilled: 0,
        in_memory: 0,
        unpacked_bytes: 0,
        reported: BTreeSet::new(),
    };
    let files: Vec<(String, Store)> = match roots {
        Roots::Memory { name, bytes } => vec![(name.to_string(), Store::Memory(bytes))],
        Roots::Disk { input, kind: InputKind::File, name } => vec![(name.to_string(), Store::Disk(input.to_path_buf()))],
        Roots::Disk { input, kind: InputKind::Directory, .. } => {
            let listing = walk::list(input, builder.options.limits.max_files);
            for limitation in &listing.limitations {
                builder.sink.event(Event::Warning { code: limitation.code.clone(), path: limitation.artifact.clone() });
            }
            builder.limitations.extend(listing.limitations);
            builder.coverage.truncated |= listing.truncated;
            listing.entries.into_iter().map(|entry| (entry.path, Store::Disk(entry.on_disk))).collect()
        }
    };
    let total = files.len() as u64;
    builder.sink.event(Event::Listed { files: total });
    let mut disk_bytes = 0u64;
    for (position, (path, store)) in files.iter().enumerate() {
        let stop = if builder.cancelled() {
            Some("cancelled")
        } else if disk_bytes >= builder.options.limits.max_total_bytes {
            Some("limit_reached")
        } else {
            None
        };
        if let Some(code) = stop {
            let detail = format!("{} of {} files were not read", files.len() - position, files.len());
            builder.stop(code, None, Some(detail));
            break;
        }
        builder.sink.event(Event::Reading { index: position as u64 + 1, total, path: path.clone() });
        builder.taken.insert(path.clone());
        let size = builder.ingest(Child { path: path.clone(), store: store.clone() }, None, 0);
        disk_bytes += size;
    }
    builder.coverage.artifacts_total = builder.artifacts.len() as u64;
    builder.coverage.artifacts_analyzed = builder.artifacts.iter().filter(|a| a.digests.is_some()).count() as u64;
    builder.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    Built {
        tree: BuiltTree { artifacts: builder.artifacts, summary: BTreeMap::new(), stores: builder.stores, _temp: builder.temp },
        limitations: builder.limitations,
        coverage: builder.coverage,
    }
}

impl Builder<'_> {
    fn cancelled(&self) -> bool {
        self.options.cancel.as_ref().is_some_and(|flag| flag.load(Ordering::Relaxed))
    }

    /// Records that the run is incomplete. Each code is recorded once per artifact-less case.
    fn stop(&mut self, code: &'static str, artifact: Option<&str>, detail: Option<String>) {
        self.coverage.truncated = true;
        if artifact.is_none() && !self.reported.insert(code) {
            return;
        }
        self.sink.event(Event::Warning { code: code.into(), path: artifact.map(str::to_string) });
        self.limitations.push(Limitation::new(code, artifact, detail));
    }

    fn warn(&mut self, code: &str, artifact: &str, detail: Option<String>) {
        self.sink.event(Event::Warning { code: code.into(), path: Some(artifact.to_string()) });
        self.limitations.push(Limitation::new(code, Some(artifact), detail));
    }

    /// Measures one artifact, adds it to the tree, and unpacks it if it is a container.
    /// Returns the artifact's size.
    fn ingest(&mut self, child: Child, parent: Option<&str>, depth: u32) -> u64 {
        let mut artifact = Artifact {
            path: child.path.clone(),
            parent: parent.map(str::to_string),
            size: 0,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        };
        let bytes = match child.store.read() {
            Ok(bytes) => bytes,
            Err(error) => {
                if let Store::Disk(path) = &child.store {
                    artifact.size = std::fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0);
                }
                self.warn("read_failed", &child.path, Some(error.to_string()));
                self.artifacts.push(artifact);
                return 0;
            }
        };
        let scanned = scan::scan(&bytes);
        artifact.size = bytes.len() as u64;
        artifact.digests = Some(scanned.digests);
        artifact.entropy = scanned.entropy;
        artifact.detected = Some(scanned.detected);
        self.coverage.bytes_analyzed += artifact.size;

        let mut children = Vec::new();
        if !bytes.is_empty() {
            let at_depth_limit = depth >= self.options.limits.max_depth;
            let unpackers = self.unpackers;
            for unpacker in unpackers {
                let mut sink =
                    Sink { builder: self, container: &child.path, children: Vec::new(), refuse: at_depth_limit, refused: false, added: 0 };
                let outcome = unpacker.unpack(&artifact, &bytes, &mut sink);
                let (found, added) = (std::mem::take(&mut sink.children), sink.added);
                let (kind, failure) = match outcome {
                    Unpack::NotMine => continue,
                    Unpack::Done { kind } => (kind, None),
                    Unpack::Failed { kind, detail } => (kind, Some(detail)),
                };
                artifact.kind = Some(kind.to_string());
                if added > 0 || failure.is_none() && !at_depth_limit {
                    artifact.unpacked_by = Some(unpacker.id().to_string());
                    self.coverage.containers_unpacked += 1;
                    self.sink.event(Event::Unpacked { path: child.path.clone(), children: added });
                }
                if let Some(detail) = failure {
                    self.warn("unpack_failed", &child.path, Some(detail));
                }
                children = found;
                break;
            }
        }
        drop(bytes);
        let size = artifact.size;
        self.stores.insert(child.path.clone(), child.store);
        self.artifacts.push(artifact);
        for grandchild in children {
            if self.cancelled() {
                self.stop("cancelled", None, None);
                break;
            }
            self.ingest(grandchild, Some(&child.path), depth + 1);
        }
        size
    }

    /// Keeps a child's bytes: in memory while small and within budget, otherwise in a temporary file.
    fn keep(&mut self, bytes: Vec<u8>) -> std::io::Result<Store> {
        if bytes.len() <= KEEP_IN_MEMORY_BELOW && self.in_memory + bytes.len() as u64 <= MEMORY_BUDGET {
            self.in_memory += bytes.len() as u64;
            return Ok(Store::Memory(Arc::new(bytes)));
        }
        if self.temp.is_none() {
            self.temp = Some(tempfile::Builder::new().prefix("analyze-anything-").tempdir()?);
        }
        let Some(temp) = &self.temp else { unreachable!("the temporary folder was created above") };
        self.spilled += 1;
        let path = temp.path().join(format!("{:08}", self.spilled));
        std::fs::File::create(&path)?.write_all(&bytes)?;
        Ok(Store::Disk(path))
    }
}

struct Sink<'a, 'b> {
    builder: &'a mut Builder<'b>,
    container: &'a str,
    children: Vec<Child>,
    /// At the depth limit nothing is unpacked; the first entry records why.
    refuse: bool,
    refused: bool,
    added: u64,
}

impl UnpackSink for Sink<'_, '_> {
    fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
        if self.refuse {
            if !self.refused {
                self.refused = true;
                self.builder.warn("depth_limit", self.container, None);
                self.builder.coverage.truncated = true;
            }
            return Err(SinkError::LimitReached);
        }
        let limits = &self.builder.options.limits;
        if self.builder.cancelled() {
            self.builder.stop("cancelled", None, None);
            return Err(SinkError::LimitReached);
        }
        if (self.builder.taken.len() as u64) >= limits.max_files {
            let detail = format!("only the first {} files were kept", limits.max_files);
            self.builder.stop("limit_reached", None, Some(detail));
            return Err(SinkError::LimitReached);
        }
        let Some(relative) = normalise(path) else {
            self.builder.warn("unsafe_path", self.container, Some(printable(path)));
            return Ok(());
        };
        // Read one byte past the smaller limit, so "exactly at the limit" and "over it" differ.
        let budget = limits.max_unpacked_bytes.saturating_sub(self.builder.unpacked_bytes);
        let allowed = budget.min(limits.max_entry_bytes);
        let mut bytes = Vec::new();
        if let Err(error) = data.take(allowed.saturating_add(1)).read_to_end(&mut bytes) {
            let full = format!("{}/{relative}", self.container);
            self.builder.warn("entry_unreadable", &full, Some(error.to_string()));
            return Err(SinkError::Read(error.to_string()));
        }
        if bytes.len() as u64 > allowed {
            let full = format!("{}/{relative}", self.container);
            if allowed == budget {
                let detail = format!("more than {} bytes would be unpacked in total", limits.max_unpacked_bytes);
                self.builder.stop("limit_reached", None, Some(detail));
                return Err(SinkError::LimitReached);
            }
            let detail = format!("the entry is larger than {} bytes", limits.max_entry_bytes);
            self.builder.stop("limit_reached", Some(&full), Some(detail));
            return Ok(());
        }
        let mut full = format!("{}/{relative}", self.container);
        let mut copy = 2;
        while !self.builder.taken.insert(full.clone()) {
            full = format!("{}/{relative} ({copy})", self.container);
            copy += 1;
        }
        self.builder.unpacked_bytes += bytes.len() as u64;
        match self.builder.keep(bytes) {
            Ok(store) => {
                self.children.push(Child { path: full, store });
                self.added += 1;
                Ok(())
            }
            Err(error) => {
                self.builder.warn("entry_unreadable", &full, Some(error.to_string()));
                Err(SinkError::Read(error.to_string()))
            }
        }
    }

    fn limitation(&mut self, code: &str, detail: Option<String>) {
        self.builder.warn(code, self.container, detail);
    }
}

/// An entry name as a safe relative path, or `None` when it points outside the container.
///
/// Both `/` and `\` separate components, since archives written on Windows use either.
fn normalise(path: &str) -> Option<String> {
    let mut parts = Vec::new();
    for part in path.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => return None,
            part => parts.push(printable(part)),
        }
    }
    if parts.is_empty() { None } else { Some(parts.join("/")) }
}

/// Replaces control characters, which would corrupt tables and terminals.
fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { '\u{fffd}' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_are_made_safe() {
        assert_eq!(normalise("a/b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(normalise("/abs//x/./y").as_deref(), Some("abs/x/y"));
        assert_eq!(normalise("C:\\dir\\file").as_deref(), Some("C:/dir/file"));
        assert_eq!(normalise("../../etc/passwd"), None);
        assert_eq!(normalise("a/../../b"), None);
        assert_eq!(normalise("a\\..\\b"), None);
        assert_eq!(normalise(""), None);
        assert_eq!(normalise("dir/"), Some("dir".to_string()));
        assert_eq!(normalise("a\nb").as_deref(), Some("a\u{fffd}b"));
    }
}
