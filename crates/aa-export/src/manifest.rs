//! The manifest written next to a run's output files, and the check against it.
//!
//! `manifest.json` lists every output file with its size and SHA-256. Checking a folder against
//! its manifest shows whether a report was altered, lost, or joined by files the run did not write.
//! The manifest itself is not signed: it detects accidental or careless change, and anyone who
//! keeps the manifest's own SHA-256 elsewhere can detect deliberate change too.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MANIFEST_NAME: &str = "manifest.json";
const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: u32,
    pub tool: String,
    pub tool_version: String,
    /// Name of the analyzed input, as the report records it.
    pub input: String,
    /// SHA-256 of the input when it was a single file.
    pub input_sha256: Option<String>,
    /// Output files by name.
    pub files: BTreeMap<String, Entry>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("{path} is not a manifest: {source}")]
    Parse { path: String, source: serde_json::Error },
    #[error("{path} is manifest version {found}; this program reads version {MANIFEST_VERSION}")]
    Version { path: String, found: u32 },
}

fn hash_file(path: &Path) -> std::io::Result<Entry> {
    let mut file = std::fs::File::open(path)?;
    let mut sha256 = Sha256::new();
    let mut buffer = vec![0u8; 256 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha256.update(&buffer[..count]);
        bytes += count as u64;
    }
    Ok(Entry { bytes, sha256: hex::encode(sha256.finalize()) })
}

impl Manifest {
    /// Starts a manifest for the outputs of analyzing `report`'s input.
    pub fn new(report: &aa_core::Report) -> Self {
        Manifest {
            manifest_version: MANIFEST_VERSION,
            tool: report.tool.name.clone(),
            tool_version: report.tool.version.clone(),
            input: report.input.name.clone(),
            input_sha256: report.input.sha256.clone(),
            files: BTreeMap::new(),
        }
    }

    /// Records the output file `name` in `dir`, hashing it as written on disk.
    pub fn add(&mut self, dir: &Path, name: &str) -> Result<(), ManifestError> {
        let path = dir.join(name);
        let entry = hash_file(&path).map_err(|source| ManifestError::Read { path: path.display().to_string(), source })?;
        self.files.insert(name.to_string(), entry);
        Ok(())
    }

    /// The manifest as the bytes of `manifest.json`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(self).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }

    pub fn load(dir: &Path) -> Result<Self, ManifestError> {
        let path = dir.join(MANIFEST_NAME);
        let shown = path.display().to_string();
        let bytes = std::fs::read(&path).map_err(|source| ManifestError::Read { path: shown.clone(), source })?;
        let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|source| ManifestError::Parse { path: shown.clone(), source })?;
        if manifest.manifest_version != MANIFEST_VERSION {
            return Err(ManifestError::Version { path: shown, found: manifest.manifest_version });
        }
        Ok(manifest)
    }
}

/// How one file compares with the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Unchanged,
    /// The content differs from what the manifest records.
    Changed,
    /// Listed in the manifest but not in the folder, or not readable.
    Missing,
    /// In the folder but not in the manifest.
    Unlisted,
}

/// The result of checking a folder against its manifest: every file, by name, with its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub files: BTreeMap<String, Status>,
}

impl Check {
    /// True when every listed file is present and unchanged and nothing else is in the folder.
    pub fn intact(&self) -> bool {
        self.files.values().all(|status| *status == Status::Unchanged)
    }
}

/// Compares the files in `dir` with `dir/manifest.json`.
pub fn verify(dir: &Path) -> Result<Check, ManifestError> {
    let manifest = Manifest::load(dir)?;
    let mut files = BTreeMap::new();
    for (name, expected) in &manifest.files {
        // A manifest is data from disk: a name with a path separator must not reach outside `dir`.
        let safe = !name.contains(['/', '\\']) && name != ".." && name != ".";
        let status = match safe.then(|| hash_file(&dir.join(name))) {
            Some(Ok(actual)) if actual == *expected => Status::Unchanged,
            Some(Ok(_)) => Status::Changed,
            Some(Err(_)) | None => Status::Missing,
        };
        files.insert(name.clone(), status);
    }
    let listing = std::fs::read_dir(dir).map_err(|source| ManifestError::Read { path: dir.display().to_string(), source })?;
    for entry in listing.filter_map(|entry| entry.ok()) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != MANIFEST_NAME && !files.contains_key(&name) {
            files.insert(name, Status::Unlisted);
        }
    }
    Ok(Check { files })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("report.json"), b"{}").expect("write");
        std::fs::write(dir.path().join("report.md"), b"# r").expect("write");
        let mut manifest = Manifest {
            manifest_version: MANIFEST_VERSION,
            tool: "analyze-anything".into(),
            tool_version: "0".into(),
            input: "x".into(),
            input_sha256: None,
            files: BTreeMap::new(),
        };
        manifest.add(dir.path(), "report.json").expect("add");
        manifest.add(dir.path(), "report.md").expect("add");
        std::fs::write(dir.path().join(MANIFEST_NAME), manifest.to_bytes()).expect("write");
        dir
    }

    #[test]
    fn untouched_outputs_are_intact() {
        let dir = written();
        let check = verify(dir.path()).expect("verify");
        assert!(check.intact());
        assert_eq!(check.files.len(), 2);
        // The digest of the two bytes "{}", as `sha256sum` reports it.
        let manifest = Manifest::load(dir.path()).expect("load");
        assert_eq!(manifest.files["report.json"].sha256, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    }

    #[test]
    fn changed_missing_and_extra_files_are_each_named() {
        let dir = written();
        std::fs::write(dir.path().join("report.json"), b"{ }").expect("write");
        std::fs::remove_file(dir.path().join("report.md")).expect("remove");
        std::fs::write(dir.path().join("extra.txt"), b"x").expect("write");
        let check = verify(dir.path()).expect("verify");
        assert!(!check.intact());
        assert_eq!(check.files["report.json"], Status::Changed);
        assert_eq!(check.files["report.md"], Status::Missing);
        assert_eq!(check.files["extra.txt"], Status::Unlisted);
    }

    #[test]
    fn manifest_names_cannot_reach_outside_the_folder() {
        let dir = written();
        let mut manifest = Manifest::load(dir.path()).expect("load");
        manifest.files.insert("../outside".into(), Entry { bytes: 0, sha256: String::new() });
        std::fs::write(dir.path().join(MANIFEST_NAME), manifest.to_bytes()).expect("write");
        assert_eq!(verify(dir.path()).expect("verify").files["../outside"], Status::Missing);
    }

    #[test]
    fn folder_without_manifest_is_an_error() {
        let dir = tempfile::tempdir().expect("temp dir");
        assert!(matches!(verify(dir.path()), Err(ManifestError::Read { .. })));
    }
}
