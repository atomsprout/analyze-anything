//! Electron asar archives: a JSON header listing every file, then the file contents.
//!
//! Layout: a Chromium Pickle holding the header size, a second Pickle holding the header as a
//! string, then the data. Offsets in the header are relative to the end of the header.

use aa_core::Artifact;
use aa_core::plugin::{Rule, SinkError, Unpack, UnpackSink, Unpacker};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::pe::u32_at;

const MAX_HEADER: usize = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    /// SHA-256 the header records for the file, lower-case hex.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Asar {
    /// Offset in the archive where file data starts.
    pub data_start: usize,
    pub files: Vec<Entry>,
    /// Files the header lists as stored outside the archive (in `app.asar.unpacked`).
    pub unpacked: Vec<String>,
    pub links: usize,
    pub truncated: bool,
}

/// Parses the header. `Err` carries why `data` is not a readable asar archive.
pub fn parse(data: &[u8]) -> Result<Asar, String> {
    // Pickle 1: payload size 4, then the size of pickle 2.
    if u32_at(data, 0) != Some(4) {
        return Err("no asar size pickle".into());
    }
    let header_pickle = u32_at(data, 4).ok_or("file too short")? as usize;
    if !(8..=MAX_HEADER).contains(&header_pickle) {
        return Err(format!("header size {header_pickle} is not plausible"));
    }
    let data_start = 8usize.checked_add(header_pickle).ok_or("header size overflow")?;
    // Pickle 2: payload size, string length, string bytes.
    let length = u32_at(data, 12).ok_or("file too short")? as usize;
    let json = data.get(16..16usize.saturating_add(length)).ok_or("the header runs past the end of the file")?;
    if 16 + length > data_start {
        return Err("header string longer than its pickle".into());
    }
    let header: Value = serde_json::from_slice(json).map_err(|e| format!("header is not JSON: {e}"))?;
    let files = header.get("files").and_then(Value::as_object).ok_or("header has no \"files\" object")?;
    let mut asar = Asar { data_start, ..Asar::default() };
    walk(files, "", 0, &mut asar);
    Ok(asar)
}

fn walk(directory: &serde_json::Map<String, Value>, prefix: &str, depth: usize, asar: &mut Asar) {
    for (name, node) in directory {
        if asar.files.len() + asar.unpacked.len() >= MAX_ENTRIES || depth > MAX_DEPTH {
            asar.truncated = true;
            return;
        }
        let path = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        if let Some(children) = node.get("files").and_then(Value::as_object) {
            walk(children, &path, depth + 1, asar);
        } else if node.get("link").is_some() {
            asar.links += 1;
        } else if node.get("unpacked").and_then(Value::as_bool) == Some(true) {
            asar.unpacked.push(path);
        } else {
            // The offset is a decimal string (it may exceed what a JSON number holds exactly).
            let offset = node.get("offset").and_then(|o| o.as_str().and_then(|s| s.parse().ok()).or(o.as_u64()));
            let size = node.get("size").and_then(Value::as_u64);
            if let (Some(offset), Some(size)) = (offset, size) {
                let integrity = node.get("integrity");
                let sha256 = integrity
                    .filter(|i| i.get("algorithm").and_then(Value::as_str).is_some_and(|a| a.eq_ignore_ascii_case("SHA256")))
                    .and_then(|i| i.get("hash"))
                    .and_then(Value::as_str)
                    .map(str::to_ascii_lowercase);
                asar.files.push(Entry { path, offset, size, sha256 });
            }
        }
    }
}

impl Asar {
    /// The bytes of `entry`, when they lie inside `data`.
    pub fn bytes<'a>(&self, data: &'a [u8], entry: &Entry) -> Option<&'a [u8]> {
        let start = (self.data_start as u64).checked_add(entry.offset)?;
        let end = start.checked_add(entry.size)?;
        data.get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
    }

    /// Checks every recorded SHA-256 against the stored bytes:
    /// `(files with a recorded hash, files that match, paths that do not)`.
    pub fn verify(&self, data: &[u8]) -> (usize, usize, Vec<String>) {
        let (mut with_hash, mut matching, mut failed) = (0, 0, Vec::new());
        for entry in &self.files {
            let Some(expected) = &entry.sha256 else { continue };
            with_hash += 1;
            match self.bytes(data, entry) {
                Some(bytes) if hex::encode(Sha256::digest(bytes)) == *expected => matching += 1,
                _ => failed.push(entry.path.clone()),
            }
        }
        (with_hash, matching, failed)
    }
}

pub struct AsarUnpacker;

pub const RULES: &[Rule] = &[Rule {
    id: "asar.entries-unreadable",
    title_zh: "asar 包内部分文件无法读取",
    title_en: "Some asar entries could not be read",
    text_zh: "asar 文件头列出的部分文件超出了文件范围，这些文件没有分析。",
    text_en: "Some files listed in the asar header lie outside the archive. They were not analyzed.",
}];

impl Unpacker for AsarUnpacker {
    fn id(&self) -> &'static str {
        "asar"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        // The cheap test first: the two fixed pickle fields and an opening brace.
        if u32_at(bytes, 0) != Some(4) || bytes.get(16) != Some(&b'{') {
            return Unpack::NotMine;
        }
        let Ok(asar) = parse(bytes) else { return Unpack::NotMine };
        let mut missing = 0usize;
        for entry in &asar.files {
            let Some(mut data) = asar.bytes(bytes, entry) else {
                missing += 1;
                continue;
            };
            if sink.add(&entry.path, &mut data) == Err(SinkError::LimitReached) {
                break;
            }
        }
        if missing > 0 {
            sink.limitation("asar.entries-unreadable", Some(aa_core::counted(missing as u64, "entries lie outside the archive")));
        }
        Unpack::Done { kind: "asar" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/data/fixture.asar");

    #[test]
    fn fixture_lists_and_verifies() {
        let asar = parse(FIXTURE).expect("asar");
        let paths: Vec<&str> = asar.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["lib/util.js", "main.js", "package.json"]);
        let util = asar.files.iter().find(|f| f.path == "lib/util.js").expect("util");
        assert_eq!(asar.bytes(FIXTURE, util), Some(b"module.exports = () => 42;\n".as_slice()));
        assert_eq!(asar.verify(FIXTURE), (3, 3, Vec::new()));
    }

    #[test]
    fn changed_content_fails_integrity() {
        let mut changed = FIXTURE.to_vec();
        let last = changed.len() - 2;
        changed[last] ^= 1;
        let asar = parse(&changed).expect("asar");
        let (with_hash, matching, failed) = asar.verify(&changed);
        assert_eq!((with_hash, matching), (3, 2));
        assert_eq!(failed, ["lib/util.js"]);
    }

    #[test]
    fn malformed_archives_do_not_panic() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[4, 0, 0, 0]).is_err());
        assert!(parse(&[4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f]).is_err());
        for cut in [8, 12, 16, 17, 40, FIXTURE.len() / 2] {
            // A cut header is an error; a cut body parses and its entries simply have no bytes.
            if let Ok(asar) = parse(&FIXTURE[..cut]) {
                asar.verify(&FIXTURE[..cut]);
            }
        }
        // Offsets and sizes far past the end.
        let header = br#"{"files":{"a":{"size":18446744073709551615,"offset":"18446744073709551615"},"b":{"files":{"c":{"size":5,"offset":"99999"}}}}}"#;
        let mut data = Vec::new();
        let padded = header.len().div_ceil(4) * 4;
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&(padded as u32 + 8).to_le_bytes());
        data.extend_from_slice(&(padded as u32 + 4).to_le_bytes());
        data.extend_from_slice(&(header.len() as u32).to_le_bytes());
        data.extend_from_slice(header);
        data.resize(16 + padded, 0);
        let asar = parse(&data).expect("header parses");
        assert_eq!(asar.files.len(), 2);
        assert!(asar.files.iter().all(|f| asar.bytes(&data, f).is_none()));
    }
}
