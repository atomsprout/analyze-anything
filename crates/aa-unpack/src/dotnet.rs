//! .NET bundle manifests and contents, read without loading the native host or assemblies.

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::inflate::Inflate;

pub struct Dotnet;

const KIND: &str = "dotnet-single-file";
const MAX_FILES: usize = 10_000;
const MAX_METADATA: usize = 16 * 1024 * 1024;
const SIGNATURE: &[u8] = &[
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38, 0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32, 0x13, 0xf5, 0xb9, 0xe6, 0xef, 0xae,
    0x33, 0x18, 0xee, 0x3b, 0x2d, 0xce, 0x24, 0xb3, 0x6a, 0xae,
];

const RULES: &[Rule] = &[
    Rule {
        id: "dotnet-bundle.contents",
        title_en: ".NET single-file contents",
        title_zh: ".NET 单文件包内容",
        text_en: "A .NET bundle marker and version {version} manifest declare {count} embedded files. Entries are read as data; the host and assemblies were not loaded or run.",
        text_zh: ".NET 包标记与版本 {version} 清单声明了 {count} 个内嵌文件。条目仅作为数据读取，没有加载或运行宿主与程序集。",
    },
    Rule {
        id: "dotnet-bundle.entry-unread",
        title_en: "Embedded .NET file could not be read",
        title_zh: ".NET 内嵌文件无法读取",
        text_en: "An embedded file could not be read under its declared extent and compression profile. Its contents remain unresolved.",
        text_zh: "一个内嵌文件无法按声明的范围与压缩方式读取，其内容仍未确定。",
    },
    Rule {
        id: "dotnet-bundle.manifest-unread",
        title_en: ".NET bundle metadata could not be read",
        title_zh: ".NET 包元数据无法读取",
        text_en: "The bundle was recognized, but its metadata could not be retained for the report.",
        text_zh: "已识别此包，但无法在报告中保留其元数据。",
    },
    Rule {
        id: "dotnet-bundle.file-type",
        title_en: ".NET bundle file type remains unresolved",
        title_zh: ".NET 包条目类型未确定",
        text_en: "An entry has an unsupported file-type declaration. Its bytes are retained as data, without assigning runtime semantics.",
        text_zh: "一个条目的文件类型声明不受支持。保留其字节作为数据，不赋予运行时语义。",
    },
];

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
type Result<T> = std::result::Result<T, String>;

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(count).ok_or("bundle metadata offset overflow")?;
        let value = self.bytes.get(self.at..end).ok_or("truncated bundle metadata")?;
        self.at = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| "short bundle integer")?))
    }
    fn u64(&mut self) -> Result<u64> {
        let value = u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| "short bundle integer")?);
        if value > i64::MAX as u64 {
            return Err("negative bundle size or offset".into());
        }
        Ok(value)
    }
    fn string(&mut self) -> Result<String> {
        let mut length = 0usize;
        for shift in (0..35).step_by(7) {
            let byte = self.take(1)?[0];
            if shift == 28 && byte > 7 {
                return Err("invalid bundle string length".into());
            }
            length |= usize::from(byte & 127) << shift;
            if byte & 128 == 0 {
                if length > 4096 {
                    return Err("bundle string exceeds the 4096-byte profile".into());
                }
                return std::str::from_utf8(self.take(length)?).map(str::to_string).map_err(|_| "bundle string is not UTF-8".into());
            }
        }
        Err("invalid bundle string length".into())
    }
}

struct Entry {
    name: String,
    offset: usize,
    size: u64,
    compressed: usize,
    kind: u8,
    metadata: usize,
}
struct Manifest {
    header: usize,
    end: usize,
    version: u32,
    bundle_id: String,
    configurations: Option<[(u64, u64); 2]>,
    flags: Option<u64>,
    entries: Vec<Entry>,
}

fn marker(bytes: &[u8]) -> Result<Option<(usize, usize)>> {
    if !crate::native_host(bytes) {
        return Ok(None);
    }
    let mut candidates = Vec::new();
    let mut invalid = false;
    for (ordinal, at) in memchr::memmem::find_iter(&bytes[..bytes.len().min(MAX_METADATA)], SIGNATURE).enumerate() {
        if ordinal == 16 {
            return Err("bundle marker search exceeds the 16-marker profile".into());
        }
        let Some(raw) = at.checked_sub(8).and_then(|start| bytes.get(start..at)) else { continue };
        let offset = u64::from_le_bytes(raw.try_into().map_err(|_| "short bundle marker")?);
        if offset == 0 {
            continue;
        } // An unbundled apphost carries the same signature.
        let offset = usize::try_from(offset).ok().filter(|offset| *offset >= at + SIGNATURE.len() && *offset < bytes.len());
        match offset {
            Some(offset) => candidates.push((at, offset)),
            None => invalid = true,
        }
    }
    match candidates.as_slice() {
        [] if invalid => Err("bundle header pointer lies outside the supported host layout".into()),
        [] => Ok(None),
        [candidate] => Ok(Some(*candidate)),
        _ => Err("several bundle header declarations are present; no marker was selected".into()),
    }
}

fn parse(bytes: &[u8], marker: usize, header: usize) -> Result<Manifest> {
    let metadata = bytes.get(header..).ok_or("bundle header is outside the file")?;
    let mut reader = Cursor { bytes: &metadata[..metadata.len().min(MAX_METADATA)], at: 0 };
    let major = reader.u32()?;
    let minor = reader.u32()?;
    if !matches!(major, 1 | 2 | 6) || minor != 0 {
        return Err(format!("unsupported .NET bundle version {major}.{minor}"));
    }
    let count = usize::try_from(reader.u32()?).map_err(|_| "bundle file count overflow")?;
    if count > MAX_FILES {
        return Err("bundle exceeds the 10,000-entry profile".into());
    }
    let bundle_id = reader.string()?;
    let mut configurations = None;
    let mut flags = None;
    if major >= 2 {
        let mut locations = [(0, 0); 2];
        for location in &mut locations {
            let offset = reader.u64()?;
            let size = reader.u64()?;
            if offset == 0 && size != 0 || offset.checked_add(size).is_none_or(|end| end > header as u64) {
                return Err("bundle configuration range lies outside embedded data".into());
            }
            *location = (offset, size);
        }
        let value = reader.u64()?;
        if value & !1 != 0 {
            return Err("unsupported bundle header flags".into());
        }
        configurations = Some(locations);
        flags = Some(value);
    }
    let mut entries = Vec::new();
    let mut extents = Vec::new();
    for _ in 0..count {
        let record = header + reader.at;
        let offset = usize::try_from(reader.u64()?).map_err(|_| "bundle entry offset overflow")?;
        let size = reader.u64()?;
        let compressed = if major >= 6 { usize::try_from(reader.u64()?).map_err(|_| "compressed size overflow")? } else { 0 };
        let kind = reader.take(1)?[0];
        let name = reader.string()?;
        if name.is_empty() || name.contains('\0') {
            return Err("empty or NUL-containing bundle entry name".into());
        }
        let stored = if compressed > 0 { compressed } else { usize::try_from(size).map_err(|_| "bundle entry size overflow")? };
        let end = offset.checked_add(stored).ok_or("bundle entry extent overflow")?;
        if offset < marker + SIGNATURE.len() || end > header {
            return Err("bundle entry range overlaps the host or manifest".into());
        }
        if stored > 0 {
            extents.push((offset, end));
        }
        entries.push(Entry { name, offset, size, compressed, kind, metadata: record });
    }
    extents.sort_unstable();
    if extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err("overlapping bundle entry ranges".into());
    }
    Ok(Manifest { header, end: header + reader.at, version: major, bundle_id, configurations, flags, entries })
}

impl Unpacker for Dotnet {
    fn id(&self) -> &'static str {
        "dotnet-bundle"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let position = match marker(bytes) {
            Ok(Some(position)) => position,
            Ok(None) => return Unpack::NotMine,
            Err(detail) => return Unpack::Failed { kind: KIND, detail },
        };
        let manifest = match parse(bytes, position.0, position.1) {
            Ok(manifest) => manifest,
            Err(detail) => return Unpack::Failed { kind: KIND, detail },
        };
        for entry in manifest.entries {
            let stored = if entry.compressed > 0 { entry.compressed } else { entry.size as usize };
            let data = &bytes[entry.offset..entry.offset + stored];
            let result = if entry.compressed > 0 {
                sink.add(&entry.name, &mut Inflate::new(data, entry.size, false))
            } else {
                sink.add(&entry.name, &mut &data[..])
            };
            match result {
                Ok(()) => {}
                Err(SinkError::LimitReached) => break,
                Err(SinkError::Read(detail)) => sink.limitation("dotnet-bundle.entry-unread", Some(format!("{}: {detail}", entry.name))),
            }
        }
        Unpack::Done { kind: KIND }
    }
}

impl Analyzer for Dotnet {
    fn id(&self) -> &'static str {
        "dotnet-bundle"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("dotnet-bundle") {
            return;
        }
        let retained = tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| {
            let (at, header) = marker(&bytes)?.ok_or("bundle marker no longer available")?;
            parse(&bytes, at, header)
        });
        let manifest = match retained {
            Ok(manifest) => manifest,
            Err(detail) => {
                out.limitation("dotnet-bundle.manifest-unread", Some(file), Some(detail));
                return;
            }
        };
        let header = manifest.header;
        for entry in manifest.entries.iter().filter(|entry| entry.kind > 5) {
            out.limitation("dotnet-bundle.file-type", Some(file), Some(format!("{}: type {}", entry.name, entry.kind)));
        }
        let entries: Vec<_> = manifest
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "path": entry.name, "offset": entry.offset, "size": entry.size, "compressed_size": entry.compressed,
                    "type": entry.kind, "manifest_offset": entry.metadata,
                })
            })
            .collect();
        let bundle_id = match aa_core::text::redact_sensitive_text(&manifest.bundle_id) {
            Ok(value) => value,
            Err(detail) => {
                out.limitation("dotnet-bundle.manifest-unread", Some(file), Some(detail.into()));
                return;
            }
        };
        out.fact(
            file,
            "dotnet-bundle.manifest",
            json!({"version": manifest.version, "header_offset": header,
            "bundle_id": bundle_id, "flags": manifest.flags, "configuration_ranges": manifest.configurations, "entries": entries}),
        );
        out.finding(
            Finding::new(Section::Structure, "dotnet-bundle", "dotnet-bundle.contents", Confidence::Verified, Severity::Info)
                .param("version", format!("{}.0", manifest.version))
                .param("count", manifest.entries.len())
                .evidence(Evidence::bytes(
                    file,
                    manifest.header as u64,
                    (manifest.end - manifest.header) as u64,
                    json!({"version": manifest.version, "file_count": manifest.entries.len()}),
                )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};

    fn fixture(version: u32, data: &[u8], compressed: bool) -> Vec<u8> {
        let stored = if compressed {
            let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(data).expect("compress fixture");
            encoder.finish().expect("finish fixture compression")
        } else {
            data.to_vec()
        };
        let mut bytes = vec![0; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[16..48].copy_from_slice(SIGNATURE);
        bytes.extend(&stored);
        let header = bytes.len();
        bytes[8..16].copy_from_slice(&(header as u64).to_le_bytes());
        bytes.extend(version.to_le_bytes());
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.extend(b"\x07fixture");
        if version >= 2 {
            bytes.extend([0; 40]);
        }
        bytes.extend(128u64.to_le_bytes());
        bytes.extend((data.len() as u64).to_le_bytes());
        if version >= 6 {
            bytes.extend((if compressed { stored.len() as u64 } else { 0 }).to_le_bytes());
        }
        bytes.push(1);
        bytes.extend(b"\x0bprogram.dll");
        bytes
    }

    fn subject() -> Artifact {
        Artifact {
            path: "bundle.exe".into(),
            parent: None,
            size: 0,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    #[derive(Default)]
    struct Sink {
        files: BTreeMap<String, Vec<u8>>,
        limitations: Vec<String>,
    }
    impl UnpackSink for Sink {
        fn add(&mut self, path: &str, reader: &mut dyn Read) -> std::result::Result<(), SinkError> {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).map_err(|error| SinkError::Read(error.to_string()))?;
            self.files.insert(path.into(), bytes);
            Ok(())
        }
        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.into());
        }
    }

    #[test]
    fn embedded_marker_does_not_claim_a_non_executable_container() {
        let mut bytes = b"container-prefix".to_vec();
        bytes.extend(fixture(6, b"payload", false));
        assert!(marker(&bytes).expect("outer container").is_none());
    }

    #[test]
    fn sdk_built_fixture_agrees_with_binary_reader_snapshot() {
        let bytes = include_bytes!("../tests/data/sdk-dotnet-bundle.exe");
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/sdk-dotnet-bundle.ref.json")).expect("native reference");
        assert_eq!(aa_core::sha256_hex(bytes), reference["sha256"].as_str().expect("fixture digest"));
        let (at, header) = marker(bytes).expect("marker").expect("native bundle");
        assert_eq!(header as u64, reference["reference"]["header_offset"].as_u64().expect("header offset"));
        let manifest = parse(bytes, at, header).expect("SDK manifest");
        // The marker is discovered independently; the manifest parser receives only its boundary.
        assert_eq!(manifest.entries.len(), 3);
        let mut sink = Sink::default();
        assert_eq!(Dotnet.unpack(&subject(), bytes, &mut sink), Unpack::Done { kind: KIND });
        for entry in reference["reference"]["files"].as_array().expect("native files") {
            let name = entry["path"].as_str().expect("member name");
            assert_eq!(aa_core::sha256_hex(&sink.files[name]), entry["sha256"].as_str().expect("native member digest"));
        }
    }

    #[test]
    fn supported_versions_expose_original_and_compressed_members() {
        for (version, compressed) in [(1, false), (2, false), (6, false), (6, true)] {
            let content = b"read as data, never execute".repeat(64);
            let bytes = fixture(version, &content, compressed);
            let mut sink = Sink::default();
            assert_eq!(Dotnet.unpack(&subject(), &bytes, &mut sink), Unpack::Done { kind: KIND });
            assert_eq!(sink.files["program.dll"], content);
            assert!(sink.limitations.is_empty());
        }
    }

    #[test]
    fn malformed_ranges_versions_counts_and_truncations_cannot_extract() {
        let original = fixture(6, b"payload", false);
        let (_, header) = marker(&original).expect("marker").expect("bundle");
        for (at, value) in [(header, 99u32), (header + 4, 1), (header + 8, 10_001)] {
            let mut bytes = original.clone();
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(matches!(Dotnet.unpack(&subject(), &bytes, &mut Sink::default()), Unpack::Failed { .. }));
        }
        let mut bytes = original.clone();
        bytes[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Dotnet.unpack(&subject(), &bytes, &mut Sink::default()), Unpack::Failed { .. }));
        for length in 0..original.len() {
            assert!(!matches!(Dotnet.unpack(&subject(), &original[..length], &mut Sink::default()), Unpack::Done { .. }));
        }
        let mut unbundled = original;
        unbundled[8..16].fill(0);
        assert_eq!(Dotnet.unpack(&subject(), &unbundled, &mut Sink::default()), Unpack::NotMine);
    }

    #[test]
    fn compressed_size_mismatch_and_trailing_bytes_are_not_accepted() {
        let data = b"content".repeat(256);
        let bytes = fixture(6, &data, true);
        let (_, header) = marker(&bytes).expect("marker").expect("bundle");
        let manifest = parse(&bytes, 16, header).expect("manifest");
        let stored = &bytes[128..header];
        for expected in [0, data.len() as u64 - 1, data.len() as u64 + 1] {
            assert!(Inflate::new(stored, expected, false).read_to_end(&mut Vec::new()).is_err());
        }
        let mut trailing = stored.to_vec();
        trailing.push(0);
        assert!(Inflate::new(&trailing, data.len() as u64, false).read_to_end(&mut Vec::new()).is_err());
        assert!(Inflate::new(&stored[..stored.len() - 1], data.len() as u64, false).read_to_end(&mut Vec::new()).is_err());
        let mut bad = bytes;
        let entry = manifest.entries[0].metadata;
        bad[entry + 8..entry + 16].copy_from_slice(&1u64.to_le_bytes());
        let mut sink = Sink::default();
        assert_eq!(Dotnet.unpack(&subject(), &bad, &mut sink), Unpack::Done { kind: KIND });
        assert!(sink.files.is_empty());
        assert_eq!(sink.limitations, ["dotnet-bundle.entry-unread"]);
    }
}
