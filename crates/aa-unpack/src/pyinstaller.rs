//! Bounded PyInstaller CArchive records. Python bytecode is kept as bytes, never loaded.

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::inflate::Inflate;

pub struct PyInstaller;
const MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const KIND: &str = "pyinstaller";
const LIMIT: usize = 16 * 1024 * 1024;
type Result<T> = std::result::Result<T, String>;

const RULES: &[Rule] = &[
    Rule {
        id: "pyinstaller.contents",
        title_en: "PyInstaller archive contents",
        title_zh: "PyInstaller 包内容",
        text_en: "A PyInstaller CArchive directory declares {count} entries and Python version code {python}. Supported member bytes are exposed without running the bootloader or loading Python code.",
        text_zh: "PyInstaller CArchive 目录声明了 {count} 个条目，Python 版本代码为 {python}。读取受支持条目的字节，没有运行引导程序或加载 Python 代码。",
    },
    Rule {
        id: "pyinstaller.entry-unread",
        title_en: "PyInstaller member could not be read",
        title_zh: "PyInstaller 条目无法读取",
        text_en: "A member's bytes could not be read under the supported size, compression or item-type profile.",
        text_zh: "一个条目的字节无法按受支持的大小、压缩或条目类型读取。",
    },
    Rule {
        id: "pyinstaller.external-reference",
        title_en: "PyInstaller reference remains unresolved",
        title_zh: "PyInstaller 引用未确定",
        text_en: "A symbolic-link or external-dependency declaration was retained in the directory but was not followed or treated as payload bytes.",
        text_zh: "目录中保留了符号链接或外部依赖声明，但没有跟随引用，也没有将其当作载荷字节。",
    },
    Rule {
        id: "pyinstaller.python-code",
        title_en: "Python code remains opaque",
        title_zh: "Python 代码仍为不透明内容",
        text_en: "The directory declares Python marshal bytecode or a PYZ archive. Python objects were not loaded, and module source, imports and control flow remain unread.",
        text_zh: "目录声明了 Python marshal 字节码或 PYZ 包。没有加载 Python 对象，模块源码、导入与控制流仍未读取。",
    },
    Rule {
        id: "pyinstaller.metadata-unread",
        title_en: "PyInstaller directory could not be retained",
        title_zh: "PyInstaller 目录无法保留",
        text_en: "The archive was recognized, but its directory metadata could not be retained in the report.",
        text_zh: "已识别此包，但无法在报告中保留其目录元数据。",
    },
];

struct Entry {
    name: String,
    offset: usize,
    stored: usize,
    size: u32,
    compressed: u8,
    kind: u8,
    record: usize,
}
struct Archive {
    start: usize,
    cookie: usize,
    toc: usize,
    python: u32,
    library: String,
    entries: Vec<Entry>,
}

fn number(bytes: &[u8], offset: usize) -> Result<usize> {
    let raw = bytes.get(offset..offset.checked_add(4).ok_or("CArchive integer offset overflow")?).ok_or("truncated CArchive integer")?;
    usize::try_from(u32::from_be_bytes(raw.try_into().map_err(|_| "short CArchive integer")?))
        .map_err(|_| "CArchive integer overflow".into())
}

fn parse_at(bytes: &[u8], cookie: usize) -> Result<Archive> {
    let end = cookie.checked_add(88).filter(|end| *end <= bytes.len()).ok_or("unsupported old or truncated CArchive cookie")?;
    let package_size = number(bytes, cookie + 8)?;
    let start = end.checked_sub(package_size).ok_or("CArchive package length exceeds captured bytes")?;
    let toc = start.checked_add(number(bytes, cookie + 12)?).ok_or("CArchive directory offset overflow")?;
    let toc_size = number(bytes, cookie + 16)?;
    if toc_size > LIMIT || toc.checked_add(toc_size) != Some(cookie) || toc < start {
        return Err("CArchive directory is outside the bounded contiguous-cookie profile".into());
    }
    let python = u32::try_from(number(bytes, cookie + 20)?).map_err(|_| "Python version code overflow")?;
    let library = &bytes[cookie + 24..end];
    let length = library.iter().position(|b| *b == 0).unwrap_or(library.len());
    if library[length..].iter().any(|b| *b != 0) {
        return Err("unsupported CArchive library-name padding".into());
    }
    let library = std::str::from_utf8(&library[..length]).map_err(|_| "CArchive library name is not UTF-8")?.to_string();
    let mut at = toc;
    let mut entries = Vec::new();
    let mut extents = Vec::new();
    while at < cookie {
        if entries.len() == 10_000 {
            return Err("CArchive directory exceeds the 10,000-entry profile".into());
        }
        let length = number(bytes, at)?;
        if !(19..=18 + 4096).contains(&length) {
            return Err("CArchive entry name/record length is outside the supported profile".into());
        }
        let record_end = at.checked_add(length).filter(|end| *end <= cookie).ok_or("CArchive directory record is truncated")?;
        let offset = start.checked_add(number(bytes, at + 4)?).ok_or("CArchive member offset overflow")?;
        let stored = number(bytes, at + 8)?;
        let size = u32::try_from(number(bytes, at + 12)?).map_err(|_| "CArchive member size overflow")?;
        let compressed = bytes[at + 16];
        let kind = bytes[at + 17];
        let name = &bytes[at + 18..record_end];
        let length = name.iter().rposition(|b| *b != 0).map_or(0, |at| at + 1);
        let name = std::str::from_utf8(&name[..length]).map_err(|_| "CArchive member name is not UTF-8")?;
        if name.is_empty() || name.contains('\0') {
            return Err("empty or NUL-containing CArchive member name".into());
        }
        let data_end = offset.checked_add(stored).filter(|end| *end <= toc).ok_or("CArchive member overlaps the directory or cookie")?;
        if stored > 0 {
            extents.push((offset, data_end));
        }
        entries.push(Entry { name: name.into(), offset, stored, size, compressed, kind, record: at });
        at = record_end;
    }
    extents.sort_unstable();
    if extents.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err("overlapping CArchive member extents".into());
    }
    Ok(Archive { start, cookie, toc, python, library, entries })
}

fn parse(bytes: &[u8]) -> Result<Option<Archive>> {
    let start = bytes.len().saturating_sub(LIMIT);
    let host = crate::native_host(bytes);
    let mut found = None;
    let mut failure = None;
    let mut examined = 0;
    for at in memchr::memmem::find_iter(&bytes[start..], MAGIC) {
        let absolute = start + at;
        if !host && !number(bytes, absolute + 8).ok().is_some_and(|length| length == absolute + 88 || length == absolute + 24) {
            continue;
        }
        if examined == 16 {
            return Err("CArchive cookie search exceeds the 16-marker profile".into());
        }
        examined += 1;
        match parse_at(bytes, absolute) {
            Ok(archive) => {
                // A cookie inside another file is not proof that the outer file is a CArchive.
                if !host && archive.start != 0 {
                    continue;
                }
                if found.is_some() {
                    return Err("several CArchive cookie declarations are present; no cookie was selected".into());
                }
                found = Some(archive);
            }
            Err(error) if host || start + at + 88 == bytes.len() => failure = Some(error),
            Err(_) => {}
        }
    }
    if found.is_some() {
        Ok(found)
    } else if let Some(failure) = failure {
        Err(failure)
    } else {
        Ok(None)
    }
}

impl Unpacker for PyInstaller {
    fn id(&self) -> &'static str {
        KIND
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let archive = match parse(bytes) {
            Ok(Some(archive)) => archive,
            Ok(None) => return Unpack::NotMine,
            Err(detail) => return Unpack::Failed { kind: KIND, detail },
        };
        for entry in archive.entries {
            if entry.kind == b'o' && entry.stored == 0 && entry.size == 0 {
                continue;
            }
            if matches!(entry.kind, b'n' | b'd') {
                sink.limitation("pyinstaller.external-reference", Some(entry.name));
                continue;
            }
            if entry.compressed > 1
                || !b"bzmMsxZl".contains(&entry.kind)
                || entry.compressed == 0 && entry.stored as u64 != u64::from(entry.size)
            {
                sink.limitation("pyinstaller.entry-unread", Some(entry.name));
                continue;
            }
            let data = &bytes[entry.offset..entry.offset + entry.stored];
            let result = if entry.compressed == 1 {
                sink.add(&entry.name, &mut Inflate::new(data, u64::from(entry.size), true))
            } else {
                sink.add(&entry.name, &mut &data[..])
            };
            match result {
                Ok(()) => {}
                Err(SinkError::LimitReached) => break,
                Err(SinkError::Read(detail)) => sink.limitation("pyinstaller.entry-unread", Some(format!("{}: {detail}", entry.name))),
            }
        }
        Unpack::Done { kind: KIND }
    }
}

impl Analyzer for PyInstaller {
    fn id(&self) -> &'static str {
        KIND
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some(KIND) {
            return;
        }
        let archive = tree
            .read(&file.path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| parse(&bytes)?.ok_or("CArchive cookie no longer available".into()));
        let archive = match archive {
            Ok(archive) => archive,
            Err(detail) => {
                out.limitation("pyinstaller.metadata-unread", Some(file), Some(detail));
                return;
            }
        };
        let entries: Vec<_> = archive
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "name": entry.name, "offset": entry.offset, "stored_size": entry.stored, "size": entry.size,
                    "compression_flag": entry.compressed, "type": char::from(entry.kind).to_string(), "toc_offset": entry.record,
                })
            })
            .collect();
        if archive.entries.iter().any(|entry| b"zmMs".contains(&entry.kind)) {
            out.limitation("pyinstaller.python-code", Some(file), None);
        }
        out.fact(
            file,
            "pyinstaller.directory",
            json!({"archive_start":archive.start,"cookie_offset":archive.cookie,
            "python_version":archive.python,"python_library":archive.library,"entries":entries}),
        );
        out.finding(
            Finding::new(Section::Structure, KIND, "pyinstaller.contents", Confidence::Verified, Severity::Info)
                .param("count", archive.entries.len())
                .param("python", archive.python)
                .evidence(Evidence::bytes(
                    file,
                    archive.toc as u64,
                    (archive.cookie - archive.toc + 88) as u64,
                    json!({"entry_count":archive.entries.len(),"python_version":archive.python}),
                )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};

    fn fixture(kind: u8, content: &[u8], compressed: bool) -> Vec<u8> {
        let stored = if compressed {
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(content).expect("compress member");
            encoder.finish().expect("finish member")
        } else {
            content.to_vec()
        };
        let mut bytes = vec![0; 64];
        bytes[..2].copy_from_slice(b"MZ");
        bytes.extend(&stored);
        for value in [32u32, 0, stored.len() as u32, content.len() as u32] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.extend([u8::from(compressed), kind]);
        bytes.extend(b"data.bin");
        bytes.extend([0; 6]);
        bytes.extend(MAGIC);
        for value in [(stored.len() + 32 + 88) as u32, stored.len() as u32, 32, 313] {
            bytes.extend(value.to_be_bytes());
        }
        let mut library = [0; 64];
        library[..13].copy_from_slice(b"python313.dll");
        bytes.extend(library);
        bytes
    }

    fn subject() -> Artifact {
        Artifact {
            path: "sample.exe".into(),
            parent: None,
            size: 0,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: Some(KIND.into()),
            facts: BTreeMap::new(),
        }
    }

    #[derive(Default)]
    struct Sink {
        files: BTreeMap<String, Vec<u8>>,
        limitations: Vec<String>,
    }
    impl UnpackSink for Sink {
        fn add(&mut self, name: &str, reader: &mut dyn Read) -> std::result::Result<(), SinkError> {
            let mut data = Vec::new();
            reader.read_to_end(&mut data).map_err(|error| SinkError::Read(error.to_string()))?;
            self.files.insert(name.into(), data);
            Ok(())
        }
        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.into());
        }
    }

    #[test]
    fn nested_archive_cookie_does_not_claim_its_non_executable_container() {
        let mut bytes = b"outer-container-prefix".to_vec();
        bytes.extend(include_bytes!("../tests/data/native-carchive.pkg"));
        assert!(parse(&bytes).expect("nested cookie").is_none());
    }

    #[test]
    fn native_carchive_writer_fixture_agrees_with_archive_viewer() {
        let bytes = include_bytes!("../tests/data/native-carchive.pkg");
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/native-carchive.ref.json")).expect("native reference");
        assert_eq!(aa_core::sha256_hex(bytes), reference["sha256"].as_str().expect("fixture digest"));
        let archive = parse(bytes).expect("native archive").expect("recognized");
        assert_eq!(archive.entries.len(), 1);
        let mut sink = Sink::default();
        assert_eq!(PyInstaller.unpack(&subject(), bytes, &mut sink), Unpack::Done { kind: KIND });
        assert_eq!(aa_core::sha256_hex(&sink.files["data.txt"]), reference["files"][0]["sha256"].as_str().expect("native digest"));
    }

    #[test]
    fn stored_and_zlib_members_allow_signed_file_trailers() {
        for compressed in [false, true] {
            let mut bytes = fixture(b'x', b"original contents", compressed);
            bytes.extend(b"opaque post-bundle signature bytes");
            let mut sink = Sink::default();
            assert_eq!(PyInstaller.unpack(&subject(), &bytes, &mut sink), Unpack::Done { kind: KIND });
            assert_eq!(sink.files["data.bin"], b"original contents");
            assert!(sink.limitations.is_empty());
        }
    }

    #[test]
    fn options_are_metadata_and_links_do_not_become_payloads() {
        let mut sink = Sink::default();
        assert_eq!(PyInstaller.unpack(&subject(), &fixture(b'o', b"", false), &mut sink), Unpack::Done { kind: KIND });
        assert!(sink.files.is_empty());
        assert!(sink.limitations.is_empty());
        for kind in *b"nd" {
            let mut sink = Sink::default();
            PyInstaller.unpack(&subject(), &fixture(kind, b"not a followed path", false), &mut sink);
            assert!(sink.files.is_empty());
            assert_eq!(sink.limitations, ["pyinstaller.external-reference"]);
        }
    }

    #[test]
    fn corrupt_records_and_unsupported_compression_stay_explicit() {
        let bytes = fixture(b'x', b"contents", true);
        let archive = parse(&bytes).expect("archive").expect("recognized");
        let mut bad = bytes.clone();
        bad[archive.toc + 16] = 2;
        let mut sink = Sink::default();
        assert_eq!(PyInstaller.unpack(&subject(), &bad, &mut sink), Unpack::Done { kind: KIND });
        assert!(sink.files.is_empty());
        assert_eq!(sink.limitations, ["pyinstaller.entry-unread"]);
        for at in [archive.toc, archive.toc + 4, archive.cookie + 8, archive.cookie + 12, archive.cookie + 16] {
            let mut bad = bytes.clone();
            bad[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert!(matches!(PyInstaller.unpack(&subject(), &bad, &mut Sink::default()), Unpack::Failed { .. }));
        }
        for length in 0..bytes.len() {
            assert!(!matches!(PyInstaller.unpack(&subject(), &bytes[..length], &mut Sink::default()), Unpack::Done { .. }));
        }
    }

    #[test]
    fn bytecode_scope_is_separate_from_archive_enumeration() {
        struct Memory {
            files: Vec<Artifact>,
            bytes: Vec<u8>,
        }
        impl Tree for Memory {
            fn artifacts(&self) -> &[Artifact] {
                &self.files
            }
            fn read(&self, _path: &str) -> std::io::Result<aa_core::plugin::Bytes> {
                Ok(aa_core::plugin::Bytes::from_vec(self.bytes.clone()))
            }
        }
        let tree = Memory { files: vec![subject()], bytes: fixture(b's', b"opaque marshal bytes", true) };
        let mut sink = Sink::default();
        PyInstaller.unpack(&tree.files[0], &tree.bytes, &mut sink);
        assert!(sink.limitations.is_empty());
        assert_eq!(sink.files["data.bin"], b"opaque marshal bytes");
        let mut out = Output::default();
        PyInstaller.analyze_file(&tree, &tree.files[0], &mut out);
        assert_eq!(out.limitations[0].code, "pyinstaller.python-code");
        assert_eq!(out.facts[0].value["entries"][0]["type"], "s");
    }
}
