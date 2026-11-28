//! Common, GNU and BSD ar directories. Thin members remain external declarations.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::{MAX_ENTRIES, MAX_METADATA, Result, extent};

pub struct Ar;

const MAX_NAME: usize = 4096;
const RULES: &[Rule] = &[
    Rule {
        id: "ar.contents",
        title_en: "ar archive contents",
        title_zh: "ar 归档内容",
        text_en: "The ar directory declares {count} ordinary members. Stored member bytes were offered to the analysis tree; external thin-archive references were not followed.",
        text_zh: "ar 目录声明了 {count} 个普通成员。存储的成员字节交给分析树读取，没有跟随瘦归档的外部引用。",
    },
    Rule {
        id: "ar.symbol-index",
        title_en: "Declared ar symbol indexes",
        title_zh: "ar 符号索引声明",
        text_en: "The archive contains {count} symbol indexes. Supported GNU index names and member-header offsets are retained as declarations; linker selection and executable behavior were not established.",
        text_zh: "归档包含 {count} 个符号索引。受支持的 GNU 索引名称和成员头偏移作为声明保留，没有确定链接器选择或可执行行为。",
    },
    Rule {
        id: "ar.directory-unread",
        title_en: "ar directory could not be read",
        title_zh: "ar 目录无法读取",
        text_en: "The archive was recognized, but its complete directory could not be retained within the supported common/GNU/BSD profile.",
        text_zh: "已识别归档，但无法在受支持的通用、GNU 和 BSD 范围内保留完整目录。",
    },
    Rule {
        id: "ar.entry-unread",
        title_en: "ar member could not be read",
        title_zh: "ar 成员无法读取",
        text_en: "A stored ar member could not be retained in the analysis tree.",
        text_zh: "一个存储的 ar 成员无法保留到分析树。",
    },
    Rule {
        id: "ar.thin-reference",
        title_en: "Thin ar members remain external references",
        title_zh: "瘦 ar 成员仍为外部引用",
        text_en: "Thin-archive members name files outside the archive. Their names and declared sizes were retained, but no host path was opened and no member contents were established.",
        text_zh: "瘦归档成员命名归档外的文件。保留了名称和声明大小，但没有打开主机路径，也没有确定成员内容。",
    },
    Rule {
        id: "ar.symbol-index-unread",
        title_en: "ar symbol index semantics remain unresolved",
        title_zh: "ar 符号索引语义未确定",
        text_en: "A symbol-index descriptor was retained, but its entries were malformed, exceeded a budget or used an unsupported BSD/COFF index profile. Ordinary stored members remain independently readable.",
        text_zh: "已保留符号索引描述，但其条目格式错误、超出限制，或采用不受支持的 BSD、COFF 索引格式。普通存储成员仍可独立读取。",
    },
];

#[derive(Debug)]
struct Member {
    name: String,
    encoding: &'static str,
    kind: &'static str,
    header: usize,
    stored_offset: usize,
    stored_size: usize,
    offset: Option<usize>,
    size: usize,
    mode: Option<u64>,
    external_header: Option<u64>,
}

#[derive(Debug)]
struct Directory {
    thin: bool,
    members: Vec<Member>,
}

fn unsigned(bytes: &[u8], radix: u32, optional: bool) -> Result<Option<u64>> {
    let text = std::str::from_utf8(bytes).map_err(|_| "ar numeric field is not ASCII")?.trim_matches(' ');
    if text.is_empty() && optional {
        return Ok(None);
    }
    if text.is_empty()
        || !text.bytes().all(|byte| match radix {
            8 => (b'0'..=b'7').contains(&byte),
            _ => byte.is_ascii_digit(),
        })
    {
        return Err("invalid unsigned ar numeric field".into());
    }
    u64::from_str_radix(text, radix).map(Some).map_err(|_| "ar integer exceeds the supported range".into())
}

fn decimal(text: &str) -> Result<usize> {
    usize::try_from(unsigned(text.as_bytes(), 10, false)?.ok_or("missing ar integer")?)
        .map_err(|_| "ar integer exceeds address space".into())
}

fn name(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty() || bytes.len() > MAX_NAME || bytes.contains(&0) {
        return Err("ar member name is empty, contains NUL or exceeds 4096 bytes".into());
    }
    std::str::from_utf8(bytes).map(str::to_string).map_err(|_| "ar member name is not UTF-8".into())
}

fn symbol_index(name: &str) -> bool {
    matches!(name, "/" | "/SYM64/" | "__.SYMDEF" | "__.SYMDEF SORTED" | "__.SYMDEF_64" | "__.SYMDEF_64 SORTED" | "/<ECSYMBOLS>/")
}

/// Resolve GNU name references once, so overlapping references cannot multiply scanning work.
fn name_table(bytes: &[u8]) -> Result<BTreeMap<usize, String>> {
    if bytes.len() > MAX_METADATA {
        return Err("ar name table exceeds 16 MiB".into());
    }
    let mut names = BTreeMap::new();
    let mut at = 0;
    while at < bytes.len() {
        // LLVM may include a final newline to make this special member even sized.
        if at + 1 == bytes.len() && bytes[at] == b'\n' {
            break;
        }
        if names.len() >= MAX_ENTRIES {
            return Err("ar name-table entry budget exhausted".into());
        }
        let rest = &bytes[at..];
        let length = rest.iter().position(|byte| *byte == b'\n').ok_or("unterminated GNU ar long name")?;
        let raw = rest[..length].strip_suffix(b"/").ok_or("GNU ar long name has no slash terminator")?;
        names.insert(at, name(raw)?);
        at += length + 1;
    }
    Ok(names)
}

fn parse(bytes: &[u8]) -> Result<Directory> {
    let thin = bytes.starts_with(b"!<thin>\n");
    if !thin && !bytes.starts_with(b"!<arch>\n") {
        return Err("missing ar archive magic".into());
    }
    let mut at = 8usize;
    let mut members = Vec::new();
    let mut names_size = 0usize;
    let mut names = None;
    while at < bytes.len() {
        if members.len() >= MAX_ENTRIES {
            return Err("ar member count exceeds 100000".into());
        }
        let header = extent(bytes, at, 60)?;
        if &header[58..60] != b"`\n" {
            return Err("invalid ar header terminator".into());
        }
        let raw = std::str::from_utf8(&header[..16]).map_err(|_| "ar header name is not UTF-8")?.trim_end_matches(' ');
        let declared = usize::try_from(unsigned(&header[48..58], 10, false)?.ok_or("missing ar member size")?)
            .map_err(|_| "ar member size exceeds address space")?;
        let mode = unsigned(&header[40..48], 8, true)?;
        let data_at = at.checked_add(60).ok_or("ar header offset overflow")?;
        let mut offset = data_at;
        let mut size = declared;
        let mut external_header = None;
        let (member_name, encoding) = if let Some(inline) = raw.strip_prefix("#1/") {
            if thin {
                return Err("BSD inline names in a thin archive are outside the supported profile".into());
            }
            let length = decimal(inline)?;
            if length > MAX_NAME || length > declared {
                return Err("BSD ar inline name exceeds member size or 4096 bytes".into());
            }
            let raw_name = extent(bytes, data_at, length)?;
            let end = raw_name.iter().position(|byte| *byte == 0).unwrap_or(length);
            if raw_name[end..].iter().any(|byte| *byte != 0) {
                return Err("BSD ar inline name has data after its NUL padding".into());
            }
            offset = data_at.checked_add(length).ok_or("BSD ar member offset overflow")?;
            size -= length;
            (name(&raw_name[..end])?, "bsd-inline")
        } else if raw == "//" || symbol_index(raw) {
            (raw.to_string(), "special")
        } else if let Some(reference) = raw.strip_prefix('/') {
            let (reference, nested) = reference.split_once(':').map_or((reference, None), |(table, header)| (table, Some(header)));
            if let Some(nested) = nested {
                if !thin {
                    return Err("nested-member offsets are only supported as thin declarations".into());
                }
                external_header = Some(u64::try_from(decimal(nested)?).map_err(|_| "thin member header offset exceeds u64")?);
            }
            let index = decimal(reference)?;
            let table: &BTreeMap<usize, String> = names.as_ref().ok_or("GNU ar name reference precedes its name table")?;
            (table.get(&index).ok_or("GNU ar name offset does not identify a name boundary")?.clone(), "gnu-table")
        } else {
            (name(raw.strip_suffix('/').unwrap_or(raw).as_bytes())?, "short")
        };
        names_size = names_size.checked_add(member_name.len()).ok_or("ar name budget overflow")?;
        if names_size > MAX_METADATA {
            return Err("ar resolved names exceed 16 MiB".into());
        }
        let kind = if member_name == "//" {
            "name-table"
        } else if symbol_index(&member_name) {
            "symbol-index"
        } else {
            "member"
        };
        let external = thin && kind == "member";
        let stored = if external { 0 } else { declared };
        if !external {
            let body = extent(bytes, data_at, stored)?;
            if kind == "name-table" {
                if names.is_some() {
                    return Err("repeated GNU ar name tables are outside the supported profile".into());
                }
                names_size = names_size.checked_add(body.len()).ok_or("ar name-table budget overflow")?;
                if names_size > MAX_METADATA {
                    return Err("ar name-table and resolved names exceed the shared 16 MiB budget".into());
                }
                names = Some(name_table(body)?);
            }
        }
        let end = data_at.checked_add(stored).ok_or("ar stored member extent overflow")?;
        if stored % 2 != 0 && extent(bytes, end, 1)? != b"\n" {
            return Err("invalid ar member alignment byte".into());
        }
        members.push(Member {
            name: member_name,
            encoding,
            kind,
            header: at,
            stored_offset: data_at,
            stored_size: stored,
            offset: (!external).then_some(offset),
            size,
            mode,
            external_header,
        });
        at = end.checked_add(stored % 2).ok_or("ar alignment overflow")?;
    }
    Ok(Directory { thin, members })
}

/// GNU indexes use big-endian words even when their object members use another byte order.
/// The index is evidence about archive declarations, never a substitute for object symbols.
fn gnu_index(bytes: &[u8], member: &Member, headers: &BTreeSet<u64>, budget: &mut (usize, usize)) -> Result<Value> {
    let width = match member.name.as_str() {
        "/" => 4,
        "/SYM64/" => 8,
        _ => return Err("BSD/COFF-specific symbol index entries are not interpreted".into()),
    };
    let data = extent(bytes, member.offset.ok_or("symbol index has no stored body")?, member.size)?;
    budget.0 = budget.0.checked_add(data.len()).ok_or("ar symbol-index byte budget overflow")?;
    if budget.0 > MAX_METADATA {
        return Err("ar symbol-index bodies exceed the shared 16 MiB budget".into());
    }
    let word = |at| -> Result<u64> {
        let raw = extent(data, at, width)?;
        Ok(raw.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte)))
    };
    let count = usize::try_from(word(0)?).map_err(|_| "ar symbol count exceeds address space")?;
    budget.1 = budget.1.checked_add(count).ok_or("ar symbol count overflow")?;
    if budget.1 > MAX_ENTRIES {
        return Err("ar symbols exceed the shared 100000-entry budget".into());
    }
    let offsets_size = count.checked_mul(width).ok_or("ar symbol offsets overflow")?;
    extent(data, width, offsets_size)?;
    let mut next = width.checked_add(offsets_size).ok_or("ar symbol names offset overflow")?;
    let mut symbols = Vec::new();
    for index in 0..count {
        let header = word(width + index * width)?;
        if !headers.contains(&header) {
            return Err("ar symbol index references no ordinary member header".into());
        }
        let tail = &data[next..];
        let length = tail.iter().position(|byte| *byte == 0).ok_or("unterminated ar index symbol name")?;
        let symbol = name(&tail[..length])?;
        symbols.push(json!({"name": symbol, "member_header_offset": header,
            "name_offset": member.offset.ok_or("symbol index has no stored body")? + next}));
        next += length + 1;
    }
    if data[next..].iter().any(|byte| *byte != 0) {
        return Err("uninterpreted trailing ar symbol-index bytes".into());
    }
    Ok(json!({"word_bits": width * 8, "symbols": symbols}))
}

impl Unpacker for Ar {
    fn id(&self) -> &'static str {
        "ar"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(b"!<arch>\n") && !bytes.starts_with(b"!<thin>\n") {
            return Unpack::NotMine;
        }
        let directory = match parse(bytes) {
            Ok(directory) => directory,
            Err(detail) => return Unpack::Failed { kind: "ar", detail },
        };
        for member in directory.members.iter().filter(|entry| entry.kind == "member") {
            if let Some(offset) = member.offset {
                let mut data = &bytes[offset..offset + member.size];
                match sink.add(&member.name, &mut data) {
                    Ok(()) => {}
                    Err(SinkError::LimitReached) => break,
                    Err(SinkError::Read(detail)) => sink.limitation("ar.entry-unread", Some(format!("{}: {detail}", member.name))),
                }
            }
        }
        if directory.thin && directory.members.iter().any(|entry| entry.kind == "member") {
            sink.limitation("ar.thin-reference", None);
        }
        Unpack::Done { kind: "ar" }
    }
}

impl Analyzer for Ar {
    fn id(&self) -> &'static str {
        "ar"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("ar") {
            return;
        }
        let result =
            tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| parse(&bytes).map(|directory| (bytes, directory)));
        let (bytes, directory) = match result {
            Ok(value) => value,
            Err(detail) => {
                out.limitation("ar.directory-unread", Some(file), Some(detail));
                return;
            }
        };
        let mut indexes = Vec::new();
        let headers = directory.members.iter().filter(|entry| entry.kind == "member").map(|entry| entry.header as u64).collect();
        let mut index_budget = (0, 0);
        let members: Vec<_> = directory
            .members
            .iter()
            .map(|member| {
                if member.kind == "symbol-index" {
                    let entries = match gnu_index(&bytes, member, &headers, &mut index_budget) {
                        Ok(value) => Some(value),
                        Err(detail) => {
                            out.limitation("ar.symbol-index-unread", Some(file), Some(format!("header {}: {detail}", member.header)));
                            None
                        }
                    };
                    indexes.push(json!({"name": member.name, "header_offset": member.header, "offset": member.offset,
                    "size": member.size, "entries": entries}));
                }
                json!({"name": member.name, "name_encoding": member.encoding, "kind": member.kind, "header_offset": member.header,
                "stored_offset": member.stored_offset, "stored_size": member.stored_size, "offset": member.offset,
                "size": member.size, "mode": member.mode, "external_member_header_offset": member.external_header})
            })
            .collect();
        let count = directory.members.iter().filter(|entry| entry.kind == "member").count();
        out.fact(file, "ar.directory", json!({"thin": directory.thin, "members": members, "symbol_indexes": indexes}));
        out.finding(
            Finding::new(Section::Structure, "ar", "ar.contents", Confidence::Verified, Severity::Info)
                .param("count", count)
                .evidence(Evidence::bytes(file, 0, bytes.len() as u64, json!({"thin": directory.thin, "member_count": count}))),
        );
        if !indexes.is_empty() {
            let mut finding =
                Finding::new(Section::Code, "ar", "ar.symbol-index", Confidence::Verified, Severity::Info).param("count", indexes.len());
            for member in directory.members.iter().filter(|entry| entry.kind == "symbol-index").take(8) {
                finding =
                    finding.evidence(Evidence::bytes(file, member.header as u64, 60, json!({"name": member.name, "size": member.size})));
            }
            out.finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;
    use std::io::Read;

    #[derive(Default)]
    struct Sink {
        files: Vec<(String, Vec<u8>)>,
        limitations: Vec<String>,
    }
    impl UnpackSink for Sink {
        fn add(&mut self, path: &str, data: &mut dyn Read) -> std::result::Result<(), SinkError> {
            let mut bytes = Vec::new();
            data.read_to_end(&mut bytes).expect("read fixture bytes");
            self.files.push((path.into(), bytes));
            Ok(())
        }
        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.into());
        }
    }
    fn artifact(bytes: &[u8]) -> Artifact {
        Artifact {
            path: "fixture.a".into(),
            parent: None,
            size: bytes.len() as u64,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: Some("ar".into()),
            facts: BTreeMap::new(),
        }
    }
    fn append(bytes: &mut Vec<u8>, name: &str, data: &[u8]) {
        bytes.extend(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, "644", data.len()).as_bytes());
        bytes.extend(data);
        if !data.len().is_multiple_of(2) {
            bytes.push(b'\n');
        }
    }

    #[test]
    fn gnu_long_names_offsets_and_index_refer_to_original_bytes() {
        let mut bytes = b"!<arch>\n".to_vec();
        let mut index = 1u32.to_be_bytes().to_vec();
        // Index offsets refer to member headers, including the special members before them.
        let names = b"a-long-object-file-name.o/\n";
        let target = 8 + 60 + 14 + 60 + names.len() + names.len() % 2;
        index.extend((target as u32).to_be_bytes());
        index.extend(b"entry\0");
        append(&mut bytes, "/", &index);
        append(&mut bytes, "//", names);
        append(&mut bytes, "/0", b"ELF");
        let parsed = parse(&bytes).expect("GNU archive");
        assert_eq!(parsed.members[2].name, "a-long-object-file-name.o");
        assert_eq!(parsed.members[2].header, target);
        let headers = parsed.members.iter().filter(|entry| entry.kind == "member").map(|entry| entry.header as u64).collect();
        assert_eq!(gnu_index(&bytes, &parsed.members[0], &headers, &mut (0, 0)).expect("index")["symbols"][0]["name"], "entry");
        let mut sink = Sink::default();
        assert_eq!(Ar.unpack(&artifact(&bytes), &bytes, &mut sink), Unpack::Done { kind: "ar" });
        assert_eq!(sink.files, [("a-long-object-file-name.o".into(), b"ELF".to_vec())]);
    }

    #[test]
    fn bsd_inline_name_padding_is_not_member_content() {
        let mut bytes = b"!<arch>\n".to_vec();
        let mut body = b"long bsd name.o\0\0".to_vec();
        let prefix = body.len();
        body.extend(b"object-bytes");
        append(&mut bytes, &format!("#1/{prefix}"), &body);
        let directory = parse(&bytes).expect("BSD archive");
        assert_eq!(directory.members[0].name, "long bsd name.o");
        assert_eq!(directory.members[0].size, 12);
        let mut sink = Sink::default();
        Ar.unpack(&artifact(&bytes), &bytes, &mut sink);
        assert_eq!(sink.files[0].1, b"object-bytes");
    }

    #[test]
    fn thin_references_never_request_external_bytes_even_for_absolute_paths() {
        let mut bytes = b"!<thin>\n".to_vec();
        append(&mut bytes, "//", b"/etc/passwd/\n../outside.o/\n");
        for name in ["/0", "/13:1234"] {
            bytes.extend(format!("{name:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n", 0, 0, 0, "644", 9999999999u64).as_bytes());
        }
        let directory = parse(&bytes).expect("thin archive");
        assert!(directory.thin);
        assert_eq!(directory.members[1].name, "/etc/passwd");
        assert_eq!(directory.members[2].external_header, Some(1234));
        assert!(directory.members[1].offset.is_none());
        let mut sink = Sink::default();
        assert_eq!(Ar.unpack(&artifact(&bytes), &bytes, &mut sink), Unpack::Done { kind: "ar" });
        assert!(sink.files.is_empty());
        assert_eq!(sink.limitations, ["ar.thin-reference"]);
    }

    #[test]
    fn malformed_names_sizes_alignment_and_short_prefixes_fail_before_extraction() {
        let mut valid = b"!<arch>\n".to_vec();
        append(&mut valid, "a.o/", b"abc");
        for length in 9..valid.len() {
            assert!(parse(&valid[..length]).is_err(), "prefix {length}");
        }
        let mut cases = Vec::new();
        let mut bad = valid.clone();
        bad[56..66].copy_from_slice(b"9999999999");
        cases.push(bad);
        let mut bad = valid.clone();
        *bad.last_mut().expect("padding byte") = 0;
        cases.push(bad);
        let mut bad = b"!<arch>\n".to_vec();
        append(&mut bad, "//", b"some-long-name.o/\n");
        append(&mut bad, "/1", b"body");
        cases.push(bad);
        let mut bad = b"!<arch>\n".to_vec();
        append(&mut bad, "#1/10", b"too-short");
        cases.push(bad);
        for bytes in cases {
            let mut sink = Sink::default();
            assert!(matches!(Ar.unpack(&artifact(&bytes), &bytes, &mut sink), Unpack::Failed { .. }));
            assert!(sink.files.is_empty());
        }
        assert!(parse(b"!<arch>\n").expect("empty archive").members.is_empty());
    }

    #[test]
    fn duplicate_member_names_remain_distinct_and_symbol_failure_does_not_hide_members() {
        let mut bytes = b"!<arch>\n".to_vec();
        append(&mut bytes, "/", &u32::MAX.to_be_bytes());
        append(&mut bytes, "a.o/", b"one");
        append(&mut bytes, "a.o/", b"two");
        let directory = parse(&bytes).expect("archive directory");
        let headers = directory.members.iter().filter(|entry| entry.kind == "member").map(|entry| entry.header as u64).collect();
        assert!(gnu_index(&bytes, &directory.members[0], &headers, &mut (0, 0)).is_err());
        let mut sink = Sink::default();
        Ar.unpack(&artifact(&bytes), &bytes, &mut sink);
        assert_eq!(sink.files, [("a.o".into(), b"one".to_vec()), ("a.o".into(), b"two".to_vec())]);
    }

    struct FixtureTree(Vec<Artifact>, Vec<u8>);
    impl Tree for FixtureTree {
        fn artifacts(&self) -> &[Artifact] {
            &self.0
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            assert_eq!(path, self.0[0].path, "the analyzer reads only its supplied archive");
            Ok(Bytes::from_vec(self.1.clone()))
        }
    }

    #[test]
    fn native_gnu_bsd_and_upstream_archive_members_match_independent_ar_and_nm() {
        let snapshot: Value = serde_json::from_str(include_str!("../tests/data/ar-native.ref.json")).expect("native reference JSON");
        for (filename, bytes) in [
            ("native-gnu.a", include_bytes!("../tests/data/native-gnu.a").as_slice()),
            ("native-bsd.a", include_bytes!("../tests/data/native-bsd.a").as_slice()),
            ("upstream-libxxhash-0.8.1.a", include_bytes!("../tests/data/upstream-libxxhash-0.8.1.a").as_slice()),
        ] {
            let record = snapshot["records"]
                .as_array()
                .expect("records")
                .iter()
                .find(|record| record["file"] == filename)
                .expect("fixture reference");
            assert_eq!(aa_core::sha256_hex(bytes), record["sha256"], "hash-bound native input {filename}");
            let tree = FixtureTree(vec![artifact(bytes)], bytes.to_vec());
            let mut output = Output::default();
            Ar.analyze_file(&tree, &tree.0[0], &mut output);
            let fact = output.facts.iter().find(|fact| fact.key == "ar.directory").expect("archive directory");
            let directory = &fact.value;
            let mut sink = Sink::default();
            assert_eq!(Ar.unpack(&tree.0[0], bytes, &mut sink), Unpack::Done { kind: "ar" });
            let expected = record["members"].as_array().expect("native members");
            assert_eq!(sink.files.len(), expected.len(), "{filename}");
            for ((name, body), native) in sink.files.iter().zip(expected) {
                assert_eq!(name, native["name"].as_str().expect("native member name"));
                assert_eq!(body.len() as u64, native["size"].as_u64().expect("native member size"));
                assert_eq!(aa_core::sha256_hex(body), native["sha256"], "{filename}/{name}");
            }
            if filename == "native-bsd.a" {
                assert!(output.limitations.iter().any(|limit| limit.code == "ar.symbol-index-unread"));
                assert!(directory["symbol_indexes"][0]["entries"].is_null());
            } else {
                assert!(output.limitations.is_empty(), "{filename}: {:?}", output.limitations);
                let mut symbols = Vec::new();
                for index in directory["symbol_indexes"].as_array().expect("indexes") {
                    for symbol in index["entries"]["symbols"].as_array().expect("symbols") {
                        let target = directory["members"]
                            .as_array()
                            .expect("members")
                            .iter()
                            .find(|entry| entry["header_offset"] == symbol["member_header_offset"])
                            .expect("indexed member");
                        symbols.push(json!({"name": symbol["name"], "member": target["name"]}));
                    }
                }
                assert_eq!(json!(symbols), record["symbol_map"], "native armap {filename}");
            }
            assert!(output.findings.iter().all(|finding| !finding.evidence.is_empty()));
        }
    }

    #[test]
    fn native_thin_archive_keeps_index_and_names_without_following_missing_objects() {
        let bytes = include_bytes!("../tests/data/native-thin.a");
        let directory = parse(bytes).expect("native thin archive");
        assert!(directory.thin);
        let references: Vec<_> = directory.members.iter().filter(|member| member.kind == "member").collect();
        assert_eq!(references.len(), 2);
        assert!(references.iter().all(|member| member.offset.is_none() && member.stored_size == 0));
        let mut sink = Sink::default();
        Ar.unpack(&artifact(bytes), bytes, &mut sink);
        assert!(sink.files.is_empty());
        assert_eq!(sink.limitations, ["ar.thin-reference"]);
        let tree = FixtureTree(vec![artifact(bytes)], bytes.to_vec());
        let mut output = Output::default();
        Ar.analyze_file(&tree, &tree.0[0], &mut output);
        assert!(output.limitations.is_empty(), "thin symbol index should refer to archive headers, not open objects");
        assert!(output.facts.iter().any(|fact| fact.value["thin"] == true));
    }

    #[test]
    fn symbol_budgets_are_shared_and_64_bit_offsets_are_checked() {
        let mut bytes = b"!<arch>\n".to_vec();
        let mut index = 1u64.to_be_bytes().to_vec();
        let target = 8 + 60 + 22;
        index.extend((target as u64).to_be_bytes());
        index.extend(b"entry\0");
        append(&mut bytes, "/SYM64/", &index);
        append(&mut bytes, "obj.o/", b"object");
        let directory = parse(&bytes).expect("64-bit GNU index");
        let headers = directory.members.iter().filter(|entry| entry.kind == "member").map(|entry| entry.header as u64).collect();
        let member = &directory.members[0];
        assert_eq!(gnu_index(&bytes, member, &headers, &mut (0, 0)).expect("GNU64 index")["word_bits"], 64);
        assert!(gnu_index(&bytes, member, &headers, &mut (MAX_METADATA, 0)).is_err());
        assert!(gnu_index(&bytes, member, &headers, &mut (0, MAX_ENTRIES)).is_err());
        let mut invalid = bytes.clone();
        invalid[member.offset.expect("stored index") + 8..member.offset.expect("stored index") + 16].fill(0xff);
        assert!(gnu_index(&invalid, member, &headers, &mut (0, 0)).is_err());
    }
}
