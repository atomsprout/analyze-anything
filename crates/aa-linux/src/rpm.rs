//! RPM header records and their declared CPIO payload; no librpm or installation hooks.

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::{MAX_ENTRIES, MAX_METADATA, Result, align, extent};

pub struct Rpm;

const RULES: &[Rule] = &[
    Rule {
        id: "rpm.identity",
        title_en: "Declared RPM package identity",
        title_zh: "RPM 包身份声明",
        text_en: "The RPM header declares {name}, version {version}, release {release}, architecture {architecture}. No installed state was queried.",
        text_zh: "RPM 头声明了包 {name}、版本 {version}、发行号 {release}、架构 {architecture}，没有查询安装状态。",
    },
    Rule {
        id: "rpm.dependencies",
        title_en: "RPM dependency declarations",
        title_zh: "RPM 依赖声明",
        text_en: "The RPM header contains {count} dependency and relationship tags. Names, version strings and flags are source declarations; repositories and host capabilities were not resolved.",
        text_zh: "RPM 头包含 {count} 个依赖与关系标签。名称、版本字符串与标志是源声明，没有解析仓库或本机能力。",
    },
    Rule {
        id: "rpm.install-scripts",
        title_en: "Declared RPM scripts",
        title_zh: "RPM 脚本声明",
        text_en: "The RPM header contains {count} script-body tags. Bodies and interpreter declarations are retained as data, without evaluation or execution.",
        text_zh: "RPM 头包含 {count} 个脚本正文标签。正文与解释器声明作为数据保留，没有求值或执行。",
    },
    Rule {
        id: "rpm.script-semantics",
        title_en: "RPM script behavior remains unresolved",
        title_zh: "RPM 脚本行为未确定",
        text_en: "Script and trigger declarations were retained. Runtime conditions, control flow and resulting system changes were not established.",
        text_zh: "保留了脚本与触发器声明，没有确定运行时条件、控制流或最终系统变化。",
    },
    Rule {
        id: "rpm.payload-unread",
        title_en: "RPM payload could not be read",
        title_zh: "RPM 载荷无法读取",
        text_en: "The payload declaration, compression or CPIO variant is outside the supported profile, or its bytes could not be retained.",
        text_zh: "载荷声明、压缩方式或 CPIO 变体不在支持范围内，或其字节无法保留。",
    },
    Rule {
        id: "rpm.header-unread",
        title_en: "RPM header could not be read",
        title_zh: "RPM 头无法读取",
        text_en: "The RPM header could not be retained within its checked ranges and metadata budget.",
        text_zh: "无法在已检查的范围与元数据预算内保留 RPM 头。",
    },
    Rule {
        id: "rpm.integrity-unverified",
        title_en: "RPM integrity and authenticity were not established",
        title_zh: "RPM 完整性与来源真实性未确定",
        text_en: "Signature and digest records are declarations only. OpenPGP signatures, header regions, payload digests and per-file integrity metadata were not verified.",
        text_zh: "签名与摘要记录仅作为声明。没有验证 OpenPGP 签名、头区域、载荷摘要或各文件完整性元数据。",
    },
    Rule {
        id: "rpm.metadata-scope",
        title_en: "RPM metadata semantics are only partially interpreted",
        title_zh: "RPM 元数据语义仅部分解读",
        text_en: "The report interprets selected identity, dependency, script and payload tags. Other index descriptors are retained without assigning their values installation semantics.",
        text_zh: "报告解读部分身份、依赖、脚本与载荷标签，保留其他索引描述符，不赋予其值安装语义。",
    },
];

#[derive(Clone)]
struct Tag {
    id: u32,
    kind: u32,
    offset: usize,
    count: u32,
    index: usize,
    value: Option<Value>,
}
struct Header {
    offset: usize,
    end: usize,
    tags: Vec<Tag>,
}
struct Package {
    signature: Header,
    header: Header,
}

fn be(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(extent(bytes, at, 4)?.try_into().map_err(|_| "short RPM integer")?))
}

fn selected(tag: u32) -> bool {
    matches!(tag, 1000..=1005 | 1014 | 1020..=1026 | 1047..=1050 | 1053..=1055 | 1065..=1069 | 1079 | 1085..=1088 |
        1090..=1092 | 1112..=1115 | 1124..=1126 | 1151..=1154 | 5020..=5025 | 5063..=5089 | 5103..=5108 | 5114)
}

fn script(tag: u32) -> bool {
    matches!(tag, 1023..=1026 | 1065 | 1079 | 1151 | 1152 | 5066 | 5076 | 5103 | 5104)
}
fn dependency(tag: u32) -> bool {
    matches!(tag, 1047..=1050 | 1053..=1055 | 1090 | 1112..=1115)
}

fn expected_type(tag: u32) -> Option<u32> {
    match tag {
        1000..=1002 | 1014 | 1020..=1026 | 1079 | 1124..=1126 | 1151 | 1152 | 5103 | 5104 => Some(6),
        1003 | 1048 | 1053 | 1112 | 1114 | 5114 => Some(4),
        1047 | 1049 | 1050 | 1054 | 1055 | 1065..=1067 | 1090 | 1113 | 1115 | 5066 | 5076 => Some(8),
        _ => None,
    }
}

fn interpreter(tag: u32) -> bool {
    matches!(tag, 1085..=1088 | 1091 | 1092 | 1153 | 1154 | 5067 | 5077 | 5105 | 5106)
}

fn header(bytes: &[u8], offset: usize, retain: bool) -> Result<Header> {
    if extent(bytes, offset, 8)? != b"\x8e\xad\xe8\x01\0\0\0\0" {
        return Err("unsupported RPM header magic or version".into());
    }
    let count = be(bytes, offset + 8)? as usize;
    let size = be(bytes, offset + 12)? as usize;
    if count > MAX_ENTRIES || size > MAX_METADATA {
        return Err("RPM index or data-store budget exhausted".into());
    }
    let table_size = count.checked_mul(16).ok_or("RPM index length overflow")?;
    let table = offset.checked_add(16).ok_or("RPM index offset overflow")?;
    extent(bytes, table, table_size)?;
    let start = table.checked_add(table_size).ok_or("RPM data offset overflow")?;
    let data = extent(bytes, start, size)?;
    let mut tags: Vec<Tag> = Vec::new();
    let mut scanned = 0usize;
    let mut values_seen = 0usize;
    for ordinal in 0..count {
        let index = table + ordinal * 16;
        let id = be(bytes, index)?;
        let kind = be(bytes, index + 4)?;
        let relative = be(bytes, index + 8)? as usize;
        let count = be(bytes, index + 12)?;
        if tags.last().is_some_and(|tag| tag.id >= id) {
            return Err("RPM tags are repeated or not strictly ordered".into());
        }
        if relative > i32::MAX as usize || relative > data.len() {
            return Err("RPM tag offset exceeds data store".into());
        }
        let wanted = retain && selected(id);
        if retain && (expected_type(id).is_some_and(|expected| kind != expected) || interpreter(id) && !matches!(kind, 6 | 8)) {
            return Err(format!("RPM tag {id} has a type inconsistent with the supported declaration profile"));
        }
        if wanted || matches!(kind, 6 | 8 | 9) {
            values_seen = values_seen.checked_add(count as usize).ok_or("RPM value count overflow")?;
            if values_seen > MAX_ENTRIES {
                return Err("RPM decoded-value budget exhausted".into());
            }
        }
        let value = match kind {
            1..=5 | 7 => {
                let width = match kind {
                    3 => 2,
                    4 => 4,
                    5 => 8,
                    _ => 1,
                };
                if kind != 7 && !relative.is_multiple_of(width) {
                    return Err("misaligned RPM integer tag".into());
                }
                let length = (count as usize).checked_mul(width).ok_or("RPM tag count overflow")?;
                let raw = extent(data, relative, length)?;
                if wanted {
                    scanned = scanned.checked_add(length).ok_or("RPM metadata size overflow")?;
                    if scanned > MAX_METADATA || count as usize > MAX_ENTRIES {
                        return Err("RPM selected values exceed the metadata budget".into());
                    }
                    let values: Vec<_> = raw
                        .chunks_exact(width)
                        .map(|chunk| {
                            let value = chunk.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
                            json!(value)
                        })
                        .collect();
                    Some(json!(values))
                } else {
                    None
                }
            }
            6 | 8 | 9 => {
                if kind == 6 && count != 1 || count as usize > MAX_ENTRIES {
                    return Err("invalid RPM string count".into());
                }
                let mut at = relative;
                let mut values = Vec::new();
                for _ in 0..count {
                    let available = MAX_METADATA.saturating_sub(scanned);
                    let remaining = extent(data, at, data.len() - at)?;
                    let scan = &remaining[..remaining.len().min(available)];
                    let length =
                        scan.iter().position(|byte| *byte == 0).ok_or("unterminated RPM string or metadata scan budget exhausted")?;
                    scanned += length + 1;
                    if wanted {
                        let text = std::str::from_utf8(&scan[..length]).map_err(|_| "selected RPM text is not UTF-8")?;
                        let value = aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?;
                        values.push(json!(value));
                    }
                    at += length + 1;
                }
                if wanted {
                    Some(if kind == 6 { values.into_iter().next().ok_or("missing RPM string")? } else { json!(values) })
                } else {
                    None
                }
            }
            _ => return Err(format!("unsupported RPM tag data type {kind}")),
        };
        tags.push(Tag { id, kind, offset: start + relative, count, index, value });
    }
    Ok(Header { offset, end: start + size, tags })
}

fn parse(bytes: &[u8]) -> Result<Package> {
    let lead = extent(bytes, 0, 96)?;
    if &lead[..4] != b"\xed\xab\xee\xdb" || lead[4..6] != [3, 0] || lead[6] != 0 || lead[7] > 1 || lead[78..80] != [0, 5] {
        return Err("only RPM 3.0 leads with header-style signatures and source/binary package types are supported".into());
    }
    let signature = header(bytes, 96, false)?;
    let next = align(signature.end, 8)?;
    if extent(bytes, signature.end, next - signature.end)?.iter().any(|byte| *byte != 0) {
        return Err("nonzero RPM signature padding".into());
    }
    let header = header(bytes, next, true)?;
    Ok(Package { signature, header })
}

fn value(header: &Header, id: u32) -> Value {
    header.tags.iter().find(|tag| tag.id == id).and_then(|tag| tag.value.clone()).unwrap_or(Value::Null)
}

fn payload<'a>(package: &Package, bytes: &'a [u8]) -> Result<(&'static str, &'a [u8])> {
    let version = value(&package.header, 5114);
    if !version.is_null() && version != json!([4]) {
        return Err("RPM formats other than v4 are outside the payload profile".into());
    }
    if value(&package.header, 1124) != "cpio" {
        return Err("RPM payload format is not an explicit CPIO declaration".into());
    }
    let data = &bytes[package.header.end..];
    let compressor = value(&package.header, 1125);
    let (name, agrees) = match compressor.as_str() {
        Some("gzip") => ("[payload].cpio.gz", data.starts_with(b"\x1f\x8b\x08")),
        Some("bzip2") => ("[payload].cpio.bz2", data.starts_with(b"BZh")),
        Some("xz") => ("[payload].cpio.xz", data.starts_with(b"\xfd7zXZ\0")),
        Some("zstd") => ("[payload].cpio.zst", data.starts_with(b"\x28\xb5\x2f\xfd")),
        Some("none") => ("[payload].cpio", data.starts_with(b"070701") || data.starts_with(b"070702")),
        _ => return Err("RPM payload compressor is missing or unsupported".into()),
    };
    if !agrees {
        return Err("RPM payload bytes do not match the declared supported compression profile".into());
    }
    Ok((name, data))
}

impl Unpacker for Rpm {
    fn id(&self) -> &'static str {
        "rpm"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(b"\xed\xab\xee\xdb") {
            return Unpack::NotMine;
        }
        let package = match parse(bytes) {
            Ok(value) => value,
            Err(detail) => return Unpack::Failed { kind: "rpm", detail },
        };
        match payload(&package, bytes) {
            Ok((name, mut data)) => match sink.add(name, &mut data) {
                Ok(()) | Err(SinkError::LimitReached) => {}
                Err(SinkError::Read(detail)) => sink.limitation("rpm.payload-unread", Some(detail)),
            },
            Err(detail) => sink.limitation("rpm.payload-unread", Some(detail)),
        }
        Unpack::Done { kind: "rpm" }
    }
}

fn records(header: &Header) -> Vec<Value> {
    header
        .tags
        .iter()
        .map(|tag| {
            json!({"tag": tag.id, "type": tag.kind, "offset": tag.offset, "count": tag.count,
        "index_offset": tag.index, "value": tag.value})
        })
        .collect()
}

impl Analyzer for Rpm {
    fn id(&self) -> &'static str {
        "rpm"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("rpm") {
            return;
        }
        let result = tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| parse(&bytes));
        let package = match result {
            Ok(value) => value,
            Err(detail) => {
                out.limitation("rpm.header-unread", Some(file), Some(detail));
                return;
            }
        };
        let header = &package.header;
        let name = value(header, 1000);
        let version = value(header, 1001);
        let release = value(header, 1002);
        let arch = value(header, 1022);
        out.fact(file, "rpm.package", json!({"name": name, "version": version, "release": release, "architecture": arch,
            "header_offset": header.offset, "payload_offset": header.end, "tags": records(header), "signature_tags": records(&package.signature)}));
        if [&name, &version, &release, &arch].iter().all(|value| value.as_str().is_some_and(|text| !text.is_empty())) {
            out.finding(
                Finding::new(Section::Identity, "rpm", "rpm.identity", Confidence::Verified, Severity::Info)
                    .param("name", name.clone())
                    .param("version", version.clone())
                    .param("release", release.clone())
                    .param("architecture", arch.clone())
                    .evidence(Evidence::bytes(
                        file,
                        header.offset as u64,
                        (header.end - header.offset) as u64,
                        json!({"name": name, "version": version, "release": release, "architecture": arch}),
                    )),
            );
        } else {
            out.limitation("rpm.header-unread", Some(file), Some("missing or incorrectly typed package identity tags".into()));
        }
        for (rule, section, predicate) in [
            ("rpm.dependencies", Section::Composition, dependency as fn(u32) -> bool),
            ("rpm.install-scripts", Section::Capabilities, script as fn(u32) -> bool),
        ] {
            let tags: Vec<_> =
                records(header).into_iter().filter(|tag| tag["tag"].as_u64().is_some_and(|id| predicate(id as u32))).collect();
            if !tags.is_empty() {
                out.finding(
                    Finding::new(section, "rpm", rule, Confidence::Verified, Severity::Info)
                        .param("count", tags.len())
                        .evidence(Evidence::bytes(file, header.offset as u64, (header.end - header.offset) as u64, json!(tags))),
                );
                if rule == "rpm.install-scripts" {
                    out.limitation("rpm.script-semantics", Some(file), None);
                }
            }
        }
        out.limitation("rpm.integrity-unverified", Some(file), None);
        out.limitation("rpm.metadata-scope", Some(file), None);
    }
}
