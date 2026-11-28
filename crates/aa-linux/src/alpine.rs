//! Alpine APK v2 gzip/TAR layers. Android ZIP APKs are a different format.

use std::collections::BTreeSet;
use std::io::Read;

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::text::{redact_named_value, redact_sensitive_text};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub struct Alpine;

const MAX_COMPRESSED: usize = 256 * 1024 * 1024;
const MAX_CONTROL: usize = 1024 * 1024;
const MAX_PAYLOAD: usize = 128 * 1024 * 1024;
const MAX_TOTAL: usize = MAX_PAYLOAD + 8 * MAX_CONTROL;
const MAX_ENTRIES: usize = 100_000;
const MAX_NAMES: usize = 16 * 1024 * 1024;
const MAX_PAX: usize = 1024 * 1024;
const MAX_FIELDS: usize = 4096;
const MAX_ARTIFACT_PATH: usize = 8192;
const MAX_OFFERED_PATHS: usize = 32 * 1024 * 1024;
const MAX_SERIALIZED_OUTPUT: usize = 16 * 1024 * 1024;
// Source paths recur in the fixed number of facts, evidence records and limits.
// Reserve their worst-case JSON escaping separately from variable previews.
const FIXED_OUTPUT_RESERVE: usize = 4 * 1024 * 1024;
const CONTROL: &str = "[control]";
const PAYLOAD: &str = "[payload]";
const SCRIPTS: &[&str] =
    &[".pre-install", ".post-install", ".pre-upgrade", ".post-upgrade", ".pre-deinstall", ".post-deinstall", ".trigger"];
type Result<T> = std::result::Result<T, &'static str>;

const RULES: &[Rule] = &[
    Rule {
        id: "alpine-apk.output-limited",
        title_en: "Alpine declaration preview was limited",
        title_zh: "Alpine 声明预览已限制",
        text_en: "Some captured-entry records, metadata fields or script text were omitted to bound output. Total and retained counts are separate; omitted previews are not absent contents.",
        text_zh: "为限制输出，省略了部分已捕获条目记录、元数据字段或脚本文本。分别记录总数与保留数；省略预览不代表内容不存在。",
    },
    Rule {
        id: "alpine-apk.contents",
        title_en: "Alpine APK v2 layers",
        title_zh: "Alpine APK v2 分层",
        text_en: "The package contains {count} checked gzip members with separate signature, control and payload roles. Gzip CRC/size trailers were checked; input bytes were not installed or executed.",
        text_zh: "包包含 {count} 个已检查的 gzip 成员，分别保留签名、控制和载荷角色。已检查 gzip CRC 和大小尾部，没有安装或执行输入。",
    },
    Rule {
        id: "alpine-apk.identity",
        title_en: "Declared Alpine package identity",
        title_zh: "Alpine 包身份声明",
        text_en: "The control layer's .PKGINFO declares {name}, version {version}, architecture {architecture}. Payload files cannot supply this control identity.",
        text_zh: "控制层的 .PKGINFO 声明了 {name}、版本 {version}、架构 {architecture}。载荷中的文件不能提供此控制身份。",
    },
    Rule {
        id: "alpine-apk.dependencies",
        title_en: "Alpine package relationship declarations",
        title_zh: "Alpine 包关系声明",
        text_en: "The control metadata contains {count} dependency, provider, replacement or trigger declarations. They remain literal; no repository or host dependency resolution was performed.",
        text_zh: "控制元数据包含 {count} 个依赖、提供者、替换或触发器声明。按字面保留，没有查询仓库或解析本机依赖。",
    },
    Rule {
        id: "alpine-apk.script",
        title_en: "Declared Alpine installation script",
        title_zh: "Alpine 安装脚本声明",
        text_en: "The control layer contains {name}. Its bounded redacted source is evidence; it was not run or evaluated.",
        text_zh: "控制层包含 {name}，将有界且已脱敏的源文作为证据，没有运行或求值。",
    },
    Rule {
        id: "alpine-apk.unread",
        title_en: "Alpine package profile could not be read",
        title_zh: "Alpine 包支持范围无法读取",
        text_en: "The candidate is malformed, exceeds a bound or uses an unsupported Alpine container, compression, TAR or control profile. Unread contents are not silently treated as absent.",
        text_zh: "候选文件损坏、超出限制，或使用不受支持的 Alpine 容器、压缩、TAR 或控制格式。未读取的内容不会被默认为不存在。",
    },
    Rule {
        id: "alpine-apk.integrity-unverified",
        title_en: "Alpine package authenticity was not established",
        title_zh: "Alpine 包来源真实性未确定",
        text_en: "Signature filenames and checksum declarations were retained, but signatures, datahash and APK-TOOLS member hashes were not verified. No key was loaded, and no authenticity verdict is made.",
        text_zh: "保留了签名文件名和摘要声明，但没有验证签名、datahash 或 APK-TOOLS 成员摘要。没有加载密钥，也不作来源真实性结论。",
    },
    Rule {
        id: "alpine-apk.archive-semantics",
        title_en: "Alpine archive link or special-file semantics remain unresolved",
        title_zh: "Alpine 归档链接或特殊文件语义未确定",
        text_en: "Link and special-file declarations were retained as metadata. No host link, device or installation effect was materialized.",
        text_zh: "将链接和特殊文件声明作为元数据保留，没有在本机创建链接、设备或产生安装效果。",
    },
    Rule {
        id: "alpine-apk.script-semantics",
        title_en: "Alpine script and trigger behavior remains unresolved",
        title_zh: "Alpine 脚本及触发器行为未确定",
        text_en: "Script text and trigger fields remain declarations. Activation, shell control flow, runtime values and resulting changes were not established.",
        text_zh: "脚本文本和触发器字段均为声明，没有确定激活、Shell 控制流、运行时值或最终变化。",
    },
    Rule {
        id: "alpine-apk.control-partial",
        title_en: "Some Alpine control declarations remain uninterpreted",
        title_zh: "部分 Alpine 控制声明未解释",
        text_en: "Unknown fields or control files were retained as data. Their additional metadata or installation semantics were not interpreted.",
        text_zh: "将未知字段或控制文件作为数据保留，没有解释其附加元数据或安装语义。",
    },
];

#[derive(Debug)]
struct Entry {
    path: String,
    logical: Option<String>,
    header: usize,
    offset: usize,
    size: usize,
    kind: u8,
    mode: u64,
    uid: u64,
    gid: u64,
    link: Option<String>,
    pax: Vec<Pax>,
}
#[derive(Debug)]
struct Pax {
    name: String,
    value: String,
    offset: usize,
    length: usize,
}
#[derive(Debug)]
struct Layer {
    role: &'static str,
    prefix: String,
    offset: usize,
    length: usize,
    bytes: Vec<u8>,
    entries: Vec<Entry>,
    trailer: bool,
}
#[derive(Debug)]
struct Package {
    layers: Vec<Layer>,
    control: usize,
    payload: usize,
}

fn extent(bytes: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    bytes.get(at..at.checked_add(size).ok_or("Alpine range overflow")?).ok_or("Alpine range exceeds captured bytes")
}
fn octal(bytes: &[u8]) -> Result<u64> {
    if bytes.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err("TAR base-256 integers are outside this profile");
    }
    let bytes = bytes.trim_ascii();
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes).trim_ascii();
    let mut value = 0u64;
    let mut ended = false;
    for byte in bytes.iter().copied() {
        if matches!(byte, 0 | b' ') {
            ended = true;
            continue;
        }
        if ended || !(b'0'..=b'7').contains(&byte) {
            return Err("invalid TAR octal integer");
        }
        value = value.checked_mul(8).and_then(|value| value.checked_add(u64::from(byte - b'0'))).ok_or("TAR integer overflow")?;
    }
    Ok(value)
}
fn text(bytes: &[u8]) -> Result<String> {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..end]).map(str::to_string).map_err(|_| "TAR names are outside the UTF-8 profile")
}
fn logical(path: &str) -> Option<String> {
    let mut path = path;
    while let Some(tail) = path.strip_prefix("./") {
        path = tail;
    }
    let path = path.trim_end_matches('/');
    if path.is_empty()
        || path.len() > 4096
        || path.contains(['\\', '\0', ':'])
        || path.split('/').any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
    {
        return None;
    }
    Some(path.into())
}

fn pax(bytes: &[u8], base: usize) -> Result<Vec<Pax>> {
    let mut at = 0usize;
    let mut fields = Vec::new();
    let mut seen = BTreeSet::new();
    while at < bytes.len() {
        let tail = &bytes[at..];
        let space = tail.iter().position(|byte| *byte == b' ').ok_or("PAX record has no length separator")?;
        if space == 0 || space > 12 || !tail[..space].iter().all(u8::is_ascii_digit) {
            return Err("invalid PAX record length");
        }
        let length =
            std::str::from_utf8(&tail[..space]).map_err(|_| "invalid PAX length")?.parse::<usize>().map_err(|_| "PAX length overflow")?;
        if length <= space + 2 || length > 16 * 1024 {
            return Err("PAX record exceeds the 16 KiB profile");
        }
        let record = extent(bytes, at, length)?;
        if record.last() != Some(&b'\n') {
            return Err("PAX record has no newline terminator");
        }
        let data = std::str::from_utf8(&record[space + 1..length - 1]).map_err(|_| "PAX value is not UTF-8")?;
        let (name, value) = data.split_once('=').ok_or("PAX record has no key/value separator")?;
        if name.is_empty() || name.len() > 256 || !seen.insert(name.to_string()) {
            return Err("duplicate or invalid PAX key");
        }
        if name == "size" || name.starts_with("GNU.sparse") {
            return Err("PAX size overrides and sparse files are outside this profile");
        }
        fields.push(Pax { name: name.into(), value: value.into(), offset: base + at, length });
        at += length;
    }
    Ok(fields)
}

fn tar(bytes: &[u8]) -> Result<(Vec<Entry>, bool)> {
    if !bytes.len().is_multiple_of(512) {
        return Err("TAR layer ends inside a 512-byte record");
    }
    let mut entries = Vec::new();
    let mut at = 0usize;
    let mut names = 0usize;
    let mut pax_bytes = 0usize;
    let mut pending: Vec<Pax> = Vec::new();
    let mut headers = 0usize;
    while at < bytes.len() {
        let header = extent(bytes, at, 512)?;
        if header.iter().all(|byte| *byte == 0) {
            if bytes.len() - at < 1024 || bytes[at..].iter().any(|byte| *byte != 0) || !pending.is_empty() {
                return Err("incomplete TAR trailer or unread data after its terminator");
            }
            return Ok((entries, true));
        }
        headers += 1;
        if headers > 2 * MAX_ENTRIES || entries.len() == MAX_ENTRIES {
            return Err("TAR header or entry count budget exhausted");
        }
        if &header[257..262] != b"ustar" {
            return Err("only USTAR/GNU headers with local PAX records are supported");
        }
        let expected = octal(&header[148..156])?;
        let actual =
            header.iter().enumerate().map(|(index, byte)| if (148..156).contains(&index) { 32 } else { u64::from(*byte) }).sum::<u64>();
        if expected != actual {
            return Err("TAR header checksum mismatch");
        }
        let size = usize::try_from(octal(&header[124..136])?).map_err(|_| "TAR size exceeds the address space")?;
        let offset = at.checked_add(512).ok_or("TAR data offset overflow")?;
        let data = extent(bytes, offset, size)?;
        let padded = size.checked_add(511).ok_or("TAR padding overflow")? / 512 * 512;
        let next = offset.checked_add(padded).ok_or("TAR entry extent overflow")?;
        extent(bytes, offset, padded)?;
        let kind = header[156];
        if kind == b'x' {
            pax_bytes = pax_bytes.checked_add(size).ok_or("PAX metadata overflow")?;
            if size > 64 * 1024 || pax_bytes > MAX_PAX || !pending.is_empty() {
                return Err("local PAX metadata budget or consecutive-header profile exceeded");
            }
            pending = pax(data, offset)?;
            at = next;
            continue;
        }
        if matches!(kind, b'g' | b'L' | b'K' | b'S') {
            return Err("global PAX, GNU long names and sparse TAR profiles are unsupported");
        }
        let raw_name = text(&header[..100])?;
        // apk-tools applies this prefix even with GNU magic. Using generic GNU
        // header semantics here would misidentify a prefixed control filename.
        let prefix = text(&header[345..500])?;
        let mut path = if prefix.is_empty() { raw_name } else { format!("{prefix}/{raw_name}") };
        let mut link = if matches!(kind, b'1' | b'2') { Some(text(&header[157..257])?) } else { None };
        for field in &pending {
            if field.name == "path" {
                path = field.value.clone();
            }
            if field.name == "linkpath" {
                link = Some(field.value.clone());
            }
        }
        names = names
            .checked_add(path.len())
            .and_then(|count| count.checked_add(link.as_ref().map_or(0, String::len)))
            .ok_or("TAR name budget overflow")?;
        if path.len() > 4096 || link.as_ref().is_some_and(|value| value.len() > 4096) || names > MAX_NAMES {
            return Err("TAR name byte budget exhausted");
        }
        entries.push(Entry {
            logical: logical(&path),
            path,
            header: at,
            offset,
            size,
            kind,
            mode: octal(&header[100..108])?,
            uid: octal(&header[108..116])?,
            gid: octal(&header[116..124])?,
            link,
            pax: std::mem::take(&mut pending),
        });
        at = next;
    }
    if !pending.is_empty() {
        return Err("PAX header has no following member");
    }
    Ok((entries, false))
}

fn gzip_header(bytes: &[u8]) -> Result<()> {
    let header = extent(bytes, 0, 10)?;
    if header[..3] != [0x1f, 0x8b, 8] || header[3] & 0xe0 != 0 {
        return Err("unsupported gzip header or reserved flags");
    }
    let mut at = 10usize;
    if header[3] & 4 != 0 {
        let raw = extent(bytes, at, 2)?;
        let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
        at += 2;
        if length > 4096 {
            return Err("gzip extra header exceeds the 4 KiB profile");
        }
        extent(bytes, at, length)?;
        at += length;
    }
    for flag in [8, 16] {
        if header[3] & flag != 0 {
            let tail = extent(bytes, at, bytes.len() - at)?;
            let length = tail.iter().take(4097).position(|byte| *byte == 0).ok_or("gzip name or comment exceeds the 4 KiB profile")?;
            at += length + 1;
        }
    }
    if header[3] & 2 != 0 {
        extent(bytes, at, 2)?;
    }
    Ok(())
}

fn gzip(bytes: &[u8], maximum: usize) -> Result<(Vec<u8>, usize)> {
    gzip_header(bytes)?;
    let mut reader = flate2::bufread::GzDecoder::new(bytes);
    let mut decoded = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| "gzip data, CRC or size trailer is invalid")?;
        if count == 0 {
            break;
        }
        if decoded.len().checked_add(count).is_none_or(|length| length > maximum) {
            return Err("gzip decoded-byte budget exhausted");
        }
        decoded.extend_from_slice(&buffer[..count]);
    }
    let consumed = bytes.len() - reader.into_inner().len();
    if consumed < 18 {
        return Err("gzip member has no complete header/trailer");
    }
    Ok((decoded, consumed))
}

fn signature(entry: &Entry) -> bool {
    entry.path.starts_with(".SIGN.") && !entry.path.contains('/') && entry.kind == b'0'
}
fn parse(bytes: &[u8]) -> Result<Package> {
    if bytes.len() > MAX_COMPRESSED {
        return Err("Alpine package exceeds the 256 MiB compressed-byte profile");
    }
    let mut layers = Vec::new();
    let mut at = 0usize;
    let mut decoded = 0usize;
    let mut control = None;
    let mut payload = None;
    while at < bytes.len() {
        if layers.len() == 8 || payload.is_some() {
            return Err("too many gzip members or bytes after the Alpine payload layer");
        }
        let maximum = if control.is_some() { MAX_PAYLOAD } else { MAX_CONTROL };
        let (data, length) = gzip(&bytes[at..], maximum.min(MAX_TOTAL - decoded))?;
        decoded += data.len();
        let (entries, trailer) = tar(&data)?;
        let (role, prefix) = if control.is_none() && !entries.is_empty() && entries.iter().all(signature) {
            if trailer {
                return Err("signature TAR must omit its zero trailer in the supported APK v2 profile");
            }
            if entries.len() > 32 {
                return Err("signature declaration count budget exhausted");
            }
            ("signature", format!("[signature-{}]", layers.len() + 1))
        } else if control.is_none() {
            if trailer {
                return Err("control TAR must omit its zero trailer in the supported APK v2 profile");
            }
            let controls: Vec<_> = entries.iter().filter(|entry| entry.path == ".PKGINFO").collect();
            let mut names = BTreeSet::new();
            if controls.len() != 1
                || controls[0].kind != b'0'
                || entries.first().map(|entry| entry.path.as_str()) != Some(".PKGINFO")
                || entries.iter().any(|entry| {
                    !entry.path.starts_with('.')
                        || entry.path.contains('/')
                        || !names.insert(entry.path.as_str())
                        || entry.logical.as_deref() != Some(entry.path.as_str())
                        || entry.kind != b'0'
                })
            {
                return Err("one first regular root .PKGINFO is required in the control-only layer");
            }
            control = Some(layers.len());
            ("control", CONTROL.into())
        } else {
            if !trailer {
                return Err("payload TAR requires a complete zero trailer");
            }
            payload = Some(layers.len());
            ("payload", PAYLOAD.into())
        };
        layers.push(Layer { role, prefix, offset: at, length, bytes: data, entries, trailer });
        at += length;
    }
    let control = control.ok_or("missing Alpine control layer")?;
    let payload = payload.ok_or("missing Alpine payload layer")?;
    Ok(Package { layers, control, payload })
}

impl Unpacker for Alpine {
    fn id(&self) -> &'static str {
        "alpine-apk"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let named = file.extension().as_deref() == Some("apk");
        if bytes.starts_with(b"ADB.") || bytes.starts_with(b"ADBc") || bytes.starts_with(b"ADBd") {
            return Unpack::Failed {
                kind: "alpine-apk",
                detail: "Alpine ADB/v3 containers are outside the supported APK v2 profile".into(),
            };
        }
        if !bytes.starts_with(&[0x1f, 0x8b, 8]) {
            return Unpack::NotMine;
        }
        let package = match parse(bytes) {
            Ok(package) => package,
            Err(detail) => return if named { Unpack::Failed { kind: "alpine-apk", detail: detail.into() } } else { Unpack::NotMine },
        };
        if file.path.len() > MAX_ARTIFACT_PATH {
            return Unpack::Failed { kind: "alpine-apk", detail: "source artifact path exceeds the 8192-byte Alpine profile".into() };
        }
        let mut offered_paths = 0usize;
        let mut invalid_names = 0usize;
        for layer in &package.layers {
            for entry in &layer.entries {
                if !matches!(entry.kind, 0 | b'0') {
                    continue;
                }
                let Some(name) = &entry.logical else {
                    invalid_names += 1;
                    continue;
                };
                let full_length = file.path.len().saturating_add(layer.prefix.len()).saturating_add(name.len()).saturating_add(2);
                if full_length > MAX_ARTIFACT_PATH || offered_paths.saturating_add(full_length) > MAX_OFFERED_PATHS {
                    sink.limitation(
                        "alpine-apk.output-limited",
                        Some("full captured path or aggregate offered-path budget exhausted".into()),
                    );
                    return Unpack::Done { kind: "alpine-apk" };
                }
                offered_paths += full_length;
                let path = format!("{}/{name}", layer.prefix);
                match sink.add(&path, &mut &layer.bytes[entry.offset..entry.offset + entry.size]) {
                    Ok(()) => {}
                    Err(SinkError::LimitReached) => return Unpack::Done { kind: "alpine-apk" },
                    Err(SinkError::Read(detail)) => {
                        sink.limitation("alpine-apk.unread", Some(detail));
                        return Unpack::Done { kind: "alpine-apk" };
                    }
                }
            }
        }
        if invalid_names != 0 {
            sink.limitation(
                "alpine-apk.archive-semantics",
                Some(format!("{invalid_names} unsupported logical entry names were not offered")),
            );
        }
        Unpack::Done { kind: "alpine-apk" }
    }
}

#[derive(Debug)]
struct Field {
    name: String,
    value: String,
    line: usize,
    offset: usize,
    length: usize,
}
fn fields(bytes: &[u8]) -> Result<Vec<Field>> {
    if bytes.len() > MAX_CONTROL {
        return Err("Alpine .PKGINFO exceeds the 1 MiB control budget");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Alpine .PKGINFO is not UTF-8")?;
    if text.contains('\0') {
        return Err("Alpine .PKGINFO contains NUL");
    }
    let mut fields = Vec::new();
    let mut scalar = BTreeSet::new();
    let mut offset = 0usize;
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        if raw.len() > 16 * 1024 || fields.len() == MAX_FIELDS {
            return Err("Alpine .PKGINFO line or field budget exhausted");
        }
        let line = raw.trim_end_matches(['\r', '\n']);
        if !line.is_empty() && !line.starts_with('#') {
            let (name, value) = line.split_once(" = ").ok_or("unsupported Alpine key = value declaration")?;
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err("unsupported Alpine metadata key");
            }
            if !matches!(name, "depend" | "provides" | "replaces" | "install_if" | "triggers") && !scalar.insert(name.to_string()) {
                return Err("duplicate Alpine scalar metadata field");
            }
            fields.push(Field { name: name.into(), value: redact_named_value(name, value)?, line: index + 1, offset, length: raw.len() });
        }
        offset += raw.len();
    }
    Ok(fields)
}
fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|name| name["normalized"] != true && name["colliding"] != true)
}
fn child<'a>(tree: &'a dyn Tree, file: &Artifact, layer: &Layer, entry: &Entry) -> Option<&'a Artifact> {
    let name = entry.logical.as_deref()?;
    if file.path.len().saturating_add(layer.prefix.len()).saturating_add(name.len()).saturating_add(2) > MAX_ARTIFACT_PATH {
        return None;
    }
    let path = format!("{}/{}/{name}", file.path, layer.prefix);
    tree.get(&path).filter(|child| {
        child.parent.as_deref() == Some(file.path.as_str())
            && original(child)
            && child.size == entry.size as u64
            && child
                .digests
                .as_ref()
                .is_some_and(|digest| digest.sha256 == aa_core::sha256_hex(&layer.bytes[entry.offset..entry.offset + entry.size]))
    })
}

struct OutputBudget {
    remaining: usize,
    limited: bool,
    reported: bool,
}
impl OutputBudget {
    fn new() -> Self {
        Self { remaining: MAX_SERIALIZED_OUTPUT - FIXED_OUTPUT_RESERVE, limited: false, reported: false }
    }
    fn take(&mut self, value: &Value, copies: usize, reserve: usize) -> bool {
        let size = serde_json::to_vec(value).ok().and_then(|bytes| bytes.len().checked_mul(copies));
        if let Some(size) = size.filter(|size| *size <= self.remaining.saturating_sub(reserve)) {
            self.remaining -= size;
            true
        } else {
            self.limited = true;
            false
        }
    }
    fn report(&mut self, file: &Artifact, out: &mut Output) {
        if self.limited && !self.reported {
            out.limitation(
                "alpine-apk.output-limited",
                Some(file),
                Some("serialized declaration previews exceed the shared 16 MiB output profile".into()),
            );
            self.reported = true;
        }
    }
}

impl Analyzer for Alpine {
    fn id(&self) -> &'static str {
        "alpine-apk"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("alpine-apk") {
            return;
        }
        if file.path.len() > MAX_ARTIFACT_PATH {
            out.limitation("alpine-apk.output-limited", Some(file), Some("source artifact path exceeds the 8192-byte profile".into()));
            return;
        }
        let parsed = tree.read(&file.path).map_err(|_| "Alpine bytes unavailable").and_then(|bytes| parse(&bytes));
        let package = match parsed {
            Ok(package) => package,
            Err(detail) => {
                out.limitation("alpine-apk.unread", Some(file), Some(detail.into()));
                return;
            }
        };
        let mut layers = Vec::new();
        let mut link_semantics = false;
        let mut budget = OutputBudget::new();
        let mut omitted_entries = 0usize;
        for layer in &package.layers {
            link_semantics |= layer.entries.iter().any(|entry| !matches!(entry.kind, 0 | b'0' | b'5') || entry.logical.is_none());
            let mut entries = Vec::new();
            for entry in &layer.entries {
                let pax=entry.pax.iter().map(|field|Ok(json!({"name":field.name,"value":redact_named_value(&field.name,&field.value)?,"offset":field.offset,"length":field.length}))).collect::<Result<Vec<_>>>();
                let pax = match pax {
                    Ok(pax) => pax,
                    Err(reason) => {
                        out.limitation("alpine-apk.unread", Some(file), Some(reason.into()));
                        return;
                    }
                };
                let value = json!({"path":entry.path,"logical_path":entry.logical,"header_offset":entry.header,"offset":entry.offset,"size":entry.size,
                    "type":entry.kind,"mode":entry.mode,"uid":entry.uid,"gid":entry.gid,"link_target":entry.link,"pax":pax,
                    "captured_source":if matches!(entry.kind,0|b'0'){child(tree,file,layer,entry).map(|child|&child.path)}else{None}});
                // Keep room for control identity, dependencies and script source.
                if !budget.take(&value, 1, 4 * 1024 * 1024) {
                    break;
                }
                entries.push(value);
            }
            let omitted = layer.entries.len() - entries.len();
            omitted_entries += omitted;
            layers.push(json!({"role":layer.role,"prefix":layer.prefix,"offset":layer.offset,"compressed_size":layer.length,"decoded_size":layer.bytes.len(),"decoded_sha256":aa_core::sha256_hex(&layer.bytes),"gzip_crc_and_size_checked":true,"tar_zero_trailer":layer.trailer,
                "entries_total":layer.entries.len(),"entries_retained":entries.len(),"entries_omitted":omitted,"entry_preview_complete":omitted==0,"entries":entries}));
        }
        budget.report(file, out);
        out.kind(file, "alpine-apk");
        out.fact(file,"alpine-apk.container",json!({"format_version":2,"layers":layers,"signature_layers":package.control,"control_layer":package.control,"payload_layer":package.payload,
            "entry_preview_complete":omitted_entries==0,"entries_omitted":omitted_entries,
            "signatures_verified":false,"declared_checksums_verified":false,"keys_loaded":false}));
        let mut contents = Finding::new(Section::Structure, "alpine-apk", "alpine-apk.contents", Confidence::Verified, Severity::Info)
            .param("count", package.layers.len());
        for layer in &package.layers {
            contents = contents.evidence(Evidence::bytes(
                file,
                layer.offset as u64,
                layer.length as u64,
                json!({"role":layer.role,"decoded_sha256":aa_core::sha256_hex(&layer.bytes),"decoded_size":layer.bytes.len()}),
            ));
        }
        out.finding(contents);
        out.limitation("alpine-apk.integrity-unverified", Some(file), None);
        if link_semantics {
            out.limitation("alpine-apk.archive-semantics", Some(file), None);
        }
        let control = &package.layers[package.control];
        let info = control.entries.iter().find(|entry| entry.path == ".PKGINFO").expect("validated control identity entry");
        let Some(source) = child(tree, file, control, info) else {
            out.limitation("alpine-apk.unread", Some(file), Some("one original captured control .PKGINFO was not established".into()));
            return;
        };
        let metadata = match fields(&control.bytes[info.offset..info.offset + info.size]) {
            Ok(metadata) => metadata,
            Err(reason) => {
                out.limitation("alpine-apk.unread", Some(source), Some(reason.into()));
                return;
            }
        };
        let identity = |name: &str| {
            metadata.iter().find(|field| field.name == name).map(|field| field.value.as_str()).filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control) && !value.contains("[redacted]")
            })
        };
        let (Some(name), Some(version), Some(architecture)) = (identity("pkgname"), identity("pkgver"), identity("arch")) else {
            out.limitation("alpine-apk.unread", Some(source), Some("literal pkgname, pkgver and arch are required".into()));
            return;
        };
        let relationship = |name: &str| matches!(name, "depend" | "provides" | "replaces" | "install_if" | "triggers");
        let dependency_total = metadata.iter().filter(|field| relationship(&field.name)).count();
        let mut values = Vec::new();
        let mut dependencies = Vec::new();
        for field in &metadata {
            let value = json!({"name":field.name,"value":field.value,"line":field.line,"offset":field.offset,"length":field.length});
            // A relationship appears in the field preview, relationship preview
            // and its finding's evidence. Charge all three serialized copies.
            if !budget.take(&value, if relationship(&field.name) { 3 } else { 1 }, 0) {
                break;
            }
            if relationship(&field.name) {
                dependencies.push(value.clone());
            }
            values.push(value);
        }
        budget.report(file, out);
        out.fact(file,"alpine-apk.package",json!({"name":name,"version":version,"architecture":architecture,"source":source.path,"source_sha256":source.digests.as_ref().map(|digest|&digest.sha256),"fields":values,"dependencies":dependencies,
            "fields_total":metadata.len(),"fields_omitted":metadata.len()-values.len(),"fields_complete":metadata.len()==values.len(),
            "dependency_fields_total":dependency_total,"dependency_fields_omitted":dependency_total-dependencies.len(),
            "origin":identity("origin"),"commit":identity("commit"),"declared_license":identity("license"),"dependency_resolution_performed":false}));
        let mut finding = Finding::new(Section::Identity, "alpine-apk", "alpine-apk.identity", Confidence::Verified, Severity::Info)
            .param("name", name)
            .param("version", version)
            .param("architecture", architecture);
        for field in metadata.iter().filter(|field| matches!(field.name.as_str(), "pkgname" | "pkgver" | "arch")) {
            finding = finding.evidence(Evidence::bytes(
                source,
                field.offset as u64,
                field.length as u64,
                json!({"name":field.name,"value":field.value,"line":field.line}),
            ));
        }
        out.finding(finding);
        if dependency_total != 0 {
            out.finding(
                Finding::new(Section::Composition, "alpine-apk", "alpine-apk.dependencies", Confidence::Verified, Severity::Info)
                    .param("count", dependency_total)
                    .evidence(Evidence::field(
                        source,
                        ".PKGINFO relationships",
                        json!({"total":dependency_total,"retained":dependencies,"complete":dependencies.len()==dependency_total}),
                    )),
            );
        }
        let known = [
            "pkgname",
            "pkgver",
            "pkgdesc",
            "url",
            "builddate",
            "packager",
            "size",
            "arch",
            "origin",
            "commit",
            "maintainer",
            "license",
            "depend",
            "provides",
            "replaces",
            "install_if",
            "triggers",
            "datahash",
            "provider_priority",
            "replaces_priority",
        ];
        if metadata.iter().any(|field| !known.contains(&field.name.as_str()))
            || control.entries.iter().any(|entry| entry.path != ".PKGINFO" && !SCRIPTS.contains(&entry.path.as_str()))
        {
            out.limitation("alpine-apk.control-partial", Some(source), None);
        }
        if metadata.iter().any(|field| field.name == "triggers") {
            out.limitation("alpine-apk.script-semantics", Some(source), None);
        }
        let mut script_retained = 0usize;
        let script_total = control.entries.iter().filter(|entry| SCRIPTS.contains(&entry.path.as_str())).count();
        if script_total != 0 {
            out.limitation("alpine-apk.script-semantics", Some(source), None);
        }
        for entry in control.entries.iter().filter(|entry| SCRIPTS.contains(&entry.path.as_str())) {
            let Some(script) = child(tree, file, control, entry) else {
                out.limitation("alpine-apk.unread", Some(file), Some("control script was not captured uniquely".into()));
                continue;
            };
            let retained = if entry.size <= 256 * 1024 {
                std::str::from_utf8(&control.bytes[entry.offset..entry.offset + entry.size])
                    .map_err(|_| "script source is not UTF-8")
                    .and_then(redact_sensitive_text)
            } else {
                Err("script exceeds the 256 KiB source profile")
            };
            match retained {
                Ok(text) => {
                    let value = json!({"package":file.path,"role":entry.path,"text":text});
                    if !budget.take(&value, 2, 0) {
                        continue;
                    }
                    script_retained += 1;
                    out.fact(script, "alpine-apk.installation-declaration", value);
                    out.finding(
                        Finding::new(Section::Capabilities, "alpine-apk", "alpine-apk.script", Confidence::Verified, Severity::Info)
                            .param("name", entry.path.clone())
                            .evidence(Evidence::bytes(script, 0, script.size, json!({"role":entry.path,"text":text}))),
                    );
                }
                Err(reason) => out.limitation("alpine-apk.unread", Some(script), Some(reason.into())),
            }
        }
        budget.report(file, out);
        out.fact(
            file,
            "alpine-apk.output",
            json!({"preview_truncated":budget.limited,"serialized_budget":MAX_SERIALIZED_OUTPUT,
            "entries_omitted":omitted_entries,"metadata_fields_omitted":metadata.len()-values.len(),
            "script_text_total":script_total,"script_text_retained":script_retained,"script_text_omitted":script_total-script_retained}),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use std::io::Write;

    #[derive(Default)]
    struct Captured {
        files: Vec<(String, Vec<u8>)>,
        limitations: Vec<String>,
    }
    impl UnpackSink for Captured {
        fn add(&mut self, path: &str, reader: &mut dyn Read) -> std::result::Result<(), SinkError> {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).map_err(|error| SinkError::Read(error.to_string()))?;
            self.files.push((path.into(), bytes));
            Ok(())
        }
        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.into());
        }
    }
    struct Supplied {
        files: Vec<Artifact>,
        data: BTreeMap<String, Vec<u8>>,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.data.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::other("fixture bytes unavailable"))
        }
    }
    fn artifact(path: &str, parent: Option<&str>, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: "0".repeat(32), sha1: "0".repeat(40), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    fn archive(entries: &[(&str, &[u8])], cut: bool) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_path(name).expect("fixture path");
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder.append(&header, *bytes).expect("fixture member");
        }
        let mut bytes = builder.into_inner().expect("finish fixture archive");
        if cut {
            while bytes.ends_with(&[0; 512]) {
                bytes.truncate(bytes.len() - 512);
            }
        }
        bytes
    }
    fn compressed(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(bytes).expect("compress fixture");
        encoder.finish().expect("finish fixture gzip")
    }
    fn header_name(bytes: &mut [u8], at: usize, name: &str, prefix: Option<&str>) {
        let header = &mut bytes[at..at + 512];
        assert!(name.len() <= 100);
        header[..100].fill(0);
        header[..name.len()].copy_from_slice(name.as_bytes());
        if let Some(prefix) = prefix {
            assert!(prefix.len() <= 155);
            header[262] = b' ';
            header[345..500].fill(0);
            header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        }
        header[148..156].fill(b' ');
        let sum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    fn pax_control(path: &str) -> Vec<u8> {
        let data = format!("path={path}\n");
        let mut length = data.len() + 2;
        loop {
            let next = length.to_string().len() + 1 + data.len();
            if next == length {
                break;
            }
            length = next;
        }
        let record = format!("{length} {data}");
        let mut bytes = archive(&[("PaxHeaders/fixture", record.as_bytes()), ("placeholder", INFO)], true);
        bytes[156] = b'x';
        header_name(&mut bytes, 0, "PaxHeaders/fixture", None);
        bytes
    }
    const INFO:&[u8]=b"pkgname = fixture\npkgver = 1.2-r0\narch = noarch\nlicense = Apache-2.0\ndepend = so:libc.musl.so.1\nprovides = fixture=1.2\ntriggers = /usr/share/fixture/*\n";
    fn package_bytes(signed: bool, control: &[(&str, &[u8])], payload: &[(&str, &[u8])]) -> Vec<u8> {
        let mut bytes =
            if signed { compressed(&archive(&[(".SIGN.RSA.fixture.rsa.pub", b"inert signature bytes")], true)) } else { Vec::new() };
        bytes.extend(compressed(&archive(control, true)));
        bytes.extend(compressed(&archive(payload, false)));
        bytes
    }
    fn report(bytes: &[u8]) -> (Supplied, Output) {
        report_at(bytes, "fixture.apk")
    }
    fn report_at(bytes: &[u8], path: &str) -> (Supplied, Output) {
        let mut root = artifact(path, None, bytes);
        let mut capture = Captured::default();
        assert_eq!(Alpine.unpack(&root, bytes, &mut capture), Unpack::Done { kind: "alpine-apk" });
        root.unpacked_by = Some("alpine-apk".into());
        let mut files = vec![root.clone()];
        let mut data = BTreeMap::from([(root.path.clone(), bytes.to_vec())]);
        for (path, bytes) in capture.files {
            let path = format!("{}/{path}", root.path);
            files.push(artifact(&path, Some(&root.path), &bytes));
            data.insert(path, bytes);
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let tree = Supplied { files, data };
        let mut out = Output::default();
        Alpine.analyze_file(&tree, &root, &mut out);
        (tree, out)
    }
    fn fact<'a>(out: &'a Output, key: &str) -> &'a Value {
        &out.facts.iter().find(|fact| fact.key == key).expect("expected Alpine fact").value
    }

    #[test]
    fn signed_unsigned_layers_and_payload_impostors_keep_control_source_authority() {
        for signed in [false, true] {
            let bytes = package_bytes(
                signed,
                &[(".PKGINFO", INFO), (".post-install", b"#!/bin/sh\n# --token fixture-secret\n")],
                &[
                    (".PKGINFO", b"pkgname = forged\npkgver = 9\narch = evil\n"),
                    (".post-install", b"payload script is not an install declaration"),
                    ("usr/bin/data", b"inert payload"),
                ],
            );
            let (tree, out) = report(&bytes);
            let package = fact(&out, "alpine-apk.package");
            assert_eq!(package["name"], "fixture");
            assert_eq!(package["version"], "1.2-r0");
            assert_eq!(package["source"], "fixture.apk/[control]/.PKGINFO");
            assert_eq!(fact(&out, "alpine-apk.container")["signature_layers"], usize::from(signed));
            assert_eq!(out.facts.iter().filter(|fact| fact.key == "alpine-apk.installation-declaration").count(), 1);
            let published = serde_json::to_string(&out.facts.iter().map(|fact| &fact.value).collect::<Vec<_>>()).expect("fact JSON");
            assert!(!published.contains("fixture-secret"));
            for finding in &out.findings {
                for evidence in &finding.evidence {
                    let source = tree.files.iter().find(|file| file.path == evidence.artifact).expect("evidence artifact");
                    if let aa_core::Location::Bytes { offset, length } = evidence.location {
                        assert!(offset + length <= source.size);
                    }
                }
            }
            let (_, repeated) = report(&bytes);
            assert_eq!(out.facts, repeated.facts);
            assert_eq!(out.findings, repeated.findings);
        }
    }

    #[test]
    fn exact_gzip_members_check_crc_size_and_header_budgets() {
        let first = compressed(b"first member");
        let second = compressed(b"second member");
        let mut joined = first.clone();
        joined.extend(&second);
        let (decoded, extent) = gzip(&joined, 64).expect("first gzip member");
        assert_eq!(decoded, b"first member");
        assert_eq!(extent, first.len());
        assert_eq!(gzip(&joined[extent..], 64).expect("second member").0, b"second member");
        for index in [first.len() - 8, first.len() - 4] {
            let mut damaged = first.clone();
            damaged[index] ^= 1;
            assert!(gzip(&damaged, 64).is_err());
        }
        assert!(gzip(&first, 3).is_err());
        let mut huge_name = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        huge_name.extend(vec![b'a'; 4097]);
        huge_name.push(0);
        assert!(gzip_header(&huge_name).is_err());
        let mut flags = first;
        flags[3] |= 0x80;
        assert!(gzip_header(&flags).is_err());
    }

    #[test]
    fn duplicate_controls_metadata_and_unread_trailing_members_never_establish_identity() {
        let duplicate = package_bytes(false, &[(".PKGINFO", INFO), ("./.PKGINFO", INFO)], &[]);
        assert!(parse(&duplicate).is_err());
        assert!(fields(b"pkgname = one\npkgname = two\npkgver = 1\narch = noarch\n").is_err());
        let mut bytes = package_bytes(true, &[(".PKGINFO", INFO)], &[("data", b"payload")]);
        let valid = bytes.clone();
        bytes.extend(compressed(b"hidden stream"));
        assert!(parse(&bytes).is_err());
        for cut in 0..valid.len() {
            assert!(parse(&valid[..cut]).is_err(), "short prefix {cut}");
        }
        let mut bytes = package_bytes(false, &[(".PKGINFO", INFO)], &[]);
        bytes.push(0);
        assert!(parse(&bytes).is_err());
        let mut ended = compressed(&archive(&[(".PKGINFO", INFO)], false));
        ended.extend(compressed(&archive(&[], false)));
        assert!(parse(&ended).is_err());
    }

    #[test]
    fn effective_literal_control_names_and_gnu_prefixes_cannot_gain_authority() {
        let payload = compressed(&archive(&[], false));
        for alias in ["./.PKGINFO", ".PKGINFO/", "././.PKGINFO"] {
            // Header::set_path removes leading ./, so preserve these spellings
            // by changing the checked raw header before gzip encoding.
            let mut control = archive(&[(".PKGINFO", INFO)], true);
            header_name(&mut control, 0, alias, None);
            assert_eq!(tar(&control).expect("checksummed alias").0[0].path, alias);
            let mut bytes = compressed(&control);
            bytes.extend(&payload);
            assert!(parse(&bytes).is_err(), "literal control alias {alias}");
            let mut captured = Captured::default();
            assert!(matches!(Alpine.unpack(&artifact("alias.apk", None, &bytes), &bytes, &mut captured), Unpack::Failed { .. }));
            assert!(captured.files.is_empty());
            let mut bytes = compressed(&pax_control(alias));
            bytes.extend(&payload);
            assert!(parse(&bytes).is_err(), "effective PAX control alias {alias}");
        }
        let mut bytes = compressed(&pax_control(".PKGINFO"));
        bytes.extend(&payload);
        assert_eq!(fact(&report(&bytes).1, "alpine-apk.package")["name"], "fixture", "literal effective PAX path is authoritative");
        for alias in ["./.post-install", ".post-install/"] {
            let mut control = archive(&[(".PKGINFO", INFO), (".post-install", b"inert script")], true);
            let at = tar(&control).expect("control records").0[1].header;
            header_name(&mut control, at, alias, None);
            let mut bytes = compressed(&control);
            bytes.extend(&payload);
            assert!(parse(&bytes).is_err(), "literal script alias {alias}");
        }
        for alias in ["./.SIGN.RSA.fixture", ".SIGN.RSA.fixture/"] {
            let mut signature = archive(&[(".SIGN.RSA.fixture", b"inert")], true);
            header_name(&mut signature, 0, alias, None);
            let mut bytes = compressed(&signature);
            bytes.extend(package_bytes(false, &[(".PKGINFO", INFO)], &[]));
            assert!(parse(&bytes).is_err(), "literal signature alias {alias}");
        }
        for name in [".PKGINFO", ".SIGN.RSA.fixture"] {
            let mut control = archive(&[(name, INFO)], true);
            header_name(&mut control, 0, name, Some("payload"));
            assert_ne!(control[262], 0, "GNU header marker");
            assert_eq!(tar(&control).expect("GNU effective prefix").0[0].path, format!("payload/{name}"));
            let mut bytes = compressed(&control);
            bytes.extend(&payload);
            assert!(parse(&bytes).is_err(), "GNU prefixed {name}");
            let mut control = archive(&[(name, INFO)], true);
            control[156] = 0;
            header_name(&mut control, 0, name, None);
            let mut bytes = compressed(&control);
            bytes.extend(&payload);
            assert!(parse(&bytes).is_err(), "NUL typeflag is not an apk-tools control file");
        }
        let repeated_script = package_bytes(false, &[(".PKGINFO", INFO), (".post-install", b"one"), (".post-install", b"two")], &[]);
        assert!(parse(&repeated_script).is_err(), "duplicate controls cannot amplify script findings");
    }

    #[test]
    fn full_artifact_paths_and_aggregate_offers_are_bounded_before_the_sink() {
        struct Counted {
            root_length: usize,
            offered: usize,
            bytes: usize,
            limits: Vec<String>,
        }
        impl UnpackSink for Counted {
            fn add(&mut self, path: &str, _reader: &mut dyn Read) -> std::result::Result<(), SinkError> {
                let full_length = self.root_length + 1 + path.len();
                assert!(full_length <= MAX_ARTIFACT_PATH, "overlong child must not reach the sink");
                self.bytes += full_length;
                assert!(self.bytes <= MAX_OFFERED_PATHS, "aggregate offers must be checked first");
                self.offered += 1;
                Ok(())
            }
            fn limitation(&mut self, code: &str, _detail: Option<String>) {
                self.limits.push(code.into());
            }
        }
        let bytes = package_bytes(false, &[(".PKGINFO", INFO)], &[]);
        for length in [MAX_ARTIFACT_PATH - 5, MAX_ARTIFACT_PATH + 1, 60 * 1024] {
            let path = format!("{}.apk", "x".repeat(length - 4));
            let root = artifact(&path, None, &bytes);
            let mut sink = Counted { root_length: path.len(), offered: 0, bytes: 0, limits: Vec::new() };
            let result = Alpine.unpack(&root, &bytes, &mut sink);
            assert_eq!(sink.offered, 0);
            if length > MAX_ARTIFACT_PATH {
                assert!(matches!(result, Unpack::Failed { .. }));
                let mut root = root;
                root.unpacked_by = Some("alpine-apk".into());
                let tree = Supplied { files: vec![root.clone()], data: BTreeMap::new() };
                let mut out = Output::default();
                Alpine.analyze_file(&tree, &root, &mut out);
                assert!(out.facts.is_empty());
                assert_eq!(out.limitations.len(), 1);
                assert_eq!(out.limitations[0].code, "alpine-apk.output-limited");
            } else {
                assert_eq!(result, Unpack::Done { kind: "alpine-apk" });
                assert_eq!(sink.limits, ["alpine-apk.output-limited"]);
            }
        }
        let names = (0..9000).map(|index| format!("file{index:05}")).collect::<Vec<_>>();
        let entries = names.iter().map(|name| (name.as_str(), &b""[..])).collect::<Vec<_>>();
        let bytes = package_bytes(false, &[(".PKGINFO", INFO)], &entries);
        let path = format!("{}fixture.apk", "nested/".repeat(850));
        let mut sink = Counted { root_length: path.len(), offered: 0, bytes: 0, limits: Vec::new() };
        assert_eq!(Alpine.unpack(&artifact(&path, None, &bytes), &bytes, &mut sink), Unpack::Done { kind: "alpine-apk" });
        assert!(sink.offered > 1 && sink.offered < entries.len());
        assert!(sink.bytes > MAX_OFFERED_PATHS - MAX_ARTIFACT_PATH);
        assert_eq!(sink.limits, ["alpine-apk.output-limited"]);
    }

    #[test]
    fn shared_serialized_preview_budget_accounts_for_long_paths_and_escaped_metadata() {
        let names = (0..2500).map(|index| format!("file{index:05}")).collect::<Vec<_>>();
        let entries = names.iter().map(|name| (name.as_str(), &b""[..])).collect::<Vec<_>>();
        let mut metadata = INFO.to_vec();
        // JSON escaping and the three copies of each relationship are charged.
        for _ in 0..110 {
            metadata.extend(format!("depend = {}\n", "\u{1}".repeat(8000)).as_bytes());
        }
        let bytes = package_bytes(false, &[(".PKGINFO", &metadata), (".post-install", b"inert text")], &entries);
        let path = format!("{}fixture.apk", "n/".repeat(3000));
        let (_, out) = report_at(&bytes, &path);
        let container = fact(&out, "alpine-apk.container");
        assert_eq!(container["entry_preview_complete"], false);
        assert!(container["entries_omitted"].as_u64().expect("omitted total") > 0);
        let payload = &container["layers"][1];
        assert_eq!(payload["entries_total"], entries.len());
        assert!(payload["entries_retained"].as_u64().expect("retained count") > 0);
        assert_eq!(
            payload["entries_retained"].as_u64().expect("retained count") + payload["entries_omitted"].as_u64().expect("omitted count"),
            entries.len() as u64
        );
        let package = fact(&out, "alpine-apk.package");
        assert_eq!(package["fields_complete"], false);
        assert_eq!(package["dependency_fields_total"], 113);
        assert!(package["dependency_fields_omitted"].as_u64().expect("omitted fields") > 0);
        assert_eq!(fact(&out, "alpine-apk.output")["preview_truncated"], true);
        assert_eq!(out.limitations.iter().filter(|limit| limit.code == "alpine-apk.output-limited").count(), 1);
        let facts = out.facts.iter().map(|fact| json!({"artifact":fact.artifact,"key":fact.key,"value":fact.value})).collect::<Vec<_>>();
        let serialized =
            serde_json::to_vec(&json!({"facts":facts,"findings":out.findings,"kinds":out.kinds,"limitations":out.limitations}))
                .expect("serialized Alpine output");
        assert!(serialized.len() <= MAX_SERIALIZED_OUTPUT, "{} bytes exceed the output profile", serialized.len());

        // Fixed evidence paths can themselves expand sixfold in JSON. Their
        // reserve is independent of the variable entry/field previews above.
        let bytes = package_bytes(true, &[(".PKGINFO", INFO), (".post-install", b"inert")], &[]);
        let path = format!("{}.apk", "\u{1}".repeat(8000));
        let (_, out) = report_at(&bytes, &path);
        let serialized = serde_json::to_vec(&json!({"facts":out.facts.iter().map(|fact|json!({"artifact":fact.artifact,"key":fact.key,"value":fact.value})).collect::<Vec<_>>(),"findings":out.findings,"kinds":out.kinds,"limitations":out.limitations})).expect("escaped evidence output");
        assert!(serialized.len() <= FIXED_OUTPUT_RESERVE);
    }

    #[test]
    fn tar_checksums_pax_lengths_paths_and_metadata_budgets_are_bounded() {
        let mut bytes = archive(&[(".PKGINFO", INFO)], true);
        bytes[12] ^= 1;
        assert!(tar(&bytes).is_err());
        assert!(pax(b"999999 path=bad\n", 0).is_err());
        assert!(pax(b"14 size=99999\n", 0).is_err());
        assert!(fields(format!("pkgname = {}\n", "a".repeat(16 * 1024)).as_bytes()).is_err());
        assert!(fields("depend = x\n".repeat(MAX_FIELDS + 1).as_bytes()).is_err());
        let mut payload = archive(&[("outside", b"not followed")], false);
        payload[..100].fill(0);
        payload[..10].copy_from_slice(b"../outside");
        payload[148..156].fill(b' ');
        let sum = payload[..512].iter().map(|byte| u64::from(*byte)).sum::<u64>();
        payload[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        let mut bytes = compressed(&archive(&[(".PKGINFO", INFO)], true));
        bytes.extend(compressed(&payload));
        let parsed = parse(&bytes).expect("unsafe path remains metadata");
        assert!(parsed.layers[parsed.payload].entries[0].logical.is_none());
        let mut captured = Captured::default();
        assert_eq!(Alpine.unpack(&artifact("fixture.apk", None, &bytes), &bytes, &mut captured), Unpack::Done { kind: "alpine-apk" });
        assert!(captured.files.iter().all(|(path, _)| !path.contains("outside")));
        assert!(!captured.limitations.is_empty());
    }

    #[test]
    fn android_zip_and_adb_v3_are_distinguished_from_supported_alpine_layers() {
        let file = artifact("same-extension.apk", None, b"");
        let mut sink = Captured::default();
        assert_eq!(Alpine.unpack(&file, b"PK\x03\x04 Android APK fixture", &mut sink), Unpack::NotMine);
        assert!(matches!(Alpine.unpack(&file, b"ADB.\x00\x00\x00\x00", &mut sink), Unpack::Failed { kind: "alpine-apk", .. }));
        let gz = compressed(b"ordinary gzip text");
        let file = artifact("ordinary.gz", None, &gz);
        assert_eq!(Alpine.unpack(&file, &gz, &mut sink), Unpack::NotMine);
    }

    #[test]
    fn published_alpine_pax_layers_retain_identity_library_and_link_declarations() {
        let bytes = include_bytes!("../tests/data/libxxhash-0.8.3-r0.apk");
        let parsed = parse(bytes).expect("real Alpine package");
        assert_eq!(parsed.layers.len(), 3);
        assert_eq!(parsed.layers.iter().map(|layer| layer.length).collect::<Vec<_>>(), vec![719, 575, 22348]);
        let (tree, out) = report(bytes);
        let package = fact(&out, "alpine-apk.package");
        assert_eq!(package["name"], "libxxhash");
        assert_eq!(package["version"], "0.8.3-r0");
        assert_eq!(package["architecture"], "x86_64");
        assert!(tree.files.iter().any(|file| file.path == "fixture.apk/[payload]/usr/lib/libxxhash.so.0.8.3" && file.size == 71360));
        let payload = &fact(&out, "alpine-apk.container")["layers"][2]["entries"];
        assert!(payload.as_array().expect("payload entries").iter().any(|entry| entry["link_target"] == "libxxhash.so.0.8.3"));
        assert_eq!(fact(&out, "alpine-apk.container")["declared_checksums_verified"], false);
    }
}
