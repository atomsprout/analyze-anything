//! A read-only Flatpak single-file profile: empty-base, inline OSTree literal objects.

mod variant;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Result;
use variant::{Budget, Node};

pub struct Flatpak;
pub struct Part;

const SUPER: &str = "(a{sv}tayay(a{sv}aya(say)sstayay)aya(uayttay)a(yaytt))";
const PAYLOAD: &str = "(a(uuu)aa(ayay)ayay)";
const MAX_BUNDLE: usize = 256 * 1024 * 1024;
const MAX_PART: usize = 64 * 1024 * 1024;
const MAX_TOTAL: usize = 256 * 1024 * 1024;
const MAX_OBJECTS: usize = 100_000;
const MAX_PARTS: usize = 4096;
const MAX_ISSUES: usize = 64;

const RULES: &[Rule] = &[
    Rule { id: "flatpak.identity", title_en: "Declared Flatpak bundle identity", title_zh: "Flatpak 单文件包身份声明",
        text_en: "The single-file bundle declares {reference}. Its supplied commit and application metadata were read without installation or runtime loading.",
        text_zh: "单文件包声明了 {reference}。读取了所提供的提交和应用元数据，没有安装或加载到运行时。" },
    Rule { id: "flatpak.contents", title_en: "Captured Flatpak bundle contents", title_zh: "已捕获的 Flatpak 单文件包内容",
        text_en: "The supported inline profile exposes {count} regular files from the supplied OSTree object graph. Each association retains its part and byte source; external objects and link targets are never fetched or followed.",
        text_zh: "支持的内联格式从所提供的 OSTree 对象图中读取了 {count} 个普通文件。每个关联保留其分段和字节来源，没有获取外部对象或跟随链接目标。" },
    Rule { id: "flatpak.permissions", title_en: "Declared Flatpak application context", title_zh: "Flatpak 应用上下文声明",
        text_en: "The application metadata contains runtime, command or permission declarations. Values remain literal; effective permissions, host overrides and execution were not established.",
        text_zh: "应用元数据包含运行时、命令或权限声明。按字面保留其值，没有确定有效权限、本机覆盖设置或实际执行。" },
    Rule { id: "flatpak.bundle-unread", title_en: "Flatpak bundle could not be read", title_zh: "Flatpak 单文件包无法读取",
        text_en: "The candidate could not be read within the bounded GVariant and single-file profile. Malformed framing and missing identity are not treated as empty values.",
        text_zh: "无法在有界 GVariant 和单文件支持范围内读取候选项。格式错误或身份缺失没有被视为空值。" },
    Rule { id: "flatpak.contents-unread", title_en: "Some Flatpak contents remain unread", title_zh: "部分 Flatpak 内容未读取",
        text_en: "The bundle contains missing, malformed or unsupported objects, operations or compression, or a reader budget was exhausted. Completed observations remain available; complete payload enumeration was not established.",
        text_zh: "单文件包包含缺失、错误或不支持的对象、操作或压缩方式，或读取预算已耗尽。保留已完成的观察，没有确定载荷枚举完整。" },
    Rule { id: "flatpak.metadata-unread", title_en: "Some Flatpak metadata remains uninterpreted", title_zh: "部分 Flatpak 元数据未解释",
        text_en: "Application metadata, duplicate fields or unsupported metadata types could not be interpreted unambiguously. Retained declarations do not establish runtime behavior.",
        text_zh: "无法唯一解释应用元数据、重复字段或不支持的元数据类型。保留的声明不能确定运行时行为。" },
    Rule { id: "flatpak.link-semantics", title_en: "Flatpak links and attributes remain declarations", title_zh: "Flatpak 链接和属性仅作为声明",
        text_en: "Symlink targets, directory modes and extended attributes remain metadata. They were not materialized, followed or applied to the host.",
        text_zh: "符号链接目标、目录模式和扩展属性仅作为元数据，没有创建、跟随或应用到本机。" },
    Rule { id: "flatpak.integrity-unverified", title_en: "Flatpak authenticity and runtime state remain unverified", title_zh: "Flatpak 来源真实性和运行时状态未验证",
        text_en: "Supported commit, object and part digests are checked separately from authenticity. Signatures, repository trust, runtime availability and effective sandbox policy were not authenticated or resolved.",
        text_zh: "支持的提交、对象和分段摘要检查与来源认证分开。没有认证或解析签名、仓库信任、运行时可用性或有效沙箱策略。" },
];

fn dict<'a>(node: &Node<'a>) -> Result<BTreeMap<&'a str, Node<'a>>> {
    let mut result = BTreeMap::new();
    for row in node.children(4096)? {
        let columns = row.children(2)?;
        let key = columns.first().ok_or("missing GVariant dictionary key")?.string()?;
        if key.len() > 4096 { return Err("GVariant dictionary key exceeds the profile".into()); }
        let value = columns.get(1).ok_or("missing GVariant dictionary value")?.variant()?;
        if result.insert(key, value).is_some() { return Err("duplicate GVariant dictionary key".into()); }
    }
    Ok(result)
}

fn checksum(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| "OSTree checksum is not 32 bytes".into())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn modified_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+_";
    let mut output = String::new();
    let mut bits = 0u32;
    let mut count = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        count += 8;
        while count >= 6 {
            count -= 6;
            output.push(ALPHABET[((bits >> count) & 63) as usize] as char);
        }
    }
    if count != 0 { output.push(ALPHABET[((bits << (6 - count)) & 63) as usize] as char); }
    output
}

struct Header<'a> {
    reference: &'a str,
    metadata: Option<Node<'a>>,
    commit: Node<'a>,
    to: [u8; 32],
    fields: Vec<Node<'a>>,
    dictionary: BTreeMap<&'a str, Node<'a>>,
    little: Option<bool>,
}

fn header(bytes: &[u8]) -> Result<Header<'_>> {
    if bytes.len() > MAX_BUNDLE { return Err("Flatpak bundle exceeds the 256 MiB input profile".into()); }
    let root = Node::new(bytes, SUPER)?;
    let fields = root.children(8)?;
    let dictionary = dict(fields.first().ok_or("missing bundle metadata")?)?;
    let reference = dictionary.get("ref").ok_or("bundle has no Flatpak ref")?.string()?;
    let parts: Vec<_> = reference.split('/').collect();
    if parts.len() != 4 || !matches!(parts[0], "app" | "runtime") || parts.iter().any(|part| part.is_empty() || part.len() > 256 || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))) {
        return Err("Flatpak ref is outside the supported four-component profile".into());
    }
    root.validate(&mut Budget::default(), 0)?;
    let to = checksum(fields.get(3).ok_or("missing target commit checksum")?.bytes()?)?;
    let commit = fields.get(4).ok_or("missing target commit object")?.clone();
    if digest(commit.data) != to { return Err("embedded commit digest differs from the target commit declaration".into()); }
    let little = match dictionary.get("ostree.endianness").map(|node| node.number(true)).transpose()? {
        Some(value) if value == u64::from(b'l') => Some(true),
        Some(value) if value == u64::from(b'B') => Some(false),
        _ => None,
    };
    let metadata = dictionary.get("metadata").cloned();
    if let Some(metadata) = &metadata { metadata.string()?; }
    Ok(Header { reference, metadata, commit, to, fields, dictionary, little })
}

fn decode_part(raw: &[u8]) -> Result<Vec<u8>> {
    let (&compression, body) = raw.split_first().ok_or("empty inline part")?;
    if raw.len() > MAX_PART { return Err("compressed part exceeds the 64 MiB profile".into()); }
    let bytes = match compression {
        0 => body.to_vec(),
        b'x' => {
            if !body.starts_with(b"\xfd7zXZ\0") { return Err("XZ part lacks the XZ stream signature".into()); }
            let cursor = Cursor::new(body);
            let mut reader = lzma_bounded::XzReader::new_mem_limit(cursor, false, 100 * 1024);
            let mut bytes = Vec::new();
            reader.by_ref().take(MAX_PART as u64 + 1).read_to_end(&mut bytes).map_err(|error| format!("bounded XZ part: {error}"))?;
            if bytes.len() > MAX_PART { return Err("decoded part exceeds the 64 MiB profile".into()); }
            if reader.into_inner().position() != body.len() as u64 { return Err("XZ part has unread trailing bytes".into()); }
            bytes
        }
        _ => return Err(format!("unsupported inline-part compression byte {compression}")),
    };
    let node = Node::new(&bytes, PAYLOAD)?;
    node.validate(&mut Budget::default(), 0)?;
    Ok(bytes)
}

fn part_name(index: usize) -> String { format!("parts/{index}.flatpak-part") }

struct Object {
    kind: u8,
    checksum: [u8; 32],
    part: usize,
    offset: usize,
    size: usize,
    mode: Option<u32>,
    xattrs: usize,
}

struct DecodedPart<'a> {
    index: usize,
    raw: Node<'a>,
    bytes: Vec<u8>,
    objects: usize,
    complete: bool,
}

struct File {
    path: String,
    checksum: [u8; 32],
    object: usize,
    target: Option<String>,
}

struct Bundle<'a> {
    header: Header<'a>,
    parts: Vec<DecodedPart<'a>>,
    objects: Vec<Object>,
    files: Vec<File>,
    directories: Vec<Value>,
    issues: Vec<String>,
    complete: bool,
}

fn varuint(bytes: &[u8], at: &mut usize) -> Result<usize> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes.get(*at).ok_or("static-delta operand is truncated")?;
        *at += 1;
        if index == 9 && byte > 1 { return Err("static-delta operand overflows 64 bits".into()); }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 { return Err("overlong static-delta operand".into()); }
            return usize::try_from(value).map_err(|_| "static-delta operand exceeds the address space".into());
        }
    }
    Err("static-delta operand is too long".into())
}

impl Bundle<'_> {
    fn issue(&mut self, detail: impl Into<String>) {
        self.complete = false;
        if self.issues.len() < MAX_ISSUES { self.issues.push(detail.into()); }
    }

    fn contents(&mut self) -> Result<()> {
        if !self.header.fields[2].bytes()?.is_empty() { return Err("nonempty base commits require external objects and are outside this profile".into()); }
        if !self.header.fields[5].bytes()?.is_empty() { return Err("recursive delta parents are outside this profile".into()); }
        if !self.header.fields[7].children(MAX_OBJECTS)?.is_empty() { return Err("fallback objects are not captured inline and are outside this profile".into()); }
        let little = self.header.little.ok_or("delta endianness is missing or unsupported; host byte order is never assumed")?;
        let headers = self.header.fields[6].children(MAX_PARTS)?;
        let base64 = modified_base64(&self.header.to);
        let mut total = 0usize;
        for (index, row) in headers.iter().enumerate() {
            let fields = row.children(5)?;
            if fields[0].number(little)? != 0 { self.issue(format!("part {index}: unsupported part version")); continue; }
            let key = format!("deltas/{}/{}/{index}", &base64[..2], &base64[2..]);
            let Some(raw) = self.header.dictionary.get(key.as_str()).cloned() else { self.issue(format!("part {index}: missing inline payload")); continue };
            if raw.ty != variant::signature("(yay)")? { self.issue(format!("part {index}: unsupported inline value type")); continue; }
            if fields[2].number(little)? != raw.data.len() as u64 { self.issue(format!("part {index}: compressed-size declaration differs from captured bytes")); continue; }
            if digest(raw.data) != checksum(fields[1].bytes()?)? { self.issue(format!("part {index}: inline payload digest mismatch")); continue; }
            let bytes = match decode_part(raw.data) { Ok(bytes) => bytes, Err(detail) => { self.issue(format!("part {index}: {detail}")); continue; } };
            total = total.checked_add(bytes.len()).ok_or("decoded-part byte total overflow")?;
            if total > MAX_TOTAL { return Err("decoded-part total exceeds the 256 MiB profile".into()); }
            let objects = fields[4].bytes()?;
            if objects.len() % 33 != 0 { self.issue(format!("part {index}: object descriptors are not a multiple of 33 bytes")); continue; }
            if self.objects.len().saturating_add(objects.len() / 33) > MAX_OBJECTS { return Err("static-delta object budget exhausted".into()); }
            let part_slot = self.parts.len();
            self.parts.push(DecodedPart { index, raw, bytes, objects: objects.len() / 33, complete: false });
            match self.read_objects(part_slot, objects) {
                Ok(()) => self.parts[part_slot].complete = true,
                Err(detail) => self.issue(format!("part {index}: {detail}")),
            }
        }
        self.resolve_tree()
    }

    fn read_objects(&mut self, slot: usize, descriptors: &[u8]) -> Result<()> {
        let root = Node::new(&self.parts[slot].bytes, PAYLOAD)?;
        let fields = root.children(4)?;
        let modes = fields[0].children(MAX_OBJECTS)?;
        let xattrs = fields[1].children(MAX_OBJECTS)?;
        let blob = fields[2].bytes()?;
        let ops = fields[3].bytes()?;
        let mut at = 0;
        for descriptor in descriptors.chunks_exact(33) {
            if ops.get(at) != Some(&b'S') { return Err("only complete literal S objects are supported; another or missing opcode remains unread".into()); }
            at += 1;
            let kind = descriptor[0];
            let checksum = checksum(&descriptor[1..])?;
            let (mode, attrs, mode_values) = if kind == 1 {
                let mode = varuint(ops, &mut at)?;
                let attrs = varuint(ops, &mut at)?;
                let mode = modes.get(mode).ok_or("file mode-table index is outside its table")?.children(3)?;
                if attrs >= xattrs.len() { return Err("file xattr-table index is outside its table".into()); }
                (Some(u32::try_from(mode[2].number(false)?).map_err(|_| "file mode exceeds 32 bits")?), attrs, Some(mode))
            } else if (2..=6).contains(&kind) { (None, 0, None) } else { return Err(format!("unsupported OSTree object type {kind}")); };
            let length = varuint(ops, &mut at)?;
            let offset = varuint(ops, &mut at)?;
            let data = crate::extent(blob, offset, length)?;
            if kind != 1 && digest(data) != checksum { return Err("metadata object digest mismatch".into()); }
            if let Some(mode_values) = mode_values {
                let actual = content_checksum(&mode_values, &xattrs[attrs], data)?;
                if actual != checksum { return Err("content object digest mismatch".into()); }
            }
            self.objects.push(Object { kind, checksum, part: slot, offset: fields[2].offset + offset, size: length, mode, xattrs: attrs });
        }
        if at != ops.len() { return Err("operation stream has trailing or unmatched operations".into()); }
        Ok(())
    }

    fn resolve_tree(&mut self) -> Result<()> {
        let mut map = BTreeMap::new();
        for (index, object) in self.objects.iter().enumerate() {
            if map.insert((object.kind, object.checksum), index).is_some() { return Err("duplicate object identities prevent unambiguous path binding".into()); }
        }
        let commit = self.header.commit.children(8)?;
        let root_tree = checksum(commit[6].bytes()?)?;
        let root_meta = checksum(commit[7].bytes()?)?;
        let mut pending = vec![(String::new(), root_tree, root_meta, BTreeSet::new())];
        let mut paths = BTreeSet::new();
        let mut names = 0usize;
        while let Some((path, tree_hash, meta_hash, mut ancestors)) = pending.pop() {
            if ancestors.len() >= 128 || !ancestors.insert(tree_hash) { return Err("OSTree directory cycle or depth budget exhausted".into()); }
            let tree_index = *map.get(&(2, tree_hash)).ok_or("directory-tree object is missing from captured parts")?;
            let meta_index = *map.get(&(3, meta_hash)).ok_or("directory-metadata object is missing from captured parts")?;
            let metadata = self.object_node(meta_index, "(uuua(ayay))")?;
            metadata.validate(&mut Budget::default(), 0)?;
            let mode = metadata.children(4)?[2].number(false)?;
            self.directories.push(json!({"path": path, "tree_checksum": hex::encode(tree_hash), "metadata_checksum": hex::encode(meta_hash), "mode": mode}));
            if self.directories.len() > MAX_OBJECTS { return Err("OSTree directory budget exhausted".into()); }
            let tree = self.object_node(tree_index, "(a(say)a(sayay))")?;
            tree.validate(&mut Budget::default(), 0)?;
            let lists = tree.children(2)?;
            let mut files = Vec::new();
            for row in lists[0].children(MAX_OBJECTS)? {
                let columns = row.children(2)?;
                let name = columns[0].string()?;
                let path = child_path(&path, name)?;
                names = names.saturating_add(path.len());
                if names > crate::MAX_METADATA || !paths.insert(path.clone()) { return Err("OSTree path budget exhausted or duplicate path declaration".into()); }
                let checksum = checksum(columns[1].bytes()?)?;
                let object = *map.get(&(1, checksum)).ok_or("file object is missing from captured parts")?;
                let target = if self.objects[object].mode.is_some_and(|mode| mode & 0o170000 == 0o120000) {
                    let data = self.object_bytes(object)?;
                    if data.len() > 4096 { return Err("symlink target exceeds the 4096-byte declaration profile".into()); }
                    let target = std::str::from_utf8(data).map_err(|_| "symlink target is not UTF-8")?;
                    if target.contains('\0') { return Err("symlink target contains NUL".into()); }
                    Some(aa_core::text::redact_sensitive_text(target).map_err(str::to_string)?)
                } else if self.objects[object].mode.is_some_and(|mode| mode & 0o170000 == 0o100000) { None } else { return Err("special file mode is outside the payload profile".into()); };
                files.push(File { path, checksum, object, target });
                if self.files.len().saturating_add(files.len()) > MAX_OBJECTS { return Err("OSTree file budget exhausted".into()); }
            }
            for row in lists[1].children(MAX_OBJECTS)? {
                let columns = row.children(3)?;
                let child = child_path(&path, columns[0].string()?)?;
                names = names.saturating_add(child.len());
                if names > crate::MAX_METADATA || !paths.insert(child.clone()) { return Err("OSTree path budget exhausted or duplicate directory declaration".into()); }
                pending.push((child, checksum(columns[1].bytes()?)?, checksum(columns[2].bytes()?)?, ancestors.clone()));
            }
            self.files.extend(files);
        }
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(())
    }

    fn object_bytes(&self, index: usize) -> Result<&[u8]> {
        let object = self.objects.get(index).ok_or("object index outside captured objects")?;
        crate::extent(&self.parts[object.part].bytes, object.offset, object.size)
    }

    fn object_node(&self, index: usize, signature: &str) -> Result<Node<'_>> {
        let mut node = Node::new(self.object_bytes(index)?, signature)?;
        node.offset = self.objects[index].offset;
        Ok(node)
    }
}

fn child_path(parent: &str, name: &str) -> Result<String> {
    if name.is_empty() || name.len() > 4096 || name.contains(['/', '\\', '\0']) || matches!(name, "." | "..") { return Err("OSTree filename is outside the safe UTF-8 leaf-name profile".into()); }
    let path = if parent.is_empty() { name.to_string() } else { format!("{parent}/{name}") };
    if path.len() > 4096 { return Err("OSTree path exceeds the 4096-byte profile".into()); }
    Ok(path)
}

fn content_checksum(modes: &[Node<'_>], xattrs: &Node<'_>, content: &[u8]) -> Result<[u8; 32]> {
    let mode = modes[2].number(false)?;
    let symlink = mode & 0o170000 == 0o120000;
    if !symlink && mode & 0o170000 != 0o100000 { return Err("content object has an unsupported file mode".into()); }
    let mut target = Vec::new();
    if symlink {
        if content.len() > 4096 || content.contains(&0) { return Err("symlink target is outside the bounded non-NUL profile".into()); }
        target.extend_from_slice(content);
    }
    target.push(0);
    let mut attributes = BTreeMap::new();
    for attribute in xattrs.children(4096)? {
        let values = attribute.children(2)?;
        let name = values[0].bytes()?;
        if name.len() > 4096 || values[1].bytes()?.len() > 1024 * 1024 { return Err("extended attribute exceeds the bounded checksum profile".into()); }
        if attributes.insert(name.to_vec(), attribute.data.to_vec()).is_some() { return Err("duplicate extended attribute names".into()); }
    }
    let attrs = variant::encode_array("(ayay)", &attributes.values().map(Vec::as_slice).collect::<Vec<_>>())?;
    let zero = [0; 4];
    let header = variant::encode_tuple(&[("u", modes[0].data), ("u", modes[1].data), ("u", modes[2].data), ("u", &zero), ("s", &target), ("a(ayay)", &attrs)])?;
    let mut hash = Sha256::new();
    hash.update(u32::try_from(header.len()).map_err(|_| "OSTree checksum header exceeds 32 bits")?.to_be_bytes());
    hash.update([0; 4]);
    hash.update(header);
    if !symlink { hash.update(content); }
    Ok(hash.finalize().into())
}

fn bundle(bytes: &[u8]) -> Result<Bundle<'_>> {
    let header = header(bytes)?;
    let mut bundle = Bundle { header, parts: Vec::new(), objects: Vec::new(), files: Vec::new(), directories: Vec::new(), issues: Vec::new(), complete: true };
    if let Err(detail) = bundle.contents() { bundle.issue(detail); }
    Ok(bundle)
}

fn add(sink: &mut dyn UnpackSink, path: &str, bytes: &[u8]) -> bool {
    match sink.add(path, &mut Cursor::new(bytes)) {
        Ok(()) => true,
        Err(SinkError::LimitReached) => false,
        Err(SinkError::Read(detail)) => { sink.limitation("flatpak.contents-unread", Some(detail)); false }
    }
}

impl Unpacker for Flatpak {
    fn id(&self) -> &'static str { "flatpak" }
    fn rules(&self) -> &'static [Rule] { RULES }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let candidate = file.extension().as_deref() == Some("flatpak");
        let parsed = match bundle(bytes) {
            Ok(parsed) => parsed,
            Err(detail) => return if candidate { Unpack::Failed { kind: "flatpak", detail } } else { Unpack::NotMine },
        };
        if let Some(metadata) = &parsed.header.metadata
            && !add(sink, "declared-metadata.ini", metadata.string().unwrap_or("").as_bytes()) { return Unpack::Done { kind: "flatpak" }; }
        for part in &parsed.parts {
            if !add(sink, &part_name(part.index), part.raw.data) { return Unpack::Done { kind: "flatpak" }; }
        }
        for file in &parsed.files {
            if file.target.is_none() {
                match parsed.object_bytes(file.object) {
                    Ok(bytes) => if !add(sink, &format!("root/{}", file.path), bytes) { break; },
                    Err(detail) => sink.limitation("flatpak.contents-unread", Some(detail)),
                }
            }
        }
        for issue in parsed.issues { sink.limitation("flatpak.contents-unread", Some(issue)); }
        Unpack::Done { kind: "flatpak" }
    }
}

impl Unpacker for Part {
    fn id(&self) -> &'static str { "flatpak-part" }
    fn rules(&self) -> &'static [Rule] { RULES }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if file.extension().as_deref() != Some("flatpak-part") || file.parent.is_none() { return Unpack::NotMine; }
        match decode_part(bytes) {
            Ok(bytes) => { add(sink, "decoded", &bytes); Unpack::Done { kind: "flatpak-part" } }
            Err(detail) => Unpack::Failed { kind: "flatpak-part", detail },
        }
    }
}

impl Analyzer for Flatpak {
    fn id(&self) -> &'static str { "flatpak" }
    fn rules(&self) -> &'static [Rule] { RULES }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("flatpak") && file.extension().as_deref() != Some("flatpak") { return; }
        let parsed = tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| retain(file, &bytes, out));
        if let Err(detail) = parsed { out.limitation("flatpak.bundle-unread", Some(file), Some(detail)); }
    }
}

fn retain(file: &Artifact, bytes: &[u8], out: &mut Output) -> Result<()> {
    let bundle = bundle(bytes)?;
    let reference = aa_core::text::redact_sensitive_text(bundle.header.reference).map_err(str::to_string)?;
    let parts: Vec<_> = bundle.parts.iter().map(|part| json!({"index": part.index, "source_offset": part.raw.offset, "source_length": part.raw.data.len(),
        "artifact": format!("{}/{}", file.path, part_name(part.index)), "decoded_artifact": format!("{}/{}/decoded", file.path, part_name(part.index)),
        "sha256": aa_core::sha256_hex(part.raw.data), "decoded_sha256": aa_core::sha256_hex(&part.bytes), "decoded_size": part.bytes.len(), "objects": part.objects, "complete": part.complete})).collect();
    let entries: Vec<_> = bundle.files.iter().map(|entry| {
        let object = &bundle.objects[entry.object];
        let part = &bundle.parts[object.part];
        json!({"path": entry.path, "object_checksum": hex::encode(entry.checksum), "object_label_verified": true,
            "mode": object.mode, "xattr_index": object.xattrs, "link_target": entry.target, "size": object.size,
            "part": part.index, "source": format!("{}/{}/decoded", file.path, part_name(part.index)), "offset": object.offset,
            "captured_path": entry.target.is_none().then(|| format!("{}/root/{}", file.path, entry.path))})
    }).collect();
    let identity: Vec<_> = reference.split('/').collect();
    out.fact(file, "flatpak.bundle", json!({"reference": reference, "name": identity[1], "architecture": identity[2], "branch": identity[3], "kind": identity[0],
        "commit": hex::encode(bundle.header.to), "complete": bundle.complete, "parts": parts, "entries": entries, "directories": bundle.directories,
        "profile": "empty-base-inline-v0-literal", "content_object_labels_verified": true, "signature_verified": false}));
    out.kind(file, "flatpak");
    out.finding(Finding::new(Section::Identity, "flatpak", "flatpak.identity", Confidence::Verified, Severity::Info)
        .param("reference", reference.as_str()).evidence(Evidence::bytes(file, bundle.header.commit.offset as u64, bundle.header.commit.data.len() as u64, json!({"reference": reference, "commit": hex::encode(bundle.header.to)}))));
    out.limitation("flatpak.integrity-unverified", Some(file), None);
    for issue in &bundle.issues { out.limitation("flatpak.contents-unread", Some(file), Some(issue.clone())); }
    if !bundle.files.is_empty() {
        let mut finding = Finding::new(Section::Composition, "flatpak", "flatpak.contents", Confidence::Derived, Severity::Info)
            .param("count", bundle.files.iter().filter(|entry| entry.target.is_none()).count());
        for entry in bundle.files.iter().take(5) {
            let object = &bundle.objects[entry.object];
            let part = &bundle.parts[object.part];
            finding = finding.evidence(Evidence::bytes(file, part.raw.offset as u64, part.raw.data.len() as u64,
                json!({"path": entry.path, "part": part.index, "decoded_offset": object.offset, "length": object.size, "object_checksum": hex::encode(entry.checksum)})));
        }
        out.finding(finding);
    }
    if bundle.files.iter().any(|entry| entry.target.is_some()) || bundle.objects.iter().any(|object| object.xattrs != 0) {
        out.limitation("flatpak.link-semantics", Some(file), None);
    }
    if let Some(metadata) = &bundle.header.metadata {
        let text = metadata.string()?;
        match application_metadata(text) {
            Ok(fields) => {
                out.fact(file, "flatpak.application", json!({"source": file.path, "offset": metadata.offset, "length": metadata.data.len(), "fields": fields}));
                out.finding(Finding::new(Section::Capabilities, "flatpak", "flatpak.permissions", Confidence::Verified, Severity::Info)
                    .evidence(Evidence::bytes(file, metadata.offset as u64, metadata.data.len() as u64, json!({"declarations": fields}))));
            }
            Err(detail) => out.limitation("flatpak.metadata-unread", Some(file), Some(detail)),
        }
        if let Some(captured) = bundle.files.iter().find(|entry| entry.path == "metadata" && entry.target.is_none())
            && bundle.object_bytes(captured.object)? != text.as_bytes() {
                out.limitation("flatpak.metadata-unread", Some(file), Some("superblock application metadata differs from the captured metadata file".into()));
            }
    } else { out.limitation("flatpak.metadata-unread", Some(file), Some("no application metadata string in the bundle superblock".into())); }
    Ok(())
}

fn application_metadata(text: &str) -> Result<Vec<Value>> {
    if text.len() > 256 * 1024 || text.contains('\0') { return Err("application metadata is outside the 256 KiB UTF-8 profile".into()); }
    let mut group = String::new();
    let mut seen = BTreeSet::new();
    let mut fields = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.len() > 16 * 1024 || fields.len() >= 4096 { return Err("application metadata line or field budget exhausted".into()); }
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) { continue; }
        if let Some(name) = line.strip_prefix('[').and_then(|line| line.strip_suffix(']')) {
            if name.is_empty() || name.len() > 256 { return Err("invalid application metadata group".into()); }
            group = name.to_string();
        } else {
            let (key, value) = line.split_once('=').ok_or("application metadata has an unsupported non-assignment line")?;
            let key = key.trim();
            if group.is_empty() || key.is_empty() || key.len() > 256 || !seen.insert((group.clone(), key.to_string())) { return Err("application metadata has missing groups or duplicate keys".into()); }
            let value = aa_core::text::redact_named_value(key, value.trim()).map_err(str::to_string)?;
            fields.push(json!({"group": group, "name": key, "value": value, "line": index + 1, "interpreted": matches!(group.as_str(), "Application" | "Runtime" | "Context" | "Session Bus Policy" | "System Bus Policy")}));
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires an explicitly supplied external .flatpak reference path"]
    fn inspect_external_reference_without_installation() {
        let path = std::env::var("AA_FLATPAK_REFERENCE").expect("set AA_FLATPAK_REFERENCE to a supplied bundle");
        let bytes = std::fs::read(path).expect("read supplied reference as bytes");
        let parsed = bundle(&bytes).expect("supported Flatpak superblock");
        eprintln!("reference={} parts={} objects={} files={} directories={} issues={:?}", parsed.header.reference, parsed.parts.len(), parsed.objects.len(), parsed.files.len(), parsed.directories.len(), parsed.issues);
        assert!(parsed.complete, "{:?}", parsed.issues);
        assert!(!parsed.files.is_empty());
    }
}
