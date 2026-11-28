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
    Rule {
        id: "flatpak.identity",
        title_en: "Declared Flatpak bundle identity",
        title_zh: "Flatpak 单文件包身份声明",
        text_en: "The single-file bundle declares {reference}. Its supplied commit and application metadata were read without installation or runtime loading.",
        text_zh: "单文件包声明了 {reference}。读取了所提供的提交和应用元数据，没有安装或加载到运行时。",
    },
    Rule {
        id: "flatpak.contents",
        title_en: "Captured Flatpak bundle contents",
        title_zh: "已捕获的 Flatpak 单文件包内容",
        text_en: "The supported inline profile exposes {count} regular files from the supplied OSTree object graph. Each association retains its part and byte source; external objects and link targets are never fetched or followed.",
        text_zh: "支持的内联格式从所提供的 OSTree 对象图中读取了 {count} 个普通文件。每个关联保留其分段和字节来源，没有获取外部对象或跟随链接目标。",
    },
    Rule {
        id: "flatpak.permissions",
        title_en: "Declared Flatpak application context",
        title_zh: "Flatpak 应用上下文声明",
        text_en: "The application metadata contains runtime, command or permission declarations. Values remain literal; effective permissions, host overrides and execution were not established.",
        text_zh: "应用元数据包含运行时、命令或权限声明。按字面保留其值，没有确定有效权限、本机覆盖设置或实际执行。",
    },
    Rule {
        id: "flatpak.bundle-unread",
        title_en: "Flatpak bundle could not be read",
        title_zh: "Flatpak 单文件包无法读取",
        text_en: "The candidate could not be read within the bounded GVariant and single-file profile. Malformed framing and missing identity are not treated as empty values.",
        text_zh: "无法在有界 GVariant 和单文件支持范围内读取候选项。格式错误或身份缺失没有被视为空值。",
    },
    Rule {
        id: "flatpak.contents-unread",
        title_en: "Some Flatpak contents remain unread",
        title_zh: "部分 Flatpak 内容未读取",
        text_en: "The bundle contains missing, malformed or unsupported objects, operations or compression, or a reader budget was exhausted. Completed observations remain available; complete payload enumeration was not established.",
        text_zh: "单文件包包含缺失、错误或不支持的对象、操作或压缩方式，或读取预算已耗尽。保留已完成的观察，没有确定载荷枚举完整。",
    },
    Rule {
        id: "flatpak.metadata-unread",
        title_en: "Some Flatpak metadata remains uninterpreted",
        title_zh: "部分 Flatpak 元数据未解释",
        text_en: "Application metadata, duplicate fields or unsupported metadata types could not be interpreted unambiguously. Retained declarations do not establish runtime behavior.",
        text_zh: "无法唯一解释应用元数据、重复字段或不支持的元数据类型。保留的声明不能确定运行时行为。",
    },
    Rule {
        id: "flatpak.link-semantics",
        title_en: "Flatpak links and attributes remain declarations",
        title_zh: "Flatpak 链接和属性仅作为声明",
        text_en: "Symlink targets, directory modes and extended attributes remain metadata. They were not materialized, followed or applied to the host.",
        text_zh: "符号链接目标、目录模式和扩展属性仅作为元数据，没有创建、跟随或应用到本机。",
    },
    Rule {
        id: "flatpak.integrity-unverified",
        title_en: "Flatpak authenticity and runtime state remain unverified",
        title_zh: "Flatpak 来源真实性和运行时状态未验证",
        text_en: "Supported commit, object and part digests are checked separately from authenticity. Signatures, repository trust, runtime availability and effective sandbox policy were not authenticated or resolved.",
        text_zh: "支持的提交、对象和分段摘要检查与来源认证分开。没有认证或解析签名、仓库信任、运行时可用性或有效沙箱策略。",
    },
];

fn dict<'a>(node: &Node<'a>) -> Result<BTreeMap<&'a str, Node<'a>>> {
    let mut result = BTreeMap::new();
    for row in node.children(4096)? {
        let columns = row.children(2)?;
        let key = columns.first().ok_or("missing GVariant dictionary key")?.string()?;
        if key.len() > 4096 {
            return Err("GVariant dictionary key exceeds the profile".into());
        }
        let value = columns.get(1).ok_or("missing GVariant dictionary value")?.variant()?;
        if result.insert(key, value).is_some() {
            return Err("duplicate GVariant dictionary key".into());
        }
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
    if count != 0 {
        output.push(ALPHABET[((bits << (6 - count)) & 63) as usize] as char);
    }
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
    if bytes.len() > MAX_BUNDLE {
        return Err("Flatpak bundle exceeds the 256 MiB input profile".into());
    }
    let root = Node::new(bytes, SUPER)?;
    let fields = root.children(8)?;
    let dictionary = dict(fields.first().ok_or("missing bundle metadata")?)?;
    let reference_node = dictionary.get("ref").ok_or("bundle has no Flatpak ref")?;
    if reference_node.ty != variant::Type::Basic(b's') {
        return Err("Flatpak ref has an unsupported GVariant type".into());
    }
    let reference = reference_node.string()?;
    let parts: Vec<_> = reference.split('/').collect();
    if parts.len() != 4
        || !matches!(parts[0], "app" | "runtime")
        || parts.iter().any(|part| {
            part.is_empty() || part.len() > 256 || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
    {
        return Err("Flatpak ref is outside the supported four-component profile".into());
    }
    root.validate(&mut Budget::default(), 0)?;
    let to = checksum(fields.get(3).ok_or("missing target commit checksum")?.bytes()?)?;
    let commit = fields.get(4).ok_or("missing target commit object")?.clone();
    if digest(commit.data) != to {
        return Err("embedded commit digest differs from the target commit declaration".into());
    }
    let endian = dictionary.get("ostree.endianness");
    if endian.is_some_and(|node| node.ty != variant::Type::Basic(b'y')) {
        return Err("delta endianness is not a byte declaration".into());
    }
    let little = match endian.map(|node| node.number(true)).transpose()? {
        Some(value) if value == u64::from(b'l') => Some(true),
        Some(value) if value == u64::from(b'B') => Some(false),
        _ => None,
    };
    let metadata = dictionary.get("metadata").cloned();
    if let Some(metadata) = &metadata {
        if metadata.ty != variant::Type::Basic(b's') {
            return Err("application metadata has an unsupported GVariant type".into());
        }
        metadata.string()?;
    }
    Ok(Header { reference, metadata, commit, to, fields, dictionary, little })
}

fn decode_part(raw: &[u8]) -> Result<Vec<u8>> {
    decode_part_with_budget(raw, &mut Budget::default())
}

fn decode_part_with_budget(raw: &[u8], budget: &mut Budget) -> Result<Vec<u8>> {
    let (&compression, body) = raw.split_first().ok_or("empty inline part")?;
    if raw.len() > MAX_PART {
        return Err("compressed part exceeds the 64 MiB profile".into());
    }
    let bytes = match compression {
        0 => body.to_vec(),
        b'x' => {
            if !body.starts_with(b"\xfd7zXZ\0") {
                return Err("XZ part lacks the XZ stream signature".into());
            }
            let cursor = Cursor::new(body);
            let mut reader = lzma_bounded::XzReader::new_mem_limit(cursor, false, 100 * 1024);
            let mut bytes = Vec::new();
            reader.by_ref().take(MAX_PART as u64 + 1).read_to_end(&mut bytes).map_err(|error| format!("bounded XZ part: {error}"))?;
            if bytes.len() > MAX_PART {
                return Err("decoded part exceeds the 64 MiB profile".into());
            }
            if reader.into_inner().position() != body.len() as u64 {
                return Err("XZ part has unread trailing bytes".into());
            }
            bytes
        }
        _ => return Err(format!("unsupported inline-part compression byte {compression}")),
    };
    let node = Node::new(&bytes, PAYLOAD)?;
    node.validate(budget, 0)?;
    Ok(bytes)
}

fn part_name(index: usize) -> String {
    format!("parts/{index}.flatpak-part")
}

struct Object {
    kind: u8,
    checksum: [u8; 32],
    part: usize,
    offset: usize,
    size: usize,
    mode: Option<u32>,
    xattrs: usize,
    xattr_count: usize,
}

struct DecodedPart<'a> {
    index: usize,
    raw: Node<'a>,
    bytes: Vec<u8>,
    objects: usize,
    verified_objects: usize,
    complete: bool,
}

struct File {
    path: String,
    checksum: [u8; 32],
    object: usize,
    target: Option<String>,
    declaration_part: usize,
    declaration_offset: usize,
    declaration_length: usize,
}

struct Bundle<'a> {
    header: Header<'a>,
    parts: Vec<DecodedPart<'a>>,
    objects: Vec<Object>,
    files: Vec<File>,
    directories: Vec<Value>,
    issues: Vec<String>,
    complete: bool,
    checksum_work: usize,
    seen_objects: BTreeSet<(u8, [u8; 32])>,
}

fn varuint(bytes: &[u8], at: &mut usize) -> Result<usize> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes.get(*at).ok_or("static-delta operand is truncated")?;
        *at += 1;
        if index == 9 && byte > 1 {
            return Err("static-delta operand overflows 64 bits".into());
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if index > 0 && byte == 0 {
                return Err("overlong static-delta operand".into());
            }
            return usize::try_from(value).map_err(|_| "static-delta operand exceeds the address space".into());
        }
    }
    Err("static-delta operand is too long".into())
}

impl Bundle<'_> {
    fn issue(&mut self, detail: impl Into<String>) {
        self.complete = false;
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(detail.into());
        }
    }

    fn contents(&mut self) -> Result<()> {
        if !self.header.fields[2].bytes()?.is_empty() {
            return Err("nonempty base commits require external objects and are outside this profile".into());
        }
        if !self.header.fields[5].bytes()?.is_empty() {
            return Err("recursive delta parents are outside this profile".into());
        }
        if !self.header.fields[7].children(MAX_OBJECTS)?.is_empty() {
            return Err("fallback objects are not captured inline and are outside this profile".into());
        }
        let little = self.header.little.ok_or("delta endianness is missing or unsupported; host byte order is never assumed")?;
        let headers = self.header.fields[6].children(MAX_PARTS)?;
        let base64 = modified_base64(&self.header.to);
        let mut total = 0usize;
        let mut budget = Budget::default();
        for (index, row) in headers.iter().enumerate() {
            let fields = row.children(5)?;
            if fields[0].number(little)? != 0 {
                self.issue(format!("part {index}: unsupported part version"));
                continue;
            }
            let key = format!("deltas/{}/{}/{index}", &base64[..2], &base64[2..]);
            let Some(raw) = self.header.dictionary.get(key.as_str()).cloned() else {
                self.issue(format!("part {index}: missing inline payload"));
                continue;
            };
            if raw.ty != variant::signature("(yay)")? {
                self.issue(format!("part {index}: unsupported inline value type"));
                continue;
            }
            if fields[2].number(little)? != raw.data.len() as u64 {
                self.issue(format!("part {index}: compressed-size declaration differs from captured bytes"));
                continue;
            }
            if digest(raw.data) != checksum(fields[1].bytes()?)? {
                self.issue(format!("part {index}: inline payload digest mismatch"));
                continue;
            }
            let bytes = match decode_part_with_budget(raw.data, &mut budget) {
                Ok(bytes) => bytes,
                Err(detail) => {
                    self.issue(format!("part {index}: {detail}"));
                    continue;
                }
            };
            total = total.checked_add(bytes.len()).ok_or("decoded-part byte total overflow")?;
            if total > MAX_TOTAL {
                return Err("decoded-part total exceeds the 256 MiB profile".into());
            }
            let objects = fields[4].bytes()?;
            if objects.len() % 33 != 0 {
                self.issue(format!("part {index}: object descriptors are not a multiple of 33 bytes"));
                continue;
            }
            if self.objects.len().saturating_add(objects.len() / 33) > MAX_OBJECTS {
                return Err("static-delta object budget exhausted".into());
            }
            let part_slot = self.parts.len();
            self.parts.push(DecodedPart { index, raw, bytes, objects: objects.len() / 33, verified_objects: 0, complete: false });
            let verified_before = self.objects.len();
            match self.read_objects(part_slot, objects) {
                Ok(()) => self.parts[part_slot].complete = true,
                Err(detail) => self.issue(format!("part {index}: {detail}")),
            }
            self.parts[part_slot].verified_objects = self.objects.len() - verified_before;
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
            if ops.get(at) != Some(&b'S') {
                return Err("only complete literal S objects are supported; another or missing opcode remains unread".into());
            }
            at += 1;
            let kind = descriptor[0];
            let checksum = checksum(&descriptor[1..])?;
            if !self.seen_objects.insert((kind, checksum)) {
                return Err("duplicate object identity in the delta records".into());
            }
            let (mode, attrs, mode_values) = if kind == 1 {
                let mode = varuint(ops, &mut at)?;
                let attrs = varuint(ops, &mut at)?;
                let mode = modes.get(mode).ok_or("file mode-table index is outside its table")?.children(3)?;
                if attrs >= xattrs.len() {
                    return Err("file xattr-table index is outside its table".into());
                }
                (Some(u32::try_from(mode[2].number(false)?).map_err(|_| "file mode exceeds 32 bits")?), attrs, Some(mode))
            } else if (2..=6).contains(&kind) {
                (None, 0, None)
            } else {
                return Err(format!("unsupported OSTree object type {kind}"));
            };
            let length = varuint(ops, &mut at)?;
            let offset = varuint(ops, &mut at)?;
            let data = crate::extent(blob, offset, length)?;
            let attribute_bytes = if kind == 1 { xattrs[attrs].data.len() } else { 0 };
            self.checksum_work = self.checksum_work.saturating_add(length).saturating_add(attribute_bytes);
            if self.checksum_work > MAX_TOTAL {
                return Err("cumulative object checksum work exceeds the 256 MiB profile".into());
            }
            if kind != 1 && digest(data) != checksum {
                return Err("metadata object digest mismatch".into());
            }
            if let Some(mode_values) = mode_values {
                let actual = content_checksum(&mode_values, &xattrs[attrs], data)?;
                if actual != checksum {
                    return Err("content object digest mismatch".into());
                }
            }
            self.objects.push(Object {
                kind,
                checksum,
                part: slot,
                offset: fields[2].offset + offset,
                size: length,
                mode,
                xattrs: attrs,
                xattr_count: if kind == 1 { xattrs[attrs].children(4096)?.len() } else { 0 },
            });
        }
        if at != ops.len() {
            return Err("operation stream has trailing or unmatched operations".into());
        }
        Ok(())
    }

    fn resolve_tree(&mut self) -> Result<()> {
        let mut map = BTreeMap::new();
        for (index, object) in self.objects.iter().enumerate() {
            if map.insert((object.kind, object.checksum), index).is_some() {
                return Err("duplicate object identities prevent unambiguous path binding".into());
            }
        }
        let commit = self.header.commit.children(8)?;
        let root_tree = checksum(commit[6].bytes()?)?;
        let root_meta = checksum(commit[7].bytes()?)?;
        let mut pending = vec![(String::new(), root_tree, root_meta, BTreeSet::new())];
        let mut queue_bytes = 128usize;
        let mut paths = BTreeSet::new();
        let mut names = 0usize;
        let mut budget = Budget::default();
        while let Some((path, tree_hash, meta_hash, mut ancestors)) = pending.pop() {
            queue_bytes = queue_bytes.saturating_sub(128 + path.len() + ancestors.len() * 64);
            if ancestors.len() >= 128 || !ancestors.insert(tree_hash) {
                return Err("OSTree directory cycle or depth budget exhausted".into());
            }
            let tree_index = *map.get(&(2, tree_hash)).ok_or("directory-tree object is missing from captured parts")?;
            let meta_index = *map.get(&(3, meta_hash)).ok_or("directory-metadata object is missing from captured parts")?;
            let metadata = self.object_node(meta_index, "(uuua(ayay))")?;
            metadata.validate(&mut budget, 0)?;
            let declarations = metadata.children(4)?;
            let mode = declarations[2].number(false)?;
            self.directories.push(
                json!({"path": path, "tree_checksum": hex::encode(tree_hash), "metadata_checksum": hex::encode(meta_hash), "mode": mode,
                    "uid": declarations[0].number(false)?, "gid": declarations[1].number(false)?, "xattr_count": declarations[3].children(4096)?.len()}),
            );
            if self.directories.len() > MAX_OBJECTS {
                return Err("OSTree directory budget exhausted".into());
            }
            let mut files = Vec::new();
            let mut file_issues = Vec::new();
            let result = (|| -> Result<()> {
                let tree = self.object_node(tree_index, "(a(say)a(sayay))")?;
                tree.validate(&mut budget, 0)?;
                let lists = tree.children(2)?;
                for row in lists[0].children(MAX_OBJECTS)? {
                    let columns = row.children(2)?;
                    let name = columns[0].string()?;
                    let path = child_path(&path, name)?;
                    names = names.saturating_add(path.len());
                    if names > crate::MAX_METADATA || paths.len() >= MAX_OBJECTS || !paths.insert(path.clone()) {
                        return Err("OSTree path budget exhausted or duplicate path declaration".into());
                    }
                    // A file's missing object or unsupported declaration does not make
                    // independently named siblings or queued directories unreadable.
                    let resolved = (|| -> Result<_> {
                        let checksum = checksum(columns[1].bytes()?)?;
                        let object = *map.get(&(1, checksum)).ok_or("file object is missing from captured parts")?;
                        let target = if self.objects[object].mode.is_some_and(|mode| mode & 0o170000 == 0o120000) {
                            let data = self.object_bytes(object)?;
                            if data.len() > 4096 {
                                return Err("symlink target exceeds the 4096-byte declaration profile".into());
                            }
                            let target = std::str::from_utf8(data).map_err(|_| "symlink target is not UTF-8")?;
                            if target.contains('\0') {
                                return Err("symlink target contains NUL".into());
                            }
                            Some(aa_core::text::redact_sensitive_text(target).map_err(str::to_string)?)
                        } else if self.objects[object].mode.is_some_and(|mode| mode & 0o170000 == 0o100000) {
                            None
                        } else {
                            return Err("special file mode is outside the payload profile".into());
                        };
                        Ok((checksum, object, target))
                    })();
                    let (checksum, object, target) = match resolved {
                        Ok(file) => file,
                        Err(detail) => {
                            if file_issues.len() < MAX_ISSUES {
                                file_issues.push(format!("file {path:?}: {detail}"));
                            }
                            continue;
                        }
                    };
                    files.push(File {
                        path,
                        checksum,
                        object,
                        target,
                        declaration_part: self.objects[tree_index].part,
                        declaration_offset: columns[0].offset,
                        declaration_length: columns[0].data.len(),
                    });
                    if self.files.len().saturating_add(files.len()) > MAX_OBJECTS {
                        return Err("OSTree file budget exhausted".into());
                    }
                }
                for row in lists[1].children(MAX_OBJECTS)? {
                    let columns = row.children(3)?;
                    let child = child_path(&path, columns[0].string()?)?;
                    names = names.saturating_add(child.len());
                    if names > crate::MAX_METADATA || paths.len() >= MAX_OBJECTS || !paths.insert(child.clone()) {
                        return Err("OSTree path budget exhausted or duplicate directory declaration".into());
                    }
                    queue_bytes = queue_bytes.saturating_add(128 + child.len() + ancestors.len() * 64);
                    if queue_bytes > crate::MAX_METADATA {
                        return Err("OSTree directory queue exceeds the 16 MiB metadata profile".into());
                    }
                    pending.push((child, checksum(columns[1].bytes()?)?, checksum(columns[2].bytes()?)?, ancestors.clone()));
                }
                Ok(())
            })();
            self.files.extend(files);
            for detail in file_issues {
                self.issue(detail);
            }
            result?;
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
    if name.is_empty() || name.len() > 4096 || name.contains(['/', '\\', '\0']) || matches!(name, "." | "..") {
        return Err("OSTree filename is outside the safe UTF-8 leaf-name profile".into());
    }
    let path = if parent.is_empty() { name.to_string() } else { format!("{parent}/{name}") };
    if path.len() > 4096 {
        return Err("OSTree path exceeds the 4096-byte profile".into());
    }
    Ok(path)
}

fn content_checksum(modes: &[Node<'_>], xattrs: &Node<'_>, content: &[u8]) -> Result<[u8; 32]> {
    let mode = modes[2].number(false)?;
    let symlink = mode & 0o170000 == 0o120000;
    if !symlink && mode & 0o170000 != 0o100000 {
        return Err("content object has an unsupported file mode".into());
    }
    let mut target = Vec::new();
    if symlink {
        if content.len() > 4096 || content.contains(&0) {
            return Err("symlink target is outside the bounded non-NUL profile".into());
        }
        target.extend_from_slice(content);
    }
    target.push(0);
    let mut attributes = BTreeMap::new();
    for attribute in xattrs.children(4096)? {
        let values = attribute.children(2)?;
        let name = values[0].bytes()?;
        if name.len() > 4096 || values[1].bytes()?.len() > 1024 * 1024 {
            return Err("extended attribute exceeds the bounded checksum profile".into());
        }
        if attributes.insert(name.to_vec(), attribute.data.to_vec()).is_some() {
            return Err("duplicate extended attribute names".into());
        }
    }
    let attrs = variant::encode_array("(ayay)", &attributes.values().map(Vec::as_slice).collect::<Vec<_>>())?;
    let zero = [0; 4];
    let header = variant::encode_tuple(&[
        ("u", modes[0].data),
        ("u", modes[1].data),
        ("u", modes[2].data),
        ("u", &zero),
        ("s", &target),
        ("a(ayay)", &attrs),
    ])?;
    let mut hash = Sha256::new();
    hash.update(u32::try_from(header.len()).map_err(|_| "OSTree checksum header exceeds 32 bits")?.to_be_bytes());
    hash.update([0; 4]);
    hash.update(header);
    if !symlink {
        hash.update(content);
    }
    Ok(hash.finalize().into())
}

fn bundle(bytes: &[u8]) -> Result<Bundle<'_>> {
    let header = header(bytes)?;
    let mut bundle = Bundle {
        header,
        parts: Vec::new(),
        objects: Vec::new(),
        files: Vec::new(),
        directories: Vec::new(),
        issues: Vec::new(),
        complete: true,
        checksum_work: 0,
        seen_objects: BTreeSet::new(),
    };
    if let Err(detail) = bundle.contents() {
        bundle.issue(detail);
    }
    bundle.files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(bundle)
}

fn add(sink: &mut dyn UnpackSink, path: &str, bytes: &[u8]) -> bool {
    match sink.add(path, &mut Cursor::new(bytes)) {
        Ok(()) => true,
        Err(SinkError::LimitReached) => false,
        Err(SinkError::Read(detail)) => {
            sink.limitation("flatpak.contents-unread", Some(detail));
            false
        }
    }
}

impl Unpacker for Flatpak {
    fn id(&self) -> &'static str {
        "flatpak"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let candidate = file.extension().as_deref() == Some("flatpak") || bytes.starts_with(b"OSTSGNDT") || bytes.starts_with(b"TDNGSTSO");
        let parsed = match bundle(bytes) {
            Ok(parsed) => parsed,
            Err(detail) => return if candidate { Unpack::Failed { kind: "flatpak", detail } } else { Unpack::NotMine },
        };
        if let Some(metadata) = &parsed.header.metadata {
            match metadata.string() {
                Ok(text) => {
                    if !add(sink, "declared-metadata.ini", text.as_bytes()) {
                        return Unpack::Done { kind: "flatpak" };
                    }
                }
                Err(detail) => sink.limitation("flatpak.metadata-unread", Some(detail)),
            }
        }
        let base64 = modified_base64(&parsed.header.to);
        let headers = match parsed.header.fields[6].children(MAX_PARTS) {
            Ok(headers) => headers,
            Err(detail) => {
                sink.limitation("flatpak.contents-unread", Some(detail));
                return Unpack::Done { kind: "flatpak" };
            }
        };
        let part_type = variant::signature("(yay)").expect("fixed valid part signature");
        for (index, _) in headers.iter().enumerate() {
            let key = format!("deltas/{}/{}/{index}", &base64[..2], &base64[2..]);
            if let Some(part) = parsed.header.dictionary.get(key.as_str())
                && part.ty == part_type
                && !add(sink, &part_name(index), part.data)
            {
                return Unpack::Done { kind: "flatpak" };
            }
        }
        for file in &parsed.files {
            if file.target.is_none() {
                match parsed.object_bytes(file.object) {
                    Ok(bytes) => {
                        if !add(sink, &format!("root/{}", file.path), bytes) {
                            break;
                        }
                    }
                    Err(detail) => sink.limitation("flatpak.contents-unread", Some(detail)),
                }
            }
        }
        for issue in parsed.issues {
            sink.limitation("flatpak.contents-unread", Some(issue));
        }
        Unpack::Done { kind: "flatpak" }
    }
}

impl Unpacker for Part {
    fn id(&self) -> &'static str {
        "flatpak-part"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if file.extension().as_deref() != Some("flatpak-part") || file.parent.is_none() {
            return Unpack::NotMine;
        }
        match decode_part(bytes) {
            Ok(bytes) => {
                add(sink, "decoded", &bytes);
                Unpack::Done { kind: "flatpak-part" }
            }
            Err(detail) => Unpack::Failed { kind: "flatpak-part", detail },
        }
    }
}

impl Analyzer for Flatpak {
    fn id(&self) -> &'static str {
        "flatpak"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("flatpak") && file.extension().as_deref() != Some("flatpak") {
            return;
        }
        let parsed = tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| retain(tree, file, &bytes, out));
        if let Err(detail) = parsed {
            out.limitation("flatpak.bundle-unread", Some(file), Some(detail));
        }
    }
}

fn retain(tree: &dyn Tree, file: &Artifact, bytes: &[u8], out: &mut Output) -> Result<()> {
    let bundle = bundle(bytes)?;
    let reference = aa_core::text::redact_sensitive_text(bundle.header.reference).map_err(str::to_string)?;
    let parts: Vec<_> = bundle.parts.iter().map(|part| json!({"index": part.index, "source_offset": part.raw.offset, "source_length": part.raw.data.len(),
        "artifact": format!("{}/{}", file.path, part_name(part.index)), "decoded_artifact": format!("{}/{}/decoded", file.path, part_name(part.index)),
        "sha256": aa_core::sha256_hex(part.raw.data), "decoded_sha256": aa_core::sha256_hex(&part.bytes), "decoded_size": part.bytes.len(),
        "declared_objects": part.objects, "verified_objects": part.verified_objects, "complete": part.complete})).collect();
    let entries: Vec<_> = bundle.files.iter().map(|entry| {
        let object = &bundle.objects[entry.object];
        let part = &bundle.parts[object.part];
        let decoded_path = format!("{}/{}/decoded", file.path, part_name(part.index));
        let captured_path = format!("{}/root/{}", file.path, entry.path);
        let captured = entry.target.is_none() && tree.get(&captured_path).is_some_and(|artifact| artifact.size == object.size as u64
            && !artifact.facts.get("engine.entry-name").and_then(|value| value.get("colliding")).and_then(Value::as_bool).unwrap_or(false));
        let declaration_part = &bundle.parts[entry.declaration_part];
        let declaration_source = format!("{}/{}/decoded", file.path, part_name(declaration_part.index));
        json!({"path": entry.path, "object_checksum": hex::encode(entry.checksum), "object_label_verified": true,
            "mode": object.mode, "xattr_index": object.xattrs, "xattr_count": object.xattr_count, "link_target": entry.target, "size": object.size,
            "part": part.index, "source": tree.get(&decoded_path).map(|artifact| &artifact.path), "offset": object.offset,
            "bundle_source": {"artifact": file.path, "offset": part.raw.offset, "length": part.raw.data.len(), "decoded_offset": object.offset},
            "declaration": {"part": declaration_part.index, "source": tree.get(&declaration_source).map(|artifact| &artifact.path), "offset": entry.declaration_offset, "length": entry.declaration_length,
                "bundle_source": {"artifact": file.path, "offset": declaration_part.raw.offset, "length": declaration_part.raw.data.len(), "decoded_offset": entry.declaration_offset}},
            "captured": captured, "captured_path": captured.then_some(captured_path)})
    }).collect();
    let identity: Vec<_> = reference.split('/').collect();
    let regular_files = bundle.files.iter().filter(|entry| entry.target.is_none()).count();
    let captured_files = entries.iter().filter(|entry| entry["captured"] == true).count();
    let captured_names: BTreeSet<_> =
        entries.iter().filter(|entry| entry["captured"] == true).filter_map(|entry| entry["path"].as_str()).collect();
    let capture_complete = captured_files == regular_files;
    out.fact(file, "flatpak.bundle", json!({"reference": reference, "name": identity[1], "architecture": identity[2], "branch": identity[3], "kind": identity[0],
        "commit": hex::encode(bundle.header.to), "complete": bundle.complete, "parts": parts, "entries": entries, "directories": bundle.directories,
        "profile": "empty-base-inline-v0-literal", "regular_files": regular_files, "captured_files": captured_files, "capture_complete": capture_complete,
        "content_object_labels_verified": true, "signature_verified": false}));
    out.kind(file, "flatpak");
    out.finding(
        Finding::new(Section::Identity, "flatpak", "flatpak.identity", Confidence::Verified, Severity::Info)
            .param("reference", reference.as_str())
            .evidence(Evidence::bytes(
                file,
                bundle.header.dictionary["ref"].offset as u64,
                bundle.header.dictionary["ref"].data.len() as u64,
                json!({"reference": reference}),
            ))
            .evidence(Evidence::bytes(
                file,
                bundle.header.commit.offset as u64,
                bundle.header.commit.data.len() as u64,
                json!({"commit": hex::encode(bundle.header.to)}),
            )),
    );
    out.limitation("flatpak.integrity-unverified", Some(file), None);
    for issue in &bundle.issues {
        out.limitation("flatpak.contents-unread", Some(file), Some(issue.clone()));
    }
    if !capture_complete {
        out.limitation(
            "flatpak.contents-unread",
            Some(file),
            Some("some reconstructed regular files were not retained as unambiguous artifacts".into()),
        );
    }
    if captured_files > 0 {
        let mut finding = Finding::new(Section::Composition, "flatpak", "flatpak.contents", Confidence::Derived, Severity::Info)
            .param("count", captured_files);
        for entry in bundle.files.iter().filter(|entry| captured_names.contains(entry.path.as_str())).take(5) {
            let object = &bundle.objects[entry.object];
            let part = &bundle.parts[object.part];
            let path = format!("{}/{}/decoded", file.path, part_name(part.index));
            let value = json!({"path": entry.path, "part": part.index, "decoded_offset": object.offset, "length": object.size, "object_checksum": hex::encode(entry.checksum)});
            finding = finding.evidence(if let Some(decoded) = tree.get(&path) {
                Evidence::bytes(decoded, object.offset as u64, object.size as u64, value)
            } else {
                Evidence::bytes(file, part.raw.offset as u64, part.raw.data.len() as u64, value)
            });
            let declaration_part = &bundle.parts[entry.declaration_part];
            let declaration_source = format!("{}/{}/decoded", file.path, part_name(declaration_part.index));
            let value = json!({"path": entry.path, "part": declaration_part.index, "decoded_offset": entry.declaration_offset, "role": "directory filename declaration"});
            finding = finding.evidence(if let Some(decoded) = tree.get(&declaration_source) {
                Evidence::bytes(decoded, entry.declaration_offset as u64, entry.declaration_length as u64, value)
            } else {
                Evidence::bytes(file, declaration_part.raw.offset as u64, declaration_part.raw.data.len() as u64, value)
            });
        }
        out.finding(finding);
    }
    if bundle.files.iter().any(|entry| entry.target.is_some())
        || bundle.objects.iter().any(|object| object.xattr_count != 0)
        || bundle.directories.iter().any(|entry| entry["xattr_count"].as_u64().unwrap_or(0) != 0)
    {
        out.limitation("flatpak.link-semantics", Some(file), None);
    }
    if let Some(metadata) = &bundle.header.metadata {
        let text = metadata.string()?;
        match application_metadata(text) {
            Ok(fields) => {
                let declared_name = fields
                    .iter()
                    .find(|field| matches!(field["group"].as_str(), Some("Application" | "Runtime")) && field["name"] == "name")
                    .and_then(|field| field["value"].as_str());
                if declared_name.is_none() {
                    out.limitation(
                        "flatpak.metadata-unread",
                        Some(file),
                        Some("application metadata has no supported name declaration".into()),
                    );
                } else if declared_name.is_some_and(|name| name != identity[1]) {
                    out.limitation(
                        "flatpak.metadata-unread",
                        Some(file),
                        Some("application metadata name differs from the bundle ref identity".into()),
                    );
                }
                out.fact(
                    file,
                    "flatpak.application",
                    json!({"source": file.path, "offset": metadata.offset, "length": metadata.data.len(), "fields": fields}),
                );
                if fields.iter().any(|field| {
                    matches!(field["group"].as_str(), Some("Context" | "Session Bus Policy" | "System Bus Policy"))
                        || (matches!(field["group"].as_str(), Some("Application" | "Runtime"))
                            && matches!(field["name"].as_str(), Some("runtime" | "sdk" | "command")))
                }) {
                    out.finding(
                        Finding::new(Section::Capabilities, "flatpak", "flatpak.permissions", Confidence::Verified, Severity::Info)
                            .evidence(Evidence::bytes(
                                file,
                                metadata.offset as u64,
                                metadata.data.len() as u64,
                                json!({"declarations": fields}),
                            )),
                    );
                }
            }
            Err(detail) => out.limitation("flatpak.metadata-unread", Some(file), Some(detail)),
        }
        if let Some(captured) = bundle.files.iter().find(|entry| entry.path == "metadata" && entry.target.is_none())
            && bundle.object_bytes(captured.object)? != text.as_bytes()
        {
            out.limitation(
                "flatpak.metadata-unread",
                Some(file),
                Some("superblock application metadata differs from the captured metadata file".into()),
            );
        }
    } else {
        out.limitation("flatpak.metadata-unread", Some(file), Some("no application metadata string in the bundle superblock".into()));
    }
    Ok(())
}

fn application_metadata(text: &str) -> Result<Vec<Value>> {
    if text.len() > 256 * 1024 || text.contains('\0') {
        return Err("application metadata is outside the 256 KiB UTF-8 profile".into());
    }
    let mut group = String::new();
    let mut seen = BTreeSet::new();
    let mut fields = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.len() > 16 * 1024 || fields.len() >= 4096 {
            return Err("application metadata line or field budget exhausted".into());
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|line| line.strip_suffix(']')) {
            if name.is_empty() || name.len() > 256 {
                return Err("invalid application metadata group".into());
            }
            group = name.to_string();
        } else {
            let (key, value) = line.split_once('=').ok_or("application metadata has an unsupported non-assignment line")?;
            let key = key.trim();
            if group.is_empty() || key.is_empty() || key.len() > 256 || !seen.insert((group.clone(), key.to_string())) {
                return Err("application metadata has missing groups or duplicate keys".into());
            }
            let value = aa_core::text::redact_named_value(key, value.trim()).map_err(str::to_string)?;
            fields.push(json!({"group": group, "name": key, "value": value, "line": index + 1, "recognized_group": matches!(group.as_str(), "Application" | "Runtime" | "Context" | "Session Bus Policy" | "System Bus Policy")}));
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;

    fn tuple(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
        variant::encode_tuple(&fields.iter().map(|(ty, bytes)| (*ty, bytes.as_slice())).collect::<Vec<_>>())
            .expect("encode constructed tuple")
    }

    fn array(ty: &str, values: &[Vec<u8>]) -> Vec<u8> {
        variant::encode_array(ty, &values.iter().map(Vec::as_slice).collect::<Vec<_>>()).expect("encode constructed array")
    }

    fn string(text: &str) -> Vec<u8> {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }
    fn value(ty: &str, mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.push(0);
        bytes.extend_from_slice(ty.as_bytes());
        bytes
    }
    fn pair(key: &str, ty: &str, bytes: Vec<u8>) -> Vec<u8> {
        tuple(&[("s", string(key)), ("v", value(ty, bytes))])
    }

    fn operand(mut number: usize, bytes: &mut Vec<u8>) {
        loop {
            let byte = (number & 127) as u8;
            number >>= 7;
            bytes.push(byte | if number == 0 { 0 } else { 128 });
            if number == 0 {
                return;
            }
        }
    }

    #[derive(Default)]
    struct Options {
        base: bool,
        fallback: bool,
        opcode: Option<u8>,
        version: u32,
        bad_part_digest: bool,
        bad_content_digest: bool,
        missing_file: bool,
        missing_first_file: bool,
        duplicate_path: bool,
        duplicate_metadata: bool,
        unsafe_name: bool,
    }

    const APP: &str = "[Application]\nname=org.example.Fixture\nruntime=org.example.Runtime/x86_64/1\ncommand=inert\n[Context]\nshared=network;\nfilesystems=home:ro;\n";

    fn fixture(options: Options) -> Vec<u8> {
        let modes = [0o100644u32, 0o120777].map(|mode| {
            tuple(&[("u", 0u32.to_be_bytes().to_vec()), ("u", 0u32.to_be_bytes().to_vec()), ("u", mode.to_be_bytes().to_vec())])
        });
        let attrs = Node::new(&[], "a(ayay)").expect("empty attribute array");
        let contents = [APP.as_bytes(), b"payload-data\n", b"payload.txt"];
        let mut hashes = Vec::new();
        for (index, content) in contents.iter().enumerate() {
            let mode = Node::new(&modes[usize::from(index == 2)], "(uuu)").expect("mode tuple").children(3).expect("mode columns");
            hashes.push(content_checksum(&mode, &attrs, content).expect("canonical content label"));
        }
        let mut names = ["metadata", "payload.txt", "alias"];
        if options.duplicate_path {
            names[2] = "payload.txt";
        }
        if options.unsafe_name {
            names[2] = "../outside";
        }
        let files: Vec<_> =
            names.iter().zip(&hashes).map(|(name, checksum)| tuple(&[("s", string(name)), ("ay", checksum.to_vec())])).collect();
        let tree = tuple(&[("a(say)", array("(say)", &files)), ("a(sayay)", Vec::new())]);
        let metadata = tuple(&[
            ("u", 0u32.to_be_bytes().to_vec()),
            ("u", 0u32.to_be_bytes().to_vec()),
            ("u", 0o40755u32.to_be_bytes().to_vec()),
            ("a(ayay)", Vec::new()),
        ]);
        let commit = tuple(&[
            ("a{sv}", Vec::new()),
            ("ay", Vec::new()),
            ("a(say)", Vec::new()),
            ("s", string("inert")),
            ("s", string("")),
            ("t", 0u64.to_be_bytes().to_vec()),
            ("ay", digest(&tree).to_vec()),
            ("ay", digest(&metadata).to_vec()),
        ]);
        let to = digest(&commit);
        let mut descriptors = Vec::new();
        let mut blob = Vec::new();
        let mut ops = Vec::new();
        for (kind, body, checksum, mode) in [
            (3, metadata.as_slice(), digest(&metadata), None),
            (2, tree.as_slice(), digest(&tree), None),
            (1, contents[0], hashes[0], Some(0)),
            (1, contents[1], hashes[1], Some(0)),
            (1, contents[2], hashes[2], Some(1)),
        ] {
            if kind == 1 && (options.missing_file && body == contents[1] || options.missing_first_file && body == contents[0]) {
                continue;
            }
            descriptors.push(kind);
            descriptors.extend_from_slice(&checksum);
            ops.push(options.opcode.unwrap_or(b'S'));
            if let Some(mode) = mode {
                operand(mode, &mut ops);
                operand(0, &mut ops);
            }
            operand(body.len(), &mut ops);
            operand(blob.len(), &mut ops);
            blob.extend_from_slice(body);
        }
        if options.bad_content_digest {
            let offset = blob.len() - contents[2].len() - contents[1].len();
            blob[offset] ^= 1;
        }
        let payload =
            tuple(&[("a(uuu)", array("(uuu)", &modes)), ("aa(ayay)", array("a(ayay)", &[Vec::new()])), ("ay", blob), ("ay", ops)]);
        let mut part = vec![0];
        part.extend(payload);
        let mut part_digest = digest(&part);
        if options.bad_part_digest {
            part_digest[0] ^= 1;
        }
        let part_header = tuple(&[
            ("u", options.version.to_le_bytes().to_vec()),
            ("ay", part_digest.to_vec()),
            ("t", (part.len() as u64).to_le_bytes().to_vec()),
            ("t", 1024u64.to_le_bytes().to_vec()),
            ("ay", descriptors),
        ]);
        let base64 = modified_base64(&to);
        let key = format!("deltas/{}/{}/0", &base64[..2], &base64[2..]);
        let mut fields = vec![
            pair("ref", "s", string("app/org.example.Fixture/x86_64/stable")),
            pair("metadata", "s", string(APP)),
            pair("ostree.endianness", "y", vec![b'l']),
            pair(&key, "(yay)", part),
        ];
        if options.duplicate_metadata {
            fields.push(pair("ref", "s", string("app/org.example.Other/x86_64/stable")));
        }
        let fallback = if options.fallback {
            array(
                "(yaytt)",
                &[tuple(&[("y", vec![1]), ("ay", vec![1; 32]), ("t", 1u64.to_le_bytes().to_vec()), ("t", 1u64.to_le_bytes().to_vec())])],
            )
        } else {
            Vec::new()
        };
        tuple(&[
            ("a{sv}", array("{sv}", &fields)),
            ("t", 0u64.to_be_bytes().to_vec()),
            ("ay", if options.base { vec![1; 32] } else { Vec::new() }),
            ("ay", to.to_vec()),
            ("(a{sv}aya(say)sstayay)", commit),
            ("ay", Vec::new()),
            ("a(uayttay)", array("(uayttay)", &[part_header])),
            ("a(yaytt)", fallback),
        ])
    }

    fn artifact(path: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: bytes.len() as u64,
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
        limits: Vec<String>,
        stop: bool,
    }
    impl UnpackSink for Sink {
        fn add(&mut self, path: &str, data: &mut dyn Read) -> std::result::Result<(), SinkError> {
            if self.stop {
                return Err(SinkError::LimitReached);
            }
            let mut bytes = Vec::new();
            data.read_to_end(&mut bytes).expect("read controlled output");
            self.files.insert(path.into(), bytes);
            Ok(())
        }
        fn limitation(&mut self, code: &str, detail: Option<String>) {
            self.limits.push(format!("{code}: {}", detail.unwrap_or_default()));
        }
    }

    struct TestTree {
        files: Vec<Artifact>,
        bytes: BTreeMap<String, Vec<u8>>,
    }
    impl Tree for TestTree {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.bytes.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }
    }

    #[test]
    fn literal_bundle_reconstructs_payload_with_checked_object_labels_and_real_source_spans() {
        let bytes = fixture(Options::default());
        let parsed = bundle(&bytes).expect("constructed bundle");
        assert!(parsed.complete, "{:?}", parsed.issues);
        assert_eq!(parsed.objects.len(), 5);
        assert_eq!(parsed.files.len(), 3);
        let payload = parsed.files.iter().find(|entry| entry.path == "payload.txt").expect("named file");
        assert_eq!(parsed.object_bytes(payload.object).expect("source slice"), b"payload-data\n");
        let declaration = &parsed.parts[payload.declaration_part].bytes
            [payload.declaration_offset..payload.declaration_offset + payload.declaration_length];
        assert_eq!(declaration, b"payload.txt\0");
        let mut sink = Sink::default();
        let file = artifact("renamed.bin", &bytes);
        assert_eq!(Unpacker::unpack(&Flatpak, &file, &bytes, &mut sink), Unpack::Done { kind: "flatpak" });
        assert_eq!(sink.files["root/payload.txt"], b"payload-data\n");
        assert!(!sink.files.contains_key("root/alias"));
        assert!(sink.files.contains_key("parts/0.flatpak-part"));
        assert!(sink.limits.is_empty());
    }

    #[test]
    fn unsupported_base_fallback_version_and_operations_are_explicit_without_payload_claims() {
        for options in [
            Options { base: true, ..Options::default() },
            Options { fallback: true, ..Options::default() },
            Options { version: 1, ..Options::default() },
            Options { opcode: Some(b'B'), ..Options::default() },
        ] {
            let bytes = fixture(options);
            let parsed = bundle(&bytes).expect("supported header");
            assert!(!parsed.complete);
            assert!(!parsed.issues.is_empty());
            let mut sink = Sink::default();
            Unpacker::unpack(&Flatpak, &artifact("app.flatpak", &bytes), &bytes, &mut sink);
            assert!(sink.files.contains_key("parts/0.flatpak-part"));
            assert!(!sink.limits.is_empty());
        }
    }

    #[test]
    fn bad_digests_missing_objects_duplicate_paths_and_unsafe_names_never_become_complete() {
        for options in [
            Options { bad_part_digest: true, ..Options::default() },
            Options { bad_content_digest: true, ..Options::default() },
            Options { missing_file: true, ..Options::default() },
            Options { duplicate_path: true, ..Options::default() },
            Options { unsafe_name: true, ..Options::default() },
        ] {
            let parsed_bytes = fixture(options);
            let parsed = bundle(&parsed_bytes).expect("structural header remains readable");
            assert!(!parsed.complete);
            assert!(!parsed.issues.is_empty());
        }
        assert!(header(&fixture(Options { duplicate_metadata: true, ..Options::default() })).is_err());
        let bytes = fixture(Options { missing_file: true, ..Options::default() });
        let partial = bundle(&bytes).expect("partial bundle header");
        assert!(partial.files.iter().any(|file| file.path == "metadata"), "completed file observations survive a later missing child");
    }

    #[test]
    fn unread_first_file_preserves_later_siblings_and_independently_queued_directories() {
        let bytes = fixture(Options { missing_first_file: true, ..Options::default() });
        let partial = bundle(&bytes).expect("missing file keeps the supported header");
        assert!(!partial.complete);
        assert_eq!(partial.issues.len(), 1);
        assert!(partial.issues[0].contains("metadata"));
        assert!(partial.files.iter().any(|file| file.path == "payload.txt"), "a good second file must still be read");
        assert!(partial.files.iter().any(|file| file.path == "alias"), "later siblings remain available");

        let bytes = fixture(Options::default());
        let mut partial = bundle(&bytes).expect("supported constructed bundle");
        let first = partial.files.iter().find(|file| file.path == "metadata").expect("first root declaration").object;
        partial.objects[first].mode = Some(0o020600);
        partial.files.clear();
        partial.directories.clear();
        partial.complete = true;
        partial.resolve_tree().expect("an unsupported file mode is local to that declaration");
        assert!(!partial.complete);
        assert_eq!(partial.issues.len(), 1);
        assert!(partial.issues[0].contains("special file mode"));
        assert!(partial.files.iter().any(|file| file.path == "payload.txt"));

        // The native writer fixture has a root metadata file followed by separate
        // export and payload directories. An unavailable file object must not
        // prevent traversal of either independently supplied directory.
        let native = include_bytes!("../tests/data/native-inert.flatpak");
        let mut partial = bundle(native).expect("native writer bundle");
        let first = partial.files.iter().find(|file| file.path == "metadata").expect("native root metadata").object;
        partial.objects.remove(first);
        partial.files.clear();
        partial.directories.clear();
        partial.complete = true;
        partial.resolve_tree().expect("missing file does not abort the directory queue");
        assert!(!partial.complete);
        assert_eq!(partial.issues.len(), 1);
        assert!(partial.files.iter().any(|file| file.path == "files/share/fixture/message.txt"));
        assert!(partial.directories.iter().any(|directory| directory["path"] == "export"));
        assert!(partial.directories.iter().any(|directory| directory["path"] == "files/share/fixture"));
    }

    #[test]
    fn malformed_frames_prefixes_strings_and_delta_varints_are_rejected_without_defaults() {
        let bytes = fixture(Options::default());
        for end in 0..bytes.len() {
            assert!(header(&bytes[..end]).is_err(), "truncated bundle at {end}");
        }
        let mut at = 0;
        assert!(varuint(&[0x80, 0], &mut at).is_err());
        let mut at = 0;
        assert!(varuint(&[0xff; 10], &mut at).is_err());
        assert!(Node::new(b"unterminated", "s").expect("string type").string().is_err());
        let mut altered = bytes.clone();
        *altered.last_mut().expect("framing byte") = 0xff;
        assert!(header(&altered).is_err());
        let node = Node::new(&bytes, SUPER).expect("superblock type");
        assert!(node.validate(&mut Budget { nodes: 2, strings: 10 }, 0).is_err());
        assert!(decode_part(&[b'g', 0, 0]).is_err());
        assert!(decode_part(&[b'x', 0, 0]).is_err());
    }

    #[test]
    fn declarations_are_literal_redacted_and_missing_capture_is_not_present_content() {
        let fields = application_metadata(
            "[Application]\nname=org.example.Fixture\n[Context]\nenvironment=literal\\;value\npassword=fixture secret\n",
        )
        .expect("literal metadata");
        assert_eq!(fields[1]["value"], "literal\\;value");
        assert_eq!(fields[2]["value"], "[redacted]");
        assert!(application_metadata("[Application]\nname=one\nname=two\n").is_err());
        let bytes = fixture(Options::default());
        let mut file = artifact("app.flatpak", &bytes);
        file.unpacked_by = Some("flatpak".into());
        let tree = TestTree { files: vec![file.clone()], bytes: BTreeMap::from([(file.path.clone(), bytes)]) };
        let mut out = Output::default();
        Analyzer::analyze_file(&Flatpak, &tree, &file, &mut out);
        let fact = &out.facts.iter().find(|fact| fact.key == "flatpak.bundle").expect("bundle facts").value;
        assert_eq!(fact["regular_files"], 2);
        assert_eq!(fact["captured_files"], 0);
        assert_eq!(fact["capture_complete"], false);
        assert!(out.limitations.iter().any(|gap| gap.code == "flatpak.contents-unread"));
        let mut sink = Sink { stop: true, ..Sink::default() };
        assert!(matches!(Unpacker::unpack(&Flatpak, &file, &tree.bytes[&file.path], &mut sink), Unpack::Done { .. }));
        assert!(sink.files.is_empty());
    }

    #[test]
    fn native_flatpak_writer_fixture_matches_original_source_paths_and_every_payload_digest() {
        let bytes = include_bytes!("../tests/data/native-inert.flatpak");
        assert_eq!(aa_core::sha256_hex(bytes), "ee9b1c1db1ae500654036a418946548ed48d65ea6bd7e189bdbb0536022cff3d");
        let source: Vec<Value> =
            serde_json::from_str(include_str!("../tests/data/native-inert.flatpak.source.json")).expect("native source record");
        let parsed = bundle(bytes).expect("native writer superblock");
        assert!(parsed.complete, "{:?}", parsed.issues);
        assert_eq!(parsed.header.reference, "app/org.example.AnalyzeAnythingFixture/x86_64/stable");
        assert_eq!(parsed.files.len(), source.len());
        assert_eq!(parsed.parts.len(), 1);
        assert_eq!(parsed.parts[0].raw.data.first(), Some(&b'x'));
        for expected in &source {
            let entry = parsed
                .files
                .iter()
                .find(|file| expected["path"].as_str() == Some(file.path.as_str()))
                .expect("original native source path");
            if let Some(target) = expected["link_target"].as_str() {
                assert_eq!(entry.target.as_deref(), Some(target));
            } else {
                let data = parsed.object_bytes(entry.object).expect("native file bytes");
                assert_eq!(data.len() as u64, expected["size"].as_u64().expect("recorded size"));
                assert_eq!(aa_core::sha256_hex(data), expected["sha256"].as_str().expect("recorded digest"));
            }
        }
        let references: Vec<Value> =
            serde_json::from_str(include_str!("../tests/data/native-flatpak.ref.json")).expect("native Flatpak/GLib record");
        let reference = references
            .iter()
            .find(|reference| reference["sha256"].as_str() == Some(aa_core::sha256_hex(bytes).as_str()))
            .expect("native comparison bound to this exact fixture");
        assert!(reference["checks"].as_array().expect("native checks").iter().all(|check| check["matches"] == true));
        for expected in reference["native"]["paths"].as_array().expect("native object paths") {
            let entry =
                parsed.files.iter().find(|entry| expected["path"].as_str() == Some(entry.path.as_str())).expect("native path retained");
            assert_eq!(hex::encode(entry.checksum), expected["checksum"].as_str().expect("native canonical object checksum"));
            assert_eq!(
                aa_core::sha256_hex(parsed.object_bytes(entry.object).expect("supplied object bytes")),
                expected["sha256"].as_str().expect("native raw payload hash")
            );
        }
    }

    #[test]
    fn checksum_work_and_type_expansion_are_bounded_before_repeated_processing() {
        let bytes = fixture(Options::default());
        let mut parsed = bundle(&bytes).expect("controlled bundle");
        let descriptors = parsed.header.fields[6].children(1).expect("part descriptor")[0].children(5).expect("descriptor fields")[4]
            .bytes()
            .expect("object descriptors")
            .to_vec();
        let before = parsed.checksum_work;
        assert!(parsed.read_objects(0, &descriptors).expect_err("duplicate identities rejected early").contains("duplicate"));
        assert_eq!(parsed.checksum_work, before);
        parsed.seen_objects.clear();
        parsed.checksum_work = MAX_TOTAL;
        assert!(parsed.read_objects(0, &descriptors).expect_err("checksum budget checked before hashing").contains("checksum work"));
        let ty = format!("a({})", "y".repeat(64));
        let data = vec![0; 64 * 16_385];
        assert!(Node::new(&data, &ty).expect("bounded signature").children(MAX_OBJECTS).is_err());
        assert!(variant::signature(&format!("{}y", "a".repeat(33))).is_err());
        assert!(Node::new(&vec![b'a'; 1024 * 1024 + 2], "s").expect("string schema").validate(&mut Budget::default(), 0).is_err());
    }

    #[test]
    fn oversized_xz_dictionary_is_rejected_before_allocation() {
        // A native liblzma stream whose block property requests a 4 GiB dictionary;
        // its block-header CRC was recomputed after changing that property.
        let frame = hex::decode("fd377a585a000004e6d6b4460200210128000000e6a011b3e0001300065d00006e0047f800000000bce4bb48b4242072000122147627ee9d1fb6f37d010000000004595a").expect("controlled XZ framing");
        let mut part = vec![b'x'];
        part.extend(frame);
        assert!(decode_part(&part).expect_err("dictionary limit").contains("memory"));
    }

    #[test]
    fn captured_regular_file_evidence_points_to_both_payload_and_filename_bytes() {
        let bytes = fixture(Options::default());
        let root = artifact("bundle.flatpak", &bytes);
        let mut sink = Sink::default();
        Unpacker::unpack(&Flatpak, &root, &bytes, &mut sink);
        let mut tree = TestTree { files: vec![root.clone()], bytes: BTreeMap::from([(root.path.clone(), bytes)]) };
        for (name, data) in &sink.files {
            let path = format!("{}/{}", root.path, name);
            let mut child = artifact(&path, data);
            child.parent = Some(root.path.clone());
            tree.files.push(child.clone());
            tree.bytes.insert(path.clone(), data.clone());
            if name.ends_with(".flatpak-part") {
                let decoded = decode_part(data).expect("decode source layer");
                let mut source = artifact(&format!("{path}/decoded"), &decoded);
                source.parent = Some(path);
                tree.bytes.insert(source.path.clone(), decoded);
                tree.files.push(source);
            }
        }
        tree.files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut out = Output::default();
        retain(&tree, &root, &tree.bytes[&root.path], &mut out).expect("retain real sources");
        let finding = out.findings.iter().find(|finding| finding.rule == "flatpak.contents").expect("captured content finding");
        assert_eq!(finding.params["count"], 2);
        assert_eq!(finding.evidence.len(), 4);
        for evidence in &finding.evidence {
            assert!(evidence.artifact.ends_with("/decoded"));
            let aa_core::Location::Bytes { offset, length } = evidence.location else {
                panic!("byte evidence required");
            };
            let source = &tree.bytes[&evidence.artifact][offset as usize..(offset + length) as usize];
            let path = evidence.value["path"].as_str().expect("associated file");
            if evidence.value["role"] == "directory filename declaration" {
                assert_eq!(source, string(path));
            } else if path == "payload.txt" {
                assert_eq!(source, b"payload-data\n");
            }
        }
    }

    #[test]
    #[ignore = "requires an explicitly supplied external .flatpak reference path"]
    fn inspect_external_reference_without_installation() {
        let path = std::env::var("AA_FLATPAK_REFERENCE").expect("set AA_FLATPAK_REFERENCE to a supplied bundle");
        let bytes = std::fs::read(path).expect("read supplied reference as bytes");
        let parsed = bundle(&bytes).expect("supported Flatpak superblock");
        eprintln!(
            "reference={} parts={} objects={} files={} directories={} issues={:?}",
            parsed.header.reference,
            parsed.parts.len(),
            parsed.objects.len(),
            parsed.files.len(),
            parsed.directories.len(),
            parsed.issues
        );
        assert!(parsed.complete, "{:?}", parsed.issues);
        assert!(!parsed.files.is_empty());
    }
}
