//! OCI layouts and Docker-save declarations, without applying or running an image.

mod json;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::Result;

pub struct Image;

const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_JSON_TOTAL: usize = 16 * 1024 * 1024;
const MAX_PUBLISHED: usize = 16 * 1024 * 1024;
const MAX_LAYERS: usize = 1024;
const MAX_MANIFESTS: usize = 64;
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";

const RULES: &[Rule] = &[
    Rule {
        id: "image.contents",
        title_en: "Declared container image composition",
        title_zh: "容器镜像组成声明",
        text_en: "The supplied OCI or Docker-save image contains {count} image manifests. Configuration and ordered layer declarations are associated only with supplied bytes; no registry or host lookup was performed.",
        text_zh: "所提供的 OCI 或 Docker-save 镜像包含 {count} 个镜像清单。配置和有序分层声明仅关联到所提供的字节，没有查询仓库或本机。",
    },
    Rule {
        id: "image.configuration",
        title_en: "Declared container image configuration",
        title_zh: "容器镜像配置声明",
        text_en: "The captured image configuration declares arguments, environment, ports or volumes. Values remain literal, with recognizable credentials redacted; no container or command was started.",
        text_zh: "捕获的镜像配置声明了参数、环境、端口或卷。按字面保留其值并遮盖可识别凭据，没有启动容器或命令。",
    },
    Rule {
        id: "image.layers",
        title_en: "Ordered image layer declarations",
        title_zh: "有序镜像分层声明",
        text_en: "The image contains {count} captured layer inventories. Original TAR order, whiteouts and link targets remain declarations; layers were not merged or applied.",
        text_zh: "镜像包含 {count} 个已捕获分层目录。原始 TAR 顺序、白化记录和链接目标仅作为声明，没有合并或应用分层。",
    },
    Rule {
        id: "image.metadata-unread",
        title_en: "Container image metadata remains unread",
        title_zh: "容器镜像元数据未读取",
        text_en: "An image document, descriptor or path could not be read unambiguously within the bounded profile. Missing or unsupported declarations are not treated as empty values.",
        text_zh: "无法在有界支持范围内唯一读取镜像文档、描述符或路径。缺失或不支持的声明没有被视为空值。",
    },
    Rule {
        id: "image.layer-unread",
        title_en: "Some image layer contents remain unread",
        title_zh: "部分镜像分层内容未读取",
        text_en: "A layer is missing, ambiguous, malformed, outside supported compression or beyond a reader budget. Partial inventories are retained and completeness is stated explicitly.",
        text_zh: "某个分层缺失、不唯一、格式错误、压缩方式不支持或超出读取预算。保留部分目录并明确说明完整性。",
    },
    Rule {
        id: "image.digest-mismatch",
        title_en: "Image descriptor bytes differ from their declarations",
        title_zh: "镜像描述符字节与声明不一致",
        text_en: "A captured blob's size, SHA-256 or uncompressed TAR DiffID differs from its declaration. This is a byte comparison, not an authenticity or execution verdict.",
        text_zh: "已捕获数据块的大小、SHA-256 或未压缩 TAR 的 DiffID 与声明不同。这是字节比较，不是来源认证或执行判定。",
    },
    Rule {
        id: "image.layer-semantics",
        title_en: "Image filesystem and runtime semantics remain unresolved",
        title_zh: "镜像文件系统和运行时语义未确定",
        text_en: "Layer files, whiteouts, links, modes and configuration remain static declarations. No merged filesystem, link target, effective environment, runtime policy or package authenticity was established.",
        text_zh: "分层文件、白化记录、链接、模式和配置仅作为静态声明，没有确定合并文件系统、链接目标、有效环境、运行时策略或软件包来源真实性。",
    },
];

#[derive(Clone)]
struct TarEntry {
    path: String,
    logical: Option<String>,
    header: u64,
    metadata_offset: u64,
    metadata_length: u64,
    offset: u64,
    size: u64,
    mode: Option<u32>,
    kind: u8,
    link: Option<String>,
}

#[derive(Default)]
struct TarIndex {
    entries: Vec<TarEntry>,
    complete: bool,
    issues: Vec<String>,
    names: BTreeMap<String, usize>,
}

fn logical(path: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(['\\', '\0'])
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    Some(path.to_string())
}

fn tar_index(bytes: &[u8], remaining: &mut usize) -> TarIndex {
    let mut index = TarIndex::default();
    if bytes.len() > MAX_BYTES {
        index.issues.push("TAR exceeds the 256 MiB image-reader profile".into());
        return index;
    }
    let mut archive = tar::Archive::new(bytes);
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            index.issues.push(format!("TAR: {error}"));
            return index;
        }
    };
    let mut text = 0usize;
    let mut trailer = 0usize;
    let mut seen = BTreeSet::new();
    for entry in entries {
        if *remaining == 0 {
            index.issues.push("global image TAR-entry budget exhausted".into());
            return index;
        }
        *remaining -= 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                index.issues.push(format!("TAR entry: {error}"));
                return index;
            }
        };
        let name = entry.path_bytes();
        let target = entry.link_name_bytes();
        text = text.saturating_add(name.len()).saturating_add(target.as_ref().map_or(0, |target| target.len()));
        if name.len() > 4096 || target.as_ref().is_some_and(|target| target.len() > 4096) || text > crate::MAX_METADATA {
            index.issues.push("image TAR name budget exhausted".into());
            return index;
        }
        let path = match std::str::from_utf8(&name) {
            Ok(path) => path.to_string(),
            Err(_) => {
                index.issues.push("image TAR path is not UTF-8".into());
                return index;
            }
        };
        let link = match target.as_ref().map(|target| std::str::from_utf8(target)).transpose() {
            Ok(target) => target.map(str::to_string),
            Err(_) => {
                index.issues.push("image TAR link target is not UTF-8".into());
                return index;
            }
        };
        let kind = entry.header().entry_type().as_byte();
        let logical = if matches!(path.as_str(), "." | "./") && kind == b'5' {
            Some(String::new())
        } else if kind == b'5' {
            logical(path.trim_end_matches('/'))
        } else {
            logical(&path)
        };
        if logical.is_none() {
            index.issues.push("noncanonical or unsafe image TAR path declaration".into());
        }
        if logical.as_ref().is_some_and(|path| !seen.insert(path.clone())) {
            index.issues.push("duplicate image TAR path declaration".into());
        }
        if index.issues.len() >= 64 {
            return index;
        }
        let offset = entry.raw_file_position();
        let metadata_offset = trailer as u64;
        let Some(metadata_length) = offset.checked_sub(metadata_offset) else {
            index.issues.push("image TAR metadata source extent is reversed".into());
            return index;
        };
        let size = entry.size();
        let range =
            usize::try_from(offset).ok().zip(usize::try_from(size).ok()).and_then(|(offset, size)| crate::extent(bytes, offset, size).ok());
        if range.is_none() {
            index.issues.push("image TAR member extends beyond captured bytes".into());
            return index;
        }
        trailer = match usize::try_from(offset)
            .ok()
            .zip(usize::try_from(size).ok())
            .and_then(|(offset, size)| offset.checked_add(size))
            .and_then(|end| crate::align(end, 512).ok())
        {
            Some(end) => end,
            None => {
                index.issues.push("image TAR member extent overflow".into());
                return index;
            }
        };
        let mode = entry.header().mode().ok();
        if mode.is_none() {
            index.issues.push("image TAR has a malformed mode".into());
        }
        if kind == b'S' {
            index.issues.push("sparse image TAR entries are outside this profile".into());
        }
        if kind == b'g' {
            index.issues.push("global PAX defaults are outside this image TAR profile".into());
        }
        if let Some(name) = &logical {
            index.names.insert(name.clone(), index.entries.len());
        }
        index.entries.push(TarEntry {
            path,
            logical,
            header: entry.raw_header_position(),
            metadata_offset,
            metadata_length,
            offset,
            size,
            mode,
            kind,
            link,
        });
    }
    if bytes.get(trailer..).is_none_or(|tail| tail.len() < 1024 || tail.iter().any(|byte| *byte != 0)) {
        index.issues.push("image TAR has an incomplete zero trailer or unread trailing data".into());
    }
    index.complete = index.issues.is_empty();
    index
}

fn clean(file: &Artifact) -> bool {
    !file.facts.get("engine.entry-name").and_then(|value| value.get("colliding")).and_then(Value::as_bool).unwrap_or(false)
}

struct Namespace<'a> {
    tree: &'a dyn Tree,
    owner: &'a Artifact,
    prefix: String,
    parent: Option<&'a str>,
    original: Option<Arc<TarIndex>>,
}

struct NamespaceCache {
    indexes: BTreeMap<String, Arc<TarIndex>>,
    bytes: usize,
    entries: usize,
}
impl Default for NamespaceCache {
    fn default() -> Self {
        Self { indexes: BTreeMap::new(), bytes: 0, entries: crate::MAX_ENTRIES }
    }
}

impl<'a> Namespace<'a> {
    #[cfg(test)]
    fn new(tree: &'a dyn Tree, marker: &'a Artifact) -> Result<Self> {
        Self::new_cached(tree, marker, &mut NamespaceCache::default())
    }
    fn new_cached(tree: &'a dyn Tree, marker: &'a Artifact, cache: &mut NamespaceCache) -> Result<Self> {
        let prefix = marker.path.rsplit_once('/').map_or(String::new(), |(prefix, _)| prefix.to_string());
        if prefix.len() > 4096 {
            return Err("image namespace path exceeds the 4096-byte profile".into());
        }
        let parent = marker.parent.as_deref();
        let mut owner = marker;
        let original = if let Some(container) = parent.and_then(|parent| tree.get(parent)) {
            if prefix == container.path {
                owner = container;
            }
            if container.unpacked_by.as_deref() != Some("tar") {
                return Err("image metadata is not in a supported original TAR namespace".into());
            }
            if container.size > MAX_BYTES as u64 {
                return Err("image archive exceeds the 256 MiB metadata-indexing profile".into());
            }
            let directory = if let Some(directory) = cache.indexes.get(&container.path) {
                Arc::clone(directory)
            } else {
                cache.bytes =
                    cache.bytes.saturating_add(usize::try_from(container.size).map_err(|_| "container size exceeds address space")?);
                if cache.bytes > MAX_BYTES {
                    return Err("global original-image TAR indexing byte budget exhausted".into());
                }
                let bytes = tree.read(&container.path).map_err(|error| error.to_string())?;
                let directory = Arc::new(tar_index(&bytes, &mut cache.entries));
                cache.indexes.insert(container.path.clone(), Arc::clone(&directory));
                directory
            };
            if !directory.complete {
                return Err(format!("original image archive is not unambiguous: {}", directory.issues.join("; ")));
            }
            Some(directory)
        } else {
            if tree.summary().get("engine.input-listing").and_then(|value| value.get("complete")).and_then(Value::as_bool) == Some(false) {
                return Err("supplied directory enumeration is incomplete".into());
            }
            None
        };
        Ok(Self { tree, owner, prefix, parent, original })
    }

    fn lookup(&self, name: &str) -> Result<&'a Artifact> {
        if logical(name).as_deref() != Some(name) {
            return Err("image reference path is noncanonical or outside its supplied namespace".into());
        }
        let path = if self.prefix.is_empty() { name.to_string() } else { format!("{}/{name}", self.prefix) };
        let file = self
            .tree
            .get(&path)
            .filter(|file| file.parent.as_deref() == self.parent && clean(file))
            .ok_or("referenced image member is missing or ambiguous")?;
        if let Some(original) = &self.original {
            let root = self.parent.ok_or("missing original image parent")?;
            let relative =
                path.strip_prefix(root).and_then(|path| path.strip_prefix('/')).ok_or("image namespace differs from its container")?;
            let entry = original.names.get(relative).and_then(|index| original.entries.get(*index));
            if !matches!(entry,Some(entry) if matches!(entry.kind,0|b'0') && entry.size == file.size) {
                return Err("image member is not an unambiguous regular original TAR entry".into());
            }
        }
        Ok(file)
    }
}

struct Reader<'a> {
    namespace: Namespace<'a>,
    json_budget: json::Budget,
    json_bytes: usize,
    data_bytes: usize,
    published_bytes: usize,
    entries: usize,
    layers: usize,
    manifests: Vec<Value>,
    edges: Vec<Value>,
    issues: Vec<(String, String)>,
    layer_facts: Vec<(&'a Artifact, Value)>,
    hashes: BTreeMap<String, String>,
    failed: bool,
}

impl<'a> Reader<'a> {
    fn new(namespace: Namespace<'a>) -> Self {
        Self {
            namespace,
            json_budget: json::Budget::default(),
            json_bytes: 0,
            data_bytes: 0,
            published_bytes: 0,
            entries: crate::MAX_ENTRIES,
            layers: 0,
            manifests: Vec::new(),
            edges: Vec::new(),
            issues: Vec::new(),
            layer_facts: Vec::new(),
            hashes: BTreeMap::new(),
            failed: false,
        }
    }
    fn issue(&mut self, code: &str, detail: impl Into<String>) {
        self.failed = true;
        if self.issues.len() < 64 {
            self.issues.push((code.to_string(), detail.into()));
        }
    }
    fn read_json(&mut self, file: &Artifact) -> Result<Value> {
        let size = usize::try_from(file.size).map_err(|_| "image JSON size exceeds the address space")?;
        self.json_bytes = self.json_bytes.saturating_add(size);
        if self.json_bytes > MAX_JSON_TOTAL || size > 2 * 1024 * 1024 {
            return Err("global image JSON byte budget exhausted".into());
        }
        let bytes = self.namespace.tree.read(&file.path).map_err(|error| error.to_string())?;
        json::parse(&bytes, &mut self.json_budget)
    }
    fn hash(&mut self, file: &Artifact) -> Result<String> {
        if let Some(value) = self.hashes.get(&file.path) {
            return Ok(value.clone());
        }
        if file.size > MAX_BYTES as u64 {
            return Err("image blob exceeds the 256 MiB reader profile".into());
        }
        let value = if let Some(digests) = &file.digests {
            digests.sha256.clone()
        } else {
            self.data_bytes = self.data_bytes.saturating_add(file.size as usize);
            if self.data_bytes > MAX_BYTES {
                return Err("global image checksum byte budget exhausted".into());
            }
            let bytes = self.namespace.tree.read(&file.path).map_err(|error| error.to_string())?;
            aa_core::sha256_hex(&bytes)
        };
        self.hashes.insert(file.path.clone(), value.clone());
        Ok(value)
    }
    fn descriptor(&mut self, value: &Value) -> Result<&'a Artifact> {
        let digest = text(value, "digest")?;
        let hex = sha256_name(digest)?;
        let size = value.get("size").and_then(Value::as_u64).ok_or("image descriptor has no unsigned size")?;
        let file = self.namespace.lookup(&format!("blobs/sha256/{hex}"))?;
        if file.size != size || self.hash(file)? != hex {
            return Err("captured image descriptor size or SHA-256 differs from its declaration".into());
        }
        Ok(file)
    }

    fn oci(&mut self, marker: &'a Artifact) -> Result<&'a Artifact> {
        let layout = self.read_json(marker)?;
        if layout.get("imageLayoutVersion").and_then(Value::as_str) != Some("1.0.0") {
            return Err("unsupported OCI image layout version".into());
        }
        let index = self.namespace.lookup("index.json")?;
        let document = self.read_json(index)?;
        let mut pending = vec![(index, document, BTreeSet::new(), 0usize)];
        let mut seen = BTreeSet::new();
        while let Some((source, document, mut ancestors, depth)) = pending.pop() {
            if depth > 16 || !ancestors.insert(source.path.clone()) {
                self.issue("image.metadata-unread", "OCI index graph cycle or depth budget exhausted");
                continue;
            }
            if !seen.insert(source.path.clone()) {
                continue;
            }
            if seen.len() > MAX_MANIFESTS || pending.len() > MAX_MANIFESTS {
                return Err("OCI index/manifest graph budget exhausted".into());
            }
            if document.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
                self.issue("image.metadata-unread", "unsupported OCI index schemaVersion");
                continue;
            }
            let descriptors = match array(&document, "manifests", MAX_MANIFESTS) {
                Ok(rows) => rows,
                Err(detail) => {
                    self.issue("image.metadata-unread", detail);
                    continue;
                }
            };
            for (position, descriptor) in descriptors.iter().enumerate() {
                let media = match text(descriptor, "mediaType") {
                    Ok(media) => media,
                    Err(detail) => {
                        self.issue("image.metadata-unread", detail);
                        continue;
                    }
                };
                let optional = redacted_json(descriptor.get("platform").unwrap_or(&Value::Null))
                    .and_then(|platform| Ok((platform, annotations(descriptor.get("annotations"))?)));
                let (platform, annotations) = match optional {
                    Ok(fields) => fields,
                    Err(detail) => {
                        self.issue("image.metadata-unread", detail);
                        continue;
                    }
                };
                let mut edge = json!({"source":source.path,"field":format!("/manifests/{position}"),"media_type":media,"digest":descriptor.get("digest"),"size":descriptor.get("size"),
                    "platform":platform,"annotations":annotations,
                    "urls_present":descriptor.get("urls").is_some(),"inline_data_present":descriptor.get("data").is_some(),"state":"unresolved","target":null});
                if !matches!(media, OCI_INDEX | DOCKER_INDEX | OCI_MANIFEST | DOCKER_MANIFEST) {
                    edge["state"] = json!("unsupported-media-type");
                    self.edges.push(edge);
                    self.issue("image.metadata-unread", "an OCI descriptor uses an unsupported media type");
                    continue;
                }
                let target = match self.descriptor(descriptor) {
                    Ok(file) => file,
                    Err(detail) => {
                        edge["state"] = json!(if detail.contains("differs") { "digest-mismatch" } else { "unresolved" });
                        self.edges.push(edge);
                        self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.metadata-unread" }, detail);
                        continue;
                    }
                };
                edge["target"] = json!(target.path);
                edge["state"] = json!("matched");
                self.edges.push(edge);
                let next = match self.read_json(target) {
                    Ok(next) => next,
                    Err(detail) => {
                        self.issue("image.metadata-unread", detail);
                        continue;
                    }
                };
                if next.get("mediaType").and_then(Value::as_str).is_some_and(|declared| declared != media) {
                    self.issue("image.metadata-unread", "OCI document mediaType differs from its referencing descriptor");
                    continue;
                }
                if matches!(media, OCI_INDEX | DOCKER_INDEX) {
                    pending.push((target, next, ancestors.clone(), depth + 1));
                } else if !self.manifests.iter().any(|manifest| manifest["source"] == target.path)
                    && let Err(detail) = self.oci_manifest(target, &next, descriptor)
                {
                    self.issue("image.metadata-unread", detail);
                }
            }
        }
        Ok(index)
    }

    fn oci_manifest(&mut self, source: &'a Artifact, document: &Value, descriptor: &Value) -> Result<()> {
        if self.manifests.len() >= MAX_MANIFESTS {
            return Err("image manifest budget exhausted".into());
        }
        if document.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err("unsupported image manifest schemaVersion".into());
        }
        let mut row = json!({"source":source.path,"digest":descriptor.get("digest"),"annotations":annotations(document.get("annotations"))?,
            "reference_annotations":annotations(descriptor.get("annotations"))?,"config_source":null,"config_digest":null,"layers":null,"complete":false});
        let mut complete = true;
        let config = document.get("config").ok_or("OCI manifest has no config descriptor")?;
        row["config_descriptor"] = json!({"digest":config.get("digest"),"size":config.get("size"),"media_type":config.get("mediaType"),"urls_present":config.get("urls").is_some()});
        row["config_state"] = json!("unresolved");
        let config_media = config.get("mediaType").and_then(Value::as_str);
        let mut diff_ids = None;
        if !matches!(config_media, Some("application/vnd.oci.image.config.v1+json" | "application/vnd.docker.container.image.v1+json")) {
            self.issue("image.metadata-unread", "unsupported image config media type");
            complete = false;
        } else {
            match self.descriptor(config) {
                Ok(file) => {
                    row["config_source"] = json!(file.path);
                    row["config_digest"] = config["digest"].clone();
                    row["config_state"] = json!("matched");
                    match self.read_json(file).and_then(|value| config_fields(&value)) {
                        Ok((fields, diffs)) => {
                            merge_fields(&mut row, fields);
                            diff_ids = diffs;
                        }
                        Err(detail) => {
                            self.issue("image.metadata-unread", detail);
                            complete = false;
                        }
                    }
                }
                Err(detail) => {
                    row["config_state"] = json!(if detail.contains("differs") { "digest-mismatch" } else { "unresolved" });
                    self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.metadata-unread" }, detail);
                    complete = false;
                }
            }
        }
        let descriptors = match array(document, "layers", MAX_LAYERS) {
            Ok(rows) => rows,
            Err(detail) => {
                self.issue("image.metadata-unread", detail);
                self.manifests.push(row);
                return Ok(());
            }
        };
        if diff_ids.as_ref().is_none_or(|diffs| diffs.len() != descriptors.len()) {
            self.issue("image.metadata-unread", "image layer count differs from rootfs.diff_ids or the rootfs profile is unread");
            complete = false;
        }
        let mut layers = Vec::new();
        for (order, descriptor) in descriptors.iter().enumerate() {
            self.layers += 1;
            if self.layers > MAX_LAYERS {
                self.issue("image.layer-unread", "global image layer count exhausted");
                complete = false;
                break;
            }
            let media = descriptor.get("mediaType").and_then(Value::as_str).unwrap_or("");
            let mut layer = json!({"order":order,"source":null,"declared_digest":descriptor.get("digest"),"digest":null,"size":descriptor.get("size"),"media_type":media,
                "state":"unresolved","diff_id":diff_ids.as_ref().and_then(|diffs| diffs.get(order)),"diff_id_state":"unresolved","tar_source":null,"entries":null,"complete":false,
                "urls_present":descriptor.get("urls").is_some()});
            match self.descriptor(descriptor) {
                Ok(file) => {
                    layer["source"] = json!(file.path);
                    layer["digest"] = descriptor["digest"].clone();
                    layer["state"] = json!("matched");
                    if let Err(detail) =
                        self.layer(file, media, diff_ids.as_ref().and_then(|diffs| diffs.get(order)).map(String::as_str), &mut layer)
                    {
                        self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.layer-unread" }, detail);
                        complete = false;
                    }
                }
                Err(detail) => {
                    layer["state"] = json!(if detail.contains("differs") { "digest-mismatch" } else { "unresolved" });
                    self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.layer-unread" }, detail);
                    complete = false;
                }
            }
            layers.push(layer);
            if layers.last().is_some_and(|layer| layer["complete"] != true) {
                complete = false;
            }
        }
        row["layers"] = json!(layers);
        row["complete"] = json!(complete);
        self.manifests.push(row);
        Ok(())
    }

    fn docker(&mut self, source: &'a Artifact, document: &Value) -> Result<()> {
        let rows = document.as_array().ok_or("Docker-save manifest is not an array")?;
        if rows.is_empty() || rows.len() > MAX_MANIFESTS {
            return Err("Docker-save manifest count is outside the profile".into());
        }
        for (index, document) in rows.iter().enumerate() {
            if let Err(detail) = self.docker_manifest(source, index, document) {
                self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.metadata-unread" }, detail);
            }
        }
        Ok(())
    }

    fn docker_manifest(&mut self, source: &'a Artifact, index: usize, document: &Value) -> Result<()> {
        let config_name = text(document, "Config")?;
        let config_source = self.namespace.lookup(config_name)?;
        let expected = config_name.strip_suffix(".json").ok_or("Docker-save config filename has no .json suffix")?;
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err("Docker-save config filename is not a canonical SHA-256 name".into());
        }
        if self.hash(config_source)? != expected {
            return Err("Docker-save config filename differs from its captured SHA-256".into());
        }
        let config = self.read_json(config_source)?;
        let (fields, diffs) = config_fields(&config)?;
        let tags = string_array(document.get("RepoTags"), 4096)?;
        let mut row = json!({"source":source.path,"manifest_position":index,"digest":null,"tags":tags,"annotations":{},"config_source":config_source.path,
                "config_digest":format!("sha256:{expected}"),"complete":true});
        merge_fields(&mut row, fields);
        let names = array(document, "Layers", MAX_LAYERS)?;
        let mut complete = diffs.as_ref().is_some_and(|diffs| diffs.len() == names.len());
        if !complete {
            self.issue("image.metadata-unread", "Docker-save layer count differs from rootfs.diff_ids or the rootfs profile is unread");
        }
        let mut layers = Vec::new();
        for (order, name) in names.iter().enumerate() {
            self.layers += 1;
            if self.layers > MAX_LAYERS {
                self.issue("image.layer-unread", "global image layer count exhausted");
                complete = false;
                break;
            }
            let mut layer = json!({"order":order,"source":null,"declared_digest":null,"digest":null,"size":null,"media_type":"application/vnd.oci.image.layer.v1.tar",
                    "state":"unresolved","diff_id":diffs.as_ref().and_then(|diffs|diffs.get(order)),"diff_id_state":"unresolved","tar_source":null,"entries":null,"complete":false});
            let result = name
                .as_str()
                .ok_or_else(|| "Docker-save layer path is not a string".to_string())
                .and_then(|name| self.namespace.lookup(name));
            match result {
                Ok(file) => {
                    layer["source"] = json!(file.path);
                    layer["size"] = json!(file.size);
                    layer["state"] = json!("captured");
                    let result = self.hash(file).and_then(|digest| {
                        layer["digest"] = json!(format!("sha256:{digest}"));
                        self.layer(
                            file,
                            "application/vnd.oci.image.layer.v1.tar",
                            diffs.as_ref().and_then(|diffs| diffs.get(order)).map(String::as_str),
                            &mut layer,
                        )
                    });
                    if let Err(detail) = result {
                        self.issue(if detail.contains("differs") { "image.digest-mismatch" } else { "image.layer-unread" }, detail);
                        complete = false;
                    }
                }
                Err(detail) => {
                    self.issue("image.layer-unread", detail);
                    complete = false;
                }
            }
            layers.push(layer);
            if layers.last().is_some_and(|layer| layer["complete"] != true) {
                complete = false;
            }
        }
        row["layers"] = json!(layers);
        row["complete"] = json!(complete);
        self.manifests.push(row);
        Ok(())
    }

    fn layer(&mut self, source: &'a Artifact, media: &str, diff: Option<&str>, row: &mut Value) -> Result<()> {
        let compression =
            if matches!(media, "application/vnd.oci.image.layer.v1.tar" | "application/vnd.oci.image.layer.nondistributable.v1.tar") {
                "tar"
            } else if matches!(
                media,
                "application/vnd.oci.image.layer.v1.tar+gzip"
                    | "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"
                    | "application/vnd.docker.image.rootfs.diff.tar.gzip"
                    | "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
            ) {
                "gzip"
            } else if matches!(
                media,
                "application/vnd.oci.image.layer.v1.tar+zstd" | "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd"
            ) {
                "zstd"
            } else {
                return Err("unsupported image layer media type or compression".into());
            };
        let tar = if compression == "tar" {
            source
        } else {
            if source.unpacked_by.as_deref() != Some("stream") || source.kind.as_deref() != Some(compression) {
                return Err("layer compression declaration differs from the captured stream profile".into());
            }
            let children: Vec<_> =
                self.namespace.tree.artifacts().iter().filter(|file| file.parent.as_deref() == Some(&source.path) && clean(file)).collect();
            if children.len() != 1 {
                return Err("decompressed layer TAR was not captured uniquely".into());
            }
            children[0]
        };
        row["tar_source"] = json!(tar.path);
        let actual_diff = format!("sha256:{}", self.hash(tar)?);
        row["computed_diff_id"] = json!(actual_diff);
        let matched = if let Some(expected) = diff {
            sha256_name(expected)?;
            if expected == actual_diff {
                row["diff_id_state"] = json!("matched");
                true
            } else {
                row["diff_id_state"] = json!("digest-mismatch");
                self.issue("image.digest-mismatch", "uncompressed image layer TAR SHA-256 differs from rootfs.diff_ids");
                false
            }
        } else {
            false
        };
        self.data_bytes = self.data_bytes.saturating_add(usize::try_from(tar.size).map_err(|_| "layer size exceeds address space")?);
        if self.data_bytes > MAX_BYTES {
            return Err("global image TAR scanning byte budget exhausted".into());
        }
        let bytes = self.namespace.tree.read(&tar.path).map_err(|error| error.to_string())?;
        let index = tar_index(&bytes, &mut self.entries);
        let mut rows = Vec::new();
        let mut whiteout_invalid = false;
        let mut output_complete = true;
        for entry in &index.entries {
            let logical = entry.logical.as_deref();
            let mut whiteout = logical.and_then(|path| {
                let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
                let target = |name: &str| if parent.is_empty() { name.to_string() } else { format!("{parent}/{name}") };
                if name == ".wh..wh..opq" {
                    Some(json!({"kind":"opaque","target":parent}))
                } else {
                    name.strip_prefix(".wh.").map(|name| json!({"kind":"remove","target":target(name)}))
                }
            });
            if whiteout.is_some()
                && (!matches!(entry.kind, 0 | b'0')
                    || entry.size != 0
                    || logical.is_some_and(|path| matches!(path.rsplit('/').next(), Some(".wh." | ".wh.." | ".wh..."))))
            {
                whiteout_invalid = true;
                if let Some(value) = &mut whiteout {
                    value["supported"] = json!(false);
                }
            }
            let path = aa_core::text::redact_sensitive_text(&entry.path).map_err(str::to_string)?;
            let link = entry.link.as_deref().map(aa_core::text::redact_sensitive_text).transpose().map_err(str::to_string)?;
            let child_path = logical.filter(|path| !path.is_empty()).map(|path| format!("{}/{path}", tar.path));
            let captured = matches!(entry.kind, 0 | b'0')
                && child_path
                    .as_deref()
                    .and_then(|path| self.namespace.tree.get(path))
                    .is_some_and(|file| clean(file) && file.size == entry.size && file.parent.as_deref() == Some(&tar.path));
            let value = json!({"path":path,"type":entry.kind,"link_target":link,"whiteout":whiteout,"header_offset":entry.header,"offset":entry.offset,
                "metadata_offset":entry.metadata_offset,"metadata_length":entry.metadata_length,"metadata_scope":"entry-and-local-extensions",
                "size":entry.size,"mode":entry.mode,"captured":captured,"captured_source":if captured{child_path}else{None}});
            // Each inventory is retained in both its package and source-TAR facts.
            // Charge the actual escaped representation, including repeated source paths.
            let size = serde_json::to_vec(&value).map_err(|error| error.to_string())?.len().saturating_mul(2);
            if self.published_bytes.saturating_add(size) > MAX_PUBLISHED {
                output_complete = false;
                self.issue("image.layer-unread", "global image published-inventory byte budget exhausted");
                break;
            }
            self.published_bytes += size;
            rows.push(value);
        }
        for detail in &index.issues {
            self.issue("image.layer-unread", detail.clone());
        }
        if whiteout_invalid {
            self.issue("image.layer-unread", "whiteout marker is not an empty regular TAR entry");
        }
        let capture_complete = output_complete
            && rows.iter().filter(|entry| matches!(entry["type"].as_u64(), Some(0 | 48))).all(|entry| entry["captured"] == true);
        if !capture_complete {
            self.issue("image.layer-unread", "some regular layer entries were not captured unambiguously");
        }
        let complete = index.complete && matched && !whiteout_invalid && capture_complete;
        row["entries"] = json!(rows);
        row["complete"] = json!(complete);
        row["capture_complete"] = json!(capture_complete);
        row["inventory_complete"] = json!(index.complete && output_complete);
        self.layer_facts.push((
            tar,
            json!({"package":self.namespace.owner.path,"source":source.path,"computed_diff_id":actual_diff,"complete":complete,
            "inventory_complete":index.complete && output_complete,"entries":rows}),
        ));
        if !complete {
            self.failed = true;
        }
        Ok(())
    }
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value.get(name).and_then(Value::as_str).ok_or_else(|| format!("image field {name} is not a string"))
}
fn array<'a>(value: &'a Value, name: &str, maximum: usize) -> Result<&'a [Value]> {
    let rows = value.get(name).and_then(Value::as_array).ok_or_else(|| format!("image field {name} is not an array"))?;
    if rows.len() > maximum {
        return Err(format!("image {name} count exceeds the profile"));
    }
    Ok(rows)
}
fn sha256_name(value: &str) -> Result<&str> {
    let hex = value.strip_prefix("sha256:").ok_or("only SHA-256 image descriptors are supported")?;
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("image SHA-256 declaration is not canonical lowercase hexadecimal".into());
    }
    Ok(hex)
}

fn string_array(value: Option<&Value>, limit: usize) -> Result<Value> {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Ok(Value::Null) };
    let values = value.as_array().ok_or("image configuration argument field is not an array")?;
    if values.len() > limit {
        return Err("image configuration array budget exhausted".into());
    }
    let mut result = Vec::new();
    let mut sensitive_next = false;
    for item in values {
        let text = item.as_str().ok_or("image configuration array has a non-string value")?;
        if text.len() > 16 * 1024 {
            return Err("image configuration value exceeds the 16 KiB profile".into());
        }
        let safe = if sensitive_next { "[redacted]".into() } else { aa_core::text::redact_sensitive_text(text).map_err(str::to_string)? };
        sensitive_next = text.starts_with('-') && aa_core::text::is_sensitive_field_name(text.trim_start_matches('-'));
        result.push(Value::String(safe));
    }
    Ok(Value::Array(result))
}

fn redacted_json(value: &Value) -> Result<Value> {
    Ok(match value {
        Value::String(text) => Value::String(aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?),
        Value::Array(values) => Value::Array(values.iter().map(redacted_json).collect::<Result<Vec<_>>>()?),
        Value::Object(values) => {
            let mut result = serde_json::Map::new();
            for (key, value) in values {
                let key_display = aa_core::text::redact_sensitive_text(key).map_err(str::to_string)?;
                if result.contains_key(&key_display) {
                    return Err("redacted image metadata keys are ambiguous".into());
                }
                result.insert(
                    key_display,
                    if let Some(text) = value.as_str() {
                        json!(aa_core::text::redact_named_value(key, text).map_err(str::to_string)?)
                    } else {
                        redacted_json(value)?
                    },
                );
            }
            Value::Object(result)
        }
        _ => value.clone(),
    })
}

fn annotations(value: Option<&Value>) -> Result<Value> {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Ok(json!({})) };
    let map = value.as_object().ok_or("image annotations are not an object")?;
    if map.len() > 4096 || map.values().any(|value| !value.is_string()) {
        return Err("image annotation profile is not a bounded string map".into());
    }
    redacted_json(value)
}

fn config_fields(value: &Value) -> Result<(Value, Option<Vec<String>>)> {
    let architecture = scalar(Some(value.get("architecture").ok_or("image architecture is absent")?))?;
    let os = scalar(Some(value.get("os").ok_or("image os is absent")?))?;
    let config = value.get("config").filter(|value| !value.is_null()).cloned().unwrap_or_else(|| json!({}));
    let config = config.as_object().ok_or("image config is not an object")?;
    let mut environment = Value::Null;
    if let Some(env) = config.get("Env").filter(|value| !value.is_null()) {
        let values = env.as_array().ok_or("image Env declaration is not an array")?;
        if values.len() > 4096 {
            return Err("image environment count exceeds the profile".into());
        }
        let mut entries = Vec::new();
        for entry in values {
            let entry = entry.as_str().ok_or("image Env contains a non-string declaration")?;
            let redacted = if let Some((key, value)) = entry.split_once('=') {
                format!(
                    "{}={}",
                    aa_core::text::redact_sensitive_text(key).map_err(str::to_string)?,
                    aa_core::text::redact_named_value(key, value).map_err(str::to_string)?
                )
            } else {
                aa_core::text::redact_sensitive_text(entry).map_err(str::to_string)?
            };
            entries.push(redacted);
        }
        environment = json!(entries);
    }
    let keys = |name: &str| -> Result<Value> {
        match config.get(name).filter(|value| !value.is_null()) {
            Some(value) => Ok(json!(
                value
                    .as_object()
                    .ok_or("image ports/volumes declaration is not an object")?
                    .keys()
                    .map(|key| aa_core::text::redact_sensitive_text(key).map_err(str::to_string))
                    .collect::<Result<Vec<_>>>()?
            )),
            None => Ok(Value::Null),
        }
    };
    let rootfs = value.get("rootfs").ok_or("image config has no rootfs declaration")?;
    let rootfs_type = scalar(rootfs.get("type"))?;
    let diffs = if rootfs.get("type").and_then(Value::as_str) == Some("layers") {
        let rows = array(rootfs, "diff_ids", MAX_LAYERS)?;
        let mut diffs = Vec::new();
        for row in rows {
            let digest = row.as_str().ok_or("rootfs.diff_ids contains a non-string value")?;
            sha256_name(digest)?;
            diffs.push(digest.to_string());
        }
        Some(diffs)
    } else {
        None
    };
    let fields = json!({"architecture":architecture,"os":os,"variant":scalar(value.get("variant"))?,"entrypoint":string_array(config.get("Entrypoint"),4096)?,
        "cmd":string_array(config.get("Cmd"),4096)?,"env":environment,"ports":keys("ExposedPorts")?,"volumes":keys("Volumes")?,"labels":annotations(config.get("Labels"))?,
        "user":scalar(config.get("User"))?,"working_directory":scalar(config.get("WorkingDir"))?,"rootfs_type":rootfs_type,
        "uninterpreted_config_keys":config.keys().filter(|key| !matches!(key.as_str(),"Entrypoint"|"Cmd"|"Env"|"ExposedPorts"|"Volumes"|"Labels"|"User"|"WorkingDir")).map(|key|aa_core::text::redact_sensitive_text(key).map_err(str::to_string)).collect::<Result<Vec<_>>>()?});
    Ok((fields, diffs))
}

fn scalar(value: Option<&Value>) -> Result<Value> {
    let Some(value) = value.filter(|value| !value.is_null()) else { return Ok(Value::Null) };
    let text = value.as_str().ok_or("selected image scalar field is not a string")?;
    if text.len() > 4096 {
        return Err("selected image scalar exceeds the 4096-byte profile".into());
    }
    Ok(json!(aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?))
}

fn merge_fields(target: &mut Value, fields: Value) {
    if let (Some(target), Some(fields)) = (target.as_object_mut(), fields.as_object()) {
        for (key, value) in fields {
            target.insert(key.clone(), value.clone());
        }
    }
}

impl Analyzer for Image {
    fn id(&self) -> &'static str {
        "image"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let mut scopes = BTreeSet::new();
        let mut candidates = 0usize;
        let mut cache = NamespaceCache::default();
        let mut candidate_json = json::Budget::default();
        let mut published_bytes = 0usize;
        for marker in tree.artifacts().iter().filter(|file| file.name() == "oci-layout") {
            candidates += 1;
            if candidates > MAX_MANIFESTS {
                out.limitation("image.metadata-unread", Some(marker), Some("image namespace budget exhausted".into()));
                break;
            }
            let namespace = match Namespace::new_cached(tree, marker, &mut cache) {
                Ok(namespace) => namespace,
                Err(detail) => {
                    out.limitation("image.metadata-unread", Some(marker), Some(detail));
                    continue;
                }
            };
            scopes.insert((namespace.prefix.clone(), namespace.parent.map(str::to_string)));
            let mut reader = Reader::new(namespace);
            reader.published_bytes = published_bytes;
            let source = match reader.oci(marker) {
                Ok(source) => source,
                Err(detail) => {
                    reader.issue("image.metadata-unread", detail);
                    marker
                }
            };
            published_bytes = reader.published_bytes;
            retain(reader, "oci", source, out);
        }
        for marker in tree.artifacts().iter().filter(|file| file.name() == "manifest.json") {
            let prefix = marker.path.rsplit_once('/').map_or("", |(prefix, _)| prefix);
            if scopes.contains(&(prefix.to_string(), marker.parent.clone())) || marker.size > 2 * 1024 * 1024 {
                continue;
            }
            let bytes = match tree.read(&marker.path) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let document = match json::parse(&bytes, &mut candidate_json) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if !document.as_array().is_some_and(|rows| rows.iter().any(|row| row.get("Config").is_some() && row.get("Layers").is_some())) {
                continue;
            }
            candidates += 1;
            if candidates > MAX_MANIFESTS {
                out.limitation("image.metadata-unread", Some(marker), Some("image namespace budget exhausted".into()));
                break;
            }
            let namespace = match Namespace::new_cached(tree, marker, &mut cache) {
                Ok(namespace) => namespace,
                Err(detail) => {
                    out.limitation("image.metadata-unread", Some(marker), Some(detail));
                    continue;
                }
            };
            let mut reader = Reader::new(namespace);
            reader.published_bytes = published_bytes;
            match reader.docker(marker, &document) {
                Ok(()) => {}
                Err(detail) => reader.issue("image.metadata-unread", detail),
            }
            published_bytes = reader.published_bytes;
            retain(reader, "docker-save", marker, out);
        }
    }
}

fn retain(reader: Reader<'_>, format: &str, source: &Artifact, out: &mut Output) {
    let owner = reader.namespace.owner;
    out.fact(
        owner,
        "image.package",
        json!({"format":format,"source":source.path,"complete":!reader.failed,"merged_filesystem":false,
        "manifests":reader.manifests,"descriptor_edges":reader.edges,"signature_verified":false}),
    );
    out.kind(owner, if format == "oci" { "oci-image" } else { "docker-image" });
    if !reader.manifests.is_empty() {
        out.finding(
            Finding::new(Section::Composition, "image", "image.contents", Confidence::Verified, Severity::Info)
                .param("count", reader.manifests.len())
                .evidence(Evidence::field(
                    source,
                    if format == "oci" { "/manifests" } else { "Docker-save manifest array" },
                    json!({"images":reader.manifests.len(),"descriptor_edges":reader.edges}),
                )),
        );
    }
    for manifest in &reader.manifests {
        let relevant =
            ["entrypoint", "cmd", "env", "ports", "volumes"].iter().any(|key| manifest.get(*key).is_some_and(|value| !value.is_null()));
        if relevant && let Some(config) = manifest["config_source"].as_str().and_then(|path| reader.namespace.tree.get(path)) {
            out.finding(Finding::new(Section::Capabilities,"image","image.configuration",Confidence::Verified,Severity::Info)
                .evidence(Evidence::field(config,"/config",json!({"entrypoint":manifest["entrypoint"],"cmd":manifest["cmd"],"env":manifest["env"],"ports":manifest["ports"],"volumes":manifest["volumes"]}))));
        }
    }
    if !reader.layer_facts.is_empty() {
        let mut finding = Finding::new(Section::Structure, "image", "image.layers", Confidence::Verified, Severity::Info)
            .param("count", reader.layer_facts.len());
        for (tar, value) in reader.layer_facts.iter().take(5) {
            let entries = value["entries"].as_array();
            if let Some(entry) = entries.and_then(|entries| {
                entries.iter().find(|entry| !entry["whiteout"].is_null() || !entry["link_target"].is_null()).or(entries.first())
            }) {
                // Effective names, link targets and sizes may come from preceding
                // PAX/GNU records rather than the final 512-byte entry header.
                finding = finding.evidence(Evidence::bytes(
                    tar,
                    entry["metadata_offset"].as_u64().unwrap_or(0),
                    entry["metadata_length"].as_u64().unwrap_or(0),
                    entry.clone(),
                ));
            } else {
                finding = finding.evidence(Evidence::whole(tar, json!({"entries":0})));
            }
        }
        out.finding(finding);
    }
    for (file, value) in reader.layer_facts {
        out.fact(file, "image.layer-entries", value);
    }
    for (code, detail) in reader.issues {
        out.limitation(&code, Some(owner), Some(detail));
    }
    out.limitation("image.layer-semantics", Some(owner), None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;
    use std::io::{Cursor, Read, Write};

    fn tar(rows: &[(&str, &[u8], u8, Option<&str>)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, bytes, kind, link) in rows {
            let mut header = tar::Header::new_ustar();
            header.set_mode(if *kind == b'2' { 0o777 } else { 0o644 });
            header.set_entry_type(tar::EntryType::new(*kind));
            header.set_size(bytes.len() as u64);
            if let Some(link) = link {
                header.set_link_name(link).expect("controlled link declaration");
            }
            header.set_cksum();
            builder.append_data(&mut header, name, Cursor::new(*bytes)).expect("constructed image TAR member");
        }
        builder.into_inner().expect("finish constructed TAR")
    }
    fn digest(bytes: &[u8]) -> String {
        format!("sha256:{}", aa_core::sha256_hex(bytes))
    }
    fn blob_name(bytes: &[u8]) -> String {
        format!("blobs/sha256/{}", aa_core::sha256_hex(bytes))
    }
    fn artifact(path: &str, bytes: &[u8], parent: Option<&str>) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: String::new(), sha1: String::new(), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    struct TestTree {
        files: Vec<Artifact>,
        bytes: BTreeMap<String, Vec<u8>>,
        summary: BTreeMap<String, Value>,
    }
    impl Tree for TestTree {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.bytes.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }
        fn summary(&self) -> &BTreeMap<String, Value> {
            &self.summary
        }
    }
    impl TestTree {
        fn new(bytes: Vec<u8>) -> Self {
            let mut tree = Self {
                files: Vec::new(),
                bytes: BTreeMap::new(),
                summary: BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]),
            };
            tree.add("image.tar", bytes, None);
            tree.files.sort_by(|a, b| a.path.cmp(&b.path));
            tree
        }
        fn add(&mut self, path: &str, bytes: Vec<u8>, parent: Option<&str>) {
            let mut file = artifact(path, &bytes, parent);
            if bytes.starts_with(b"\x1f\x8b\x08") {
                file.unpacked_by = Some("stream".into());
                file.kind = Some("gzip".into());
                let mut decoded = Vec::new();
                if flate2::read::GzDecoder::new(&bytes[..]).read_to_end(&mut decoded).is_ok() {
                    self.add(&format!("{path}/content"), decoded, Some(path));
                }
            } else if bytes.len() >= 512 && bytes.get(257..262) == Some(b"ustar") {
                file.unpacked_by = Some("tar".into());
                file.kind = Some("tar".into());
                let mut budget = crate::MAX_ENTRIES;
                let index = tar_index(&bytes, &mut budget);
                for entry in index.entries.iter().filter(|entry| matches!(entry.kind, 0 | b'0')) {
                    if let Some(name) = &entry.logical {
                        let data =
                            crate::extent(&bytes, entry.offset as usize, entry.size as usize).expect("constructed data extent").to_vec();
                        self.add(&format!("{path}/{name}"), data, Some(path));
                    }
                }
            }
            self.bytes.insert(path.into(), bytes);
            self.files.push(file);
        }
    }
    #[derive(Default)]
    struct Options {
        docker: bool,
        bad_diff: bool,
        missing_layer: bool,
        tamper_layer: bool,
        duplicate_index: bool,
        duplicate_json: bool,
        bad_config_path: bool,
        empty_layer: bool,
    }
    fn fixture(options: Options) -> Vec<u8> {
        let layer = if options.empty_layer {
            vec![0; 1024]
        } else {
            tar(&[
                ("etc/config", b"inert payload", b'0', None),
                ("etc/alias", b"", b'1', Some("etc/config")),
                ("usr/link", b"", b'2', Some("../etc/config")),
                ("old/.wh.gone", b"", b'0', None),
                ("cache/.wh..wh..opq", b"", b'0', None),
            ])
        };
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&layer).expect("gzip layer");
        let compressed = gzip.finish().expect("finish gzip");
        let diff = if options.bad_diff { format!("sha256:{}", "0".repeat(64)) } else { digest(&layer) };
        let config = if options.duplicate_json {
            br#"{"architecture":"amd64","os":"linux","config":{"Env":[],"Env":["PASSWORD=secret"]},"rootfs":{"type":"layers","diff_ids":[]}}"#.to_vec()
        } else {
            serde_json::to_vec(&json!({"architecture":"amd64","os":"linux","config":{"Entrypoint":["/not-run","--password","argv secret"],"Cmd":["literal","$(not-a-command)"],
                "Env":["PASSWORD=two words","PLAIN=literal"],"ExposedPorts":{"80/tcp":{}},"Volumes":{"/data":{}},"Labels":{"org.opencontainers.image.title":"Fixture"}},"rootfs":{"type":"layers","diff_ids":[diff]}})).expect("config JSON")
        };
        if options.docker {
            let config_name = format!("{}.json", aa_core::sha256_hex(&config));
            let manifest=serde_json::to_vec(&json!([{"Config":if options.bad_config_path{"../outside.json"}else{&config_name},"RepoTags":["fixture:1"],"Layers":["layer/layer.tar"]}])).expect("Docker-save manifest");
            let mut rows = vec![("manifest.json", manifest.as_slice(), b'0', None), (config_name.as_str(), config.as_slice(), b'0', None)];
            if !options.missing_layer {
                rows.push(("layer/layer.tar", layer.as_slice(), b'0', None));
            }
            return tar(&rows);
        }
        let config_name = blob_name(&config);
        let layer_name = blob_name(&compressed);
        let manifest=serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_MANIFEST,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":digest(&config),"size":config.len()},
            "layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":digest(&compressed),"size":compressed.len()}]})).expect("OCI manifest");
        let manifest_name = blob_name(&manifest);
        let index=serde_json::to_vec(&json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":[{"mediaType":OCI_MANIFEST,"digest":digest(&manifest),"size":manifest.len(),
            "annotations":{"org.opencontainers.image.ref.name":"fixture:1"}}]})).expect("OCI index");
        let mut changed = compressed.clone();
        if options.tamper_layer {
            changed[20] ^= 1;
        }
        let mut rows = vec![
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#.as_slice(), b'0', None),
            ("index.json", index.as_slice(), b'0', None),
            (config_name.as_str(), config.as_slice(), b'0', None),
            (manifest_name.as_str(), manifest.as_slice(), b'0', None),
        ];
        if !options.missing_layer {
            rows.push((layer_name.as_str(), changed.as_slice(), b'0', None));
        }
        if options.duplicate_index {
            rows.push(("./index.json", index.as_slice(), b'0', None));
        }
        tar(&rows)
    }
    fn analyze(bytes: Vec<u8>) -> (TestTree, Output) {
        let tree = TestTree::new(bytes);
        let mut out = Output::default();
        Image.analyze_tree(&tree, &mut out);
        (tree, out)
    }

    fn members(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut remaining = crate::MAX_ENTRIES;
        tar_index(bytes, &mut remaining)
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, 0 | b'0'))
            .map(|entry| {
                (entry.path.clone(), crate::extent(bytes, entry.offset as usize, entry.size as usize).expect("member extent").to_vec())
            })
            .collect()
    }
    fn repack(rows: &[(String, Vec<u8>)]) -> Vec<u8> {
        let borrowed: Vec<_> = rows.iter().map(|(name, bytes)| (name.as_str(), bytes.as_slice(), b'0', None)).collect();
        tar(&borrowed)
    }

    #[test]
    fn invalid_first_image_records_do_not_hide_independent_valid_siblings() {
        for (field, invalid) in
            [("Config", json!("missing-config.json")), ("Config", json!({"invalid":"value"})), ("RepoTags", json!({"invalid":"value"}))]
        {
            let mut rows = members(&fixture(Options { docker: true, ..Options::default() }));
            let manifest = rows.iter_mut().find(|(name, _)| name == "manifest.json").expect("Docker control");
            let mut document: Value = serde_json::from_slice(&manifest.1).expect("manifest");
            let good = document[0].clone();
            let mut bad = good.clone();
            bad[field] = invalid;
            document = json!([bad, good]);
            manifest.1 = serde_json::to_vec(&document).expect("two image records");
            let (_, out) = analyze(repack(&rows));
            let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("partial package").value;
            assert_eq!(package["complete"], false);
            let retained = package["manifests"].as_array().expect("retained independent manifests");
            assert_eq!(retained.len(), 1);
            assert_eq!(retained[0]["manifest_position"], 1);
            assert_eq!(retained[0]["complete"], true);
            assert_eq!(retained[0]["layers"][0]["entries"].as_array().expect("captured good layer").len(), 5);
        }
        let mut rows = members(&fixture(Options::default()));
        let index = rows.iter_mut().find(|(name, _)| name == "index.json").expect("OCI index");
        let mut document: Value = serde_json::from_slice(&index.1).expect("index");
        let good = document["manifests"][0].clone();
        let mut bad = good.clone();
        bad["annotations"] = json!(["invalid object"]);
        document["manifests"] = json!([bad, good]);
        index.1 = serde_json::to_vec(&document).expect("two descriptors");
        let (_, out) = analyze(repack(&rows));
        let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("partial OCI package").value;
        assert_eq!(package["complete"], false);
        assert_eq!(package["manifests"].as_array().expect("valid later descriptor").len(), 1);
        assert_eq!(package["manifests"][0]["complete"], true);
    }

    #[test]
    fn effective_pax_link_declarations_reference_their_extension_bytes() {
        let mut builder = tar::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("linkpath", b"../outside".as_slice()), ("path", b"effective-alias".as_slice())])
            .expect("PAX declarations");
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_mode(0o777);
        header.set_size(0);
        header.set_link_name("benign").expect("raw base link");
        header.set_cksum();
        builder.append_data(&mut header, "alias", Cursor::new([])).expect("link header");
        let layer = builder.into_inner().expect("finalized PAX layer");
        let mut remaining = crate::MAX_ENTRIES;
        let parsed = tar_index(&layer, &mut remaining);
        assert!(parsed.complete, "{:?}", parsed.issues);
        let entry = &parsed.entries[0];
        assert_eq!(entry.link.as_deref(), Some("../outside"));
        assert_eq!(entry.path, "effective-alias");
        let raw_header = &layer[entry.header as usize..entry.header as usize + 512];
        assert!(!raw_header.windows(10).any(|window| window == b"../outside"));
        let metadata = &layer[entry.metadata_offset as usize..(entry.metadata_offset + entry.metadata_length) as usize];
        assert!(metadata.windows(10).any(|window| window == b"../outside"));
        assert!(metadata.windows(15).any(|window| window == b"effective-alias"));
        assert_eq!(entry.metadata_length, 1536);
        let mut tree = TestTree::new(fixture(Options::default()));
        tree.add("pax.tar", layer.clone(), None);
        let marker = tree.files.iter().find(|file| file.name() == "oci-layout").expect("namespace marker");
        let mut reader = Reader::new(Namespace::new(&tree, marker).expect("original namespace"));
        let source = tree.files.iter().find(|file| file.path == "pax.tar").expect("source TAR");
        reader.layer(source, "application/vnd.oci.image.layer.v1.tar", Some(&digest(&layer)), &mut json!({})).expect("PAX layer inventory");
        let mut out = Output::default();
        retain(reader, "oci", marker, &mut out);
        let finding = out.findings.iter().find(|finding| finding.rule == "image.layers").expect("layer evidence");
        let evidence = &finding.evidence[0];
        assert_eq!(evidence.value["link_target"], "../outside");
        let aa_core::Location::Bytes { offset, length } = evidence.location else { panic!("expected exact metadata byte span") };
        let observed = &tree.bytes[&evidence.artifact][offset as usize..(offset + length) as usize];
        assert!(observed.windows(10).any(|window| window == b"../outside"));
    }

    #[test]
    fn native_writer_archives_match_hash_bound_independent_config_and_every_layer_entry() {
        let references: Value =
            serde_json::from_str(include_str!("../tests/data/native-image.ref.json")).expect("native comparison record");
        let fixtures: &[(&[u8], &str, &str)] = &[
            (
                include_bytes!("../tests/data/native-image.oci.tar"),
                "oci",
                "2f2df7cea6652176d4dd23de2e143510ab423a9ec45ad89daeb1c46c16a686c5",
            ),
            (
                include_bytes!("../tests/data/native-image.docker.tar"),
                "docker-save",
                "7f212f0198616f6618b5d0dc1b2a66de9f25b2fa2e1ab8a1bc80c1070626d2fd",
            ),
        ];
        for (bytes, format, hash) in fixtures {
            assert_eq!(aa_core::sha256_hex(bytes), *hash);
            let reference = references
                .as_array()
                .expect("comparison records")
                .iter()
                .find(|row| row["sha256"] == *hash)
                .expect("exact native source hash");
            assert!(reference["checks"].as_array().expect("native checks").iter().all(|check| check["matches"] == true));
            let (tree, out) = analyze(bytes.to_vec());
            let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("real native image archive").value;
            assert_eq!(package["format"], *format);
            assert_eq!(package["complete"], true, "{:?}", out.limitations);
            assert_eq!(package["merged_filesystem"], false);
            let actual = &package["manifests"][0];
            let native = &reference["native"]["manifests"][0];
            for key in ["architecture", "os"] {
                assert_eq!(actual[key], native["config"][key]);
            }
            assert_eq!(actual["config_digest"], native["config_digest"]);
            assert_eq!(actual["entrypoint"], native["config"]["config"]["Entrypoint"]);
            assert_eq!(actual["cmd"], native["config"]["config"]["Cmd"]);
            assert_eq!(actual["env"][1], "PASSWORD=[redacted]");
            assert_eq!(actual["layers"].as_array().expect("actual layers").len(), 3);
            for (layer, expected) in
                actual["layers"].as_array().expect("actual layers").iter().zip(native["layers"].as_array().expect("native layers"))
            {
                assert_eq!(layer["diff_id_state"], "matched");
                assert_eq!(layer["computed_diff_id"], expected["diff_id"]);
                assert_eq!(layer["declared_digest"], expected["declared_digest"]);
                let entries = layer["entries"].as_array().expect("original TAR inventory");
                let expected_entries = expected["entries"].as_array().expect("native TAR inventory");
                assert_eq!(entries.len(), expected_entries.len());
                for (entry, expected) in entries.iter().zip(expected_entries) {
                    assert_eq!(
                        entry["path"].as_str().expect("declared path").trim_end_matches('/'),
                        expected["path"].as_str().expect("native path").trim_end_matches('/')
                    );
                    for key in ["type", "link_target", "whiteout", "header_offset", "offset", "size", "mode"] {
                        assert_eq!(entry[key], expected[key], "native entry field {key}");
                    }
                    if let Some(hash) = expected["sha256"].as_str() {
                        let path = entry["captured_source"].as_str().expect("captured original regular data");
                        assert_eq!(aa_core::sha256_hex(&tree.bytes[path]), hash);
                    }
                }
            }
        }
    }

    #[test]
    fn oci_and_docker_save_bind_configs_ordered_layers_diffids_and_literal_declarations() {
        for docker in [false, true] {
            let (tree, out) = analyze(fixture(Options { docker, ..Options::default() }));
            let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("image package").value;
            assert_eq!(package["format"], if docker { "docker-save" } else { "oci" });
            assert_eq!(package["complete"], true, "{:?}", out.limitations);
            assert_eq!(package["merged_filesystem"], false);
            let manifest = &package["manifests"][0];
            assert_eq!(manifest["env"][0], "PASSWORD=[redacted]");
            assert_eq!(manifest["entrypoint"][2], "[redacted]");
            assert_eq!(manifest["cmd"][1], "$(not-a-command)");
            assert_eq!(manifest["ports"], json!(["80/tcp"]));
            assert_eq!(manifest["volumes"], json!(["/data"]));
            let layer = &manifest["layers"][0];
            assert_eq!(layer["diff_id_state"], "matched");
            assert_eq!(layer["entries"].as_array().expect("entry list").len(), 5);
            assert_eq!(layer["entries"][3]["whiteout"]["kind"], "remove");
            assert_eq!(layer["entries"][4]["whiteout"]["kind"], "opaque");
            assert_eq!(layer["entries"][1]["captured"], false);
            assert_eq!(layer["entries"][2]["link_target"], "../etc/config");
            let tar = layer["tar_source"].as_str().expect("actual TAR source");
            for entry in layer["entries"].as_array().expect("entries") {
                let offset = entry["header_offset"].as_u64().expect("header span") as usize;
                assert!(tree.bytes[tar].get(offset..offset + 512).is_some());
            }
            assert!(!serde_json::to_string(&package).expect("structured fact").contains("two words"));
        }
    }

    #[test]
    fn missing_tampered_and_wrong_diffid_layers_are_distinct_explicit_states() {
        for options in [
            Options { missing_layer: true, ..Options::default() },
            Options { tamper_layer: true, ..Options::default() },
            Options { bad_diff: true, ..Options::default() },
        ] {
            let (_, out) = analyze(fixture(options));
            let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("partial image").value;
            assert_eq!(package["complete"], false);
            assert_eq!(package["manifests"][0]["complete"], false);
            assert!(out.limitations.iter().any(|gap| matches!(gap.code.as_str(), "image.layer-unread" | "image.digest-mismatch")));
        }
    }

    #[test]
    fn duplicate_original_members_json_and_noncanonical_paths_never_establish_complete_images() {
        let (_, out) = analyze(fixture(Options { duplicate_index: true, ..Options::default() }));
        assert!(out.limitations.iter().any(|gap| gap.code == "image.metadata-unread"));
        assert!(!out.facts.iter().any(|fact| fact.key == "image.package"));
        for options in
            [Options { duplicate_json: true, ..Options::default() }, Options { docker: true, bad_config_path: true, ..Options::default() }]
        {
            let (_, out) = analyze(fixture(options));
            assert!(out.limitations.iter().any(|gap| gap.code == "image.metadata-unread"));
            assert!(out.facts.iter().any(|fact| fact.key == "image.package" && fact.value["complete"] == false));
        }
    }

    #[test]
    fn empty_tar_layers_and_reader_budgets_have_explicit_semantics() {
        let (_, out) = analyze(fixture(Options { docker: true, empty_layer: true, ..Options::default() }));
        let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("empty layer image").value;
        assert_eq!(package["complete"], true, "{:?}", out.limitations);
        assert_eq!(package["manifests"][0]["layers"][0]["entries"], json!([]));
        let bytes = tar(&[("entry", b"x", b'0', None)]);
        let mut remaining = 0;
        let index = tar_index(&bytes, &mut remaining);
        assert!(!index.complete);
        assert!(index.issues[0].contains("budget"));
        let mut huge = artifact("too-big", b"x", None);
        huge.size = MAX_BYTES as u64 + 1;
        let tree = TestTree::new(fixture(Options::default()));
        let marker = tree.files.iter().find(|file| file.name() == "oci-layout").expect("marker");
        let mut reader = Reader::new(Namespace::new(&tree, marker).expect("original namespace"));
        assert!(reader.hash(&huge).is_err());
        let layer = tree
            .files
            .iter()
            .find(|file| file.unpacked_by.as_deref() == Some("tar") && file.path.contains("/content"))
            .expect("captured layer");
        reader.entries = 0;
        let mut row = json!({});
        let expected = format!("sha256:{}", reader.hash(layer).expect("measured digest"));
        reader.layer(layer, "application/vnd.oci.image.layer.v1.tar", Some(&expected), &mut row).expect("partial inventory retained");
        assert_eq!(row["complete"], false);
        assert!(reader.issues.iter().any(|(_, detail)| detail.contains("budget")));
        let marker = tree.files.iter().find(|file| file.name() == "oci-layout").expect("marker");
        let mut reader = Reader::new(Namespace::new(&tree, marker).expect("original namespace"));
        reader.published_bytes = MAX_PUBLISHED;
        let mut row = json!({});
        reader.layer(layer, "application/vnd.oci.image.layer.v1.tar", Some(&expected), &mut row).expect("bounded published prefix");
        assert_eq!(row["entries"], json!([]));
        assert_eq!(row["inventory_complete"], false);
        assert_eq!(row["capture_complete"], false);
        assert_eq!(row["complete"], false);
        assert!(reader.issues.iter().any(|(_, detail)| detail.contains("published-inventory")));
    }

    #[test]
    fn compressed_empty_layers_and_escaped_docker_keys_keep_their_original_meaning() {
        let (_, out) = analyze(fixture(Options { empty_layer: true, ..Options::default() }));
        let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("gzip empty image layer").value;
        assert_eq!(package["complete"], true, "{:?}", out.limitations);
        let original = fixture(Options { docker: true, ..Options::default() });
        let mut remaining = crate::MAX_ENTRIES;
        let index = tar_index(&original, &mut remaining);
        let owned: Vec<_> = index
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, 0 | b'0'))
            .map(|entry| {
                let mut bytes = crate::extent(&original, entry.offset as usize, entry.size as usize).expect("original member").to_vec();
                if entry.path == "manifest.json" {
                    bytes = String::from_utf8(bytes)
                        .expect("manifest JSON")
                        .replace("\"Config\"", "\"Con\\u0066ig\"")
                        .replace("\"Layers\"", "\"\\u004cayers\"")
                        .into_bytes();
                }
                (entry.path.clone(), bytes)
            })
            .collect();
        let rows: Vec<_> = owned.iter().map(|(name, bytes)| (name.as_str(), bytes.as_slice(), b'0', None)).collect();
        let (_, out) = analyze(tar(&rows));
        assert!(out.facts.iter().any(|fact| fact.key == "image.package" && fact.value["complete"] == true));
    }

    #[test]
    fn archive_scope_cache_is_shared_and_nested_layouts_have_distinct_owners() {
        let bytes = tar(&[("first/oci-layout", b"{}", b'0', None), ("second/oci-layout", b"{}", b'0', None)]);
        let tree = TestTree::new(bytes);
        let mut cache = NamespaceCache::default();
        let first = tree.files.iter().find(|file| file.path.ends_with("first/oci-layout")).expect("first layout marker");
        let second = tree.files.iter().find(|file| file.path.ends_with("second/oci-layout")).expect("second layout marker");
        let first_scope = Namespace::new_cached(&tree, first, &mut cache).expect("first original namespace");
        let bytes = cache.bytes;
        let entries = cache.entries;
        let second_scope = Namespace::new_cached(&tree, second, &mut cache).expect("shared original namespace");
        assert_eq!(cache.indexes.len(), 1);
        assert_eq!(cache.bytes, bytes);
        assert_eq!(cache.entries, entries);
        assert_ne!(first_scope.owner.path, second_scope.owner.path);
        let mut exhausted = NamespaceCache { bytes: MAX_BYTES, ..NamespaceCache::default() };
        assert!(Namespace::new_cached(&tree, first, &mut exhausted).is_err());
    }

    #[test]
    fn unrelated_nested_artifacts_never_satisfy_an_original_layer_member() {
        let mut tree = TestTree::new(fixture(Options::default()));
        let payload =
            tree.files.iter_mut().find(|file| file.path.ends_with("/content/etc/config")).expect("captured ordinary layer payload");
        payload.parent = Some("another-container".into());
        let mut out = Output::default();
        Image.analyze_tree(&tree, &mut out);
        let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("partial image").value;
        assert_eq!(package["complete"], false);
        let entries = package["manifests"][0]["layers"][0]["entries"].as_array().expect("layer inventory");
        assert_eq!(entries.iter().find(|entry| entry["path"] == "etc/config").expect("original declaration")["captured"], false);
    }

    #[test]
    fn unsafe_control_spellings_whiteout_targets_and_selected_scalars_are_explicit() {
        let bytes = tar(&[("index.json/", b"[]", b'0', None)]);
        let mut remaining = crate::MAX_ENTRIES;
        assert!(!tar_index(&bytes, &mut remaining).complete);
        assert_eq!(logical("./valid/name").as_deref(), Some("valid/name"));
        assert!(logical("valid/name/").is_none());
        let token = format!("ghp_{}", "a".repeat(36));
        let config = json!({"architecture":token,"os":"password=fixture","variant":"token=fixture","config":{"User":"secret=fixture","WorkingDir":"password=fixture"},"rootfs":{"type":"layers","diff_ids":[]}});
        let (fields, _) = config_fields(&config).expect("literal redacted scalar profile");
        let output = fields.to_string();
        assert!(!output.contains(&token));
        assert!(!output.contains("=fixture"));
        let mut invalid = config;
        invalid["variant"] = json!({"unexpected":"object"});
        assert!(config_fields(&invalid).is_err());
        for name in [".wh.", ".wh..", ".wh..."] {
            let bytes = tar(&[(name, b"", b'0', None)]);
            let mut tree = TestTree::new(fixture(Options { docker: true, ..Options::default() }));
            let source_path = "image.tar/layer/layer.tar";
            tree.bytes.insert(source_path.into(), bytes.clone());
            let source = tree.files.iter_mut().find(|file| file.path == source_path).expect("layer source");
            source.size = bytes.len() as u64;
            source.digests.as_mut().expect("measured test digest").sha256 = aa_core::sha256_hex(&bytes);
            let marker = tree.files.iter().find(|file| file.name() == "manifest.json").expect("Docker marker");
            let mut reader = Reader::new(Namespace::new(&tree, marker).expect("original metadata namespace"));
            let source = tree.files.iter().find(|file| file.path == source_path).expect("bounded layer");
            let mut row = json!({});
            let diff = digest(&bytes);
            reader.layer(source, "application/vnd.oci.image.layer.v1.tar", Some(&diff), &mut row).expect("invalid declaration retained");
            assert_eq!(row["complete"], false);
            assert_eq!(row["entries"][0]["whiteout"]["supported"], false);
        }
    }

    #[test]
    fn native_unfinalized_layer_descriptors_do_not_establish_complete_tar_coverage() {
        let bytes = include_bytes!("../tests/data/native-unfinalized.oci.tar");
        assert_eq!(aa_core::sha256_hex(bytes), "1666785aa68325bdb9cbeb129bbbd50a97d5f68e5f37ef0ea0b00987a67b652d");
        let (_, out) = analyze(bytes.to_vec());
        let package = &out.facts.iter().find(|fact| fact.key == "image.package").expect("native OCI metadata remains readable").value;
        assert_eq!(package["complete"], false);
        let layers = package["manifests"][0]["layers"].as_array().expect("native ordered layers");
        assert_eq!(layers.len(), 3);
        assert!(layers.iter().all(|layer| layer["diff_id_state"] == "matched"));
        assert!(layers.iter().all(|layer| layer["complete"] == false));
        assert!(
            out.limitations
                .iter()
                .any(|gap| gap.code == "image.layer-unread" && gap.detail.as_deref().is_some_and(|detail| detail.contains("trailer")))
        );
    }
}
