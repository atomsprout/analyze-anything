//! ALPM packages: original TAR entries and bounded, literal root metadata.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::Result;

pub struct Arch;

const MAX_TAR_BYTES: usize = 256 * 1024 * 1024;
const MAX_CONTROL: usize = 1024 * 1024;
const MAX_SCRIPT: usize = 256 * 1024;
const MAX_FIELDS: usize = 8192;
const MAX_LINE: usize = 16 * 1024;
const CONTROLS: [&str; 4] = [".PKGINFO", ".BUILDINFO", ".INSTALL", ".MTREE"];
const RELATIONSHIPS: [&str; 7] = ["depend", "optdepend", "makedepend", "checkdepend", "provides", "conflict", "replaces"];

const RULES: &[Rule] = &[
    Rule {
        id: "arch.identity",
        title_en: "Declared Arch package identity",
        title_zh: "Arch 软件包身份声明",
        text_en: "The root .PKGINFO declares package {name}, version {version}, architecture {architecture}. These are package declarations, not installed-state checks.",
        text_zh: "根目录的 .PKGINFO 声明了包 {name}、版本 {version}、架构 {architecture}。这些是软件包声明，没有检查安装状态。",
    },
    Rule {
        id: "arch.dependencies",
        title_en: "Arch package relationship declarations",
        title_zh: "Arch 软件包关系声明",
        text_en: "The root .PKGINFO contains {count} dependency or package-relationship declarations. Constraints and optional-dependency descriptions remain literal; no repository or host resolution was performed.",
        text_zh: "根目录的 .PKGINFO 包含 {count} 个依赖或软件包关系声明。按字面保留约束和可选依赖描述，没有查询仓库或本机状态。",
    },
    Rule {
        id: "arch.build-info",
        title_en: "Declared Arch package build information",
        title_zh: "Arch 软件包构建信息声明",
        text_en: "Selected declarations from the root .BUILDINFO were read as source data. They describe the declared build environment, not this machine or a verified reproducible build.",
        text_zh: "根目录 .BUILDINFO 的部分声明作为源数据读取。它们描述所声明的构建环境，没有检查本机或验证构建可重现性。",
    },
    Rule {
        id: "arch.install-script",
        title_en: "Declared Arch installation script",
        title_zh: "Arch 安装脚本声明",
        text_en: "The package contains a root .INSTALL script. Source text retained within the supported limits has recognizable credentials redacted; the script was not run or evaluated.",
        text_zh: "软件包根目录包含 .INSTALL 脚本。在支持限制内保留的源码会遮盖可识别凭据，没有运行或求值脚本。",
    },
    Rule {
        id: "arch.mtree",
        title_en: "Arch package MTREE member",
        title_zh: "Arch 软件包 MTREE 成员",
        text_en: "The package contains a root .MTREE member. Its size and digest are recorded; its declarations, member checksums and package authenticity were not verified.",
        text_zh: "软件包根目录包含 .MTREE 成员。已记录其大小和摘要，没有验证其中的声明、成员校验和或软件包来源真实性。",
    },
    Rule {
        id: "arch.package-unread",
        title_en: "Arch package information could not be read",
        title_zh: "Arch 软件包信息无法读取",
        text_en: "An ALPM package candidate could not be read unambiguously within the supported TAR and metadata profile. Partial observations remain available.",
        text_zh: "无法在支持的 TAR 和元数据范围内唯一确定并读取 ALPM 软件包候选项。已读取的部分观察仍然保留。",
    },
    Rule {
        id: "arch.metadata-unread",
        title_en: "Arch package metadata could not be interpreted",
        title_zh: "Arch 软件包元数据无法解释",
        text_en: "A root metadata member is ambiguous, malformed or outside the bounded text profile. Missing values are not treated as empty declarations.",
        text_zh: "根目录元数据成员不唯一、格式错误或超出有界文本范围。未将缺失值视为空声明。",
    },
    Rule {
        id: "arch.archive-semantics",
        title_en: "Arch archive declarations remain unresolved",
        title_zh: "Arch 归档声明语义未确定",
        text_en: "Link and special-file declarations remain archive metadata. Targets were not followed or materialized, and installation effects were not established.",
        text_zh: "链接和特殊文件声明仅作为归档元数据保留，没有跟随或创建目标，也没有确定安装效果。",
    },
    Rule {
        id: "arch.script-semantics",
        title_en: "Arch installation script behavior remains unresolved",
        title_zh: "Arch 安装脚本行为未确定",
        text_en: "The .INSTALL text is source data. Shell control flow, lifecycle invocation, runtime values and resulting system changes were not established.",
        text_zh: ".INSTALL 文本是源数据，没有确定 Shell 控制流、生命周期调用、运行时值或最终系统变化。",
    },
    Rule {
        id: "arch.integrity-unverified",
        title_en: "Arch package authenticity was not established",
        title_zh: "Arch 软件包来源真实性未确定",
        text_en: "Reading ALPM metadata and payload bytes does not authenticate a package. Detached signatures, repository metadata, MTREE checksums and installation eligibility were not verified.",
        text_zh: "读取 ALPM 元数据和载荷字节不能认证软件包来源。没有验证分离签名、仓库元数据、MTREE 校验和或安装适用性。",
    },
];

#[derive(Debug)]
struct Entry {
    path: String,
    logical: Option<String>,
    header: u64,
    offset: u64,
    size: u64,
    mode: Option<u32>,
    kind: u8,
    link: Option<String>,
}

impl Entry {
    fn regular(&self) -> bool {
        self.kind == b'0' || self.kind == 0
    }

    fn bytes<'a>(&self, bytes: &'a [u8], limit: usize) -> Result<&'a [u8]> {
        let size = usize::try_from(self.size).map_err(|_| "ALPM member size exceeds the address space")?;
        if size > limit {
            return Err(format!("ALPM member exceeds the {limit}-byte text profile"));
        }
        crate::extent(bytes, usize::try_from(self.offset).map_err(|_| "ALPM member offset exceeds the address space")?, size)
    }
}

#[derive(Default)]
struct Directory {
    entries: Vec<Entry>,
    issues: Vec<String>,
    complete: bool,
}

/// An original spelling is retained independently from the conservative logical name.
fn logical(path: &str) -> Option<String> {
    let name = path.strip_prefix("./").unwrap_or(path).trim_end_matches('/');
    if name.is_empty()
        || name.starts_with('/')
        || name.contains(['\\', '\0'])
        || name.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return None;
    }
    Some(name.to_string())
}

/// Reject aliases that the engine could otherwise turn into the same root control name.
fn control_alias(path: &str) -> Option<&str> {
    let replaced = path.replace('\\', "/");
    let mut parts = Vec::new();
    for part in replaced.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    if parts.len() == 1 { CONTROLS.into_iter().find(|name| parts[0] == *name) } else { None }
}

fn directory(bytes: &[u8]) -> Directory {
    let mut result = Directory::default();
    if bytes.len() > MAX_TAR_BYTES {
        result.issues.push("ALPM TAR exceeds the 256 MiB indexing profile".into());
        return result;
    }
    let mut archive = tar::Archive::new(bytes);
    let mut names = 0usize;
    let mut trailer = 0usize;
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            result.issues.push(format!("TAR directory: {error}"));
            return result;
        }
    };
    for entry in entries {
        if result.entries.len() >= crate::MAX_ENTRIES {
            result.issues.push("ALPM TAR entry budget exhausted".into());
            return result;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                result.issues.push(format!("TAR entry: {error}"));
                return result;
            }
        };
        let path = entry.path_bytes();
        let link = entry.link_name_bytes();
        let added = path.len().saturating_add(link.as_ref().map_or(0, |link| link.len()));
        names = names.saturating_add(added);
        if path.len() > 4096 || link.as_ref().is_some_and(|link| link.len() > 4096) || names > crate::MAX_METADATA {
            result.issues.push("ALPM TAR name or metadata budget exhausted".into());
            return result;
        }
        let path = match std::str::from_utf8(&path) {
            Ok(path) => path,
            Err(_) => {
                result.issues.push("ALPM TAR path is not UTF-8".into());
                return result;
            }
        };
        let link = match link.as_ref().map(|link| std::str::from_utf8(link).map_err(|_| "ALPM TAR link is not UTF-8")).transpose() {
            Ok(link) => link,
            Err(detail) => {
                result.issues.push(detail.into());
                return result;
            }
        };
        let (path, link) = match aa_core::text::redact_sensitive_text(path)
            .and_then(|path| Ok((path, link.map(aa_core::text::redact_sensitive_text).transpose()?)))
        {
            Ok(value) => value,
            Err(detail) => {
                result.issues.push(detail.into());
                return result;
            }
        };
        let row = Entry {
            logical: logical(&path),
            path,
            header: entry.raw_header_position(),
            offset: entry.raw_file_position(),
            size: entry.size(),
            mode: entry.header().mode().ok(),
            kind: entry.header().entry_type().as_byte(),
            link,
        };
        // Extents refer to the captured TAR, never the compressed parent's bytes.
        let valid_extent = usize::try_from(row.offset)
            .ok()
            .zip(usize::try_from(row.size).ok())
            .and_then(|(offset, size)| crate::extent(bytes, offset, size).ok());
        if valid_extent.is_none() {
            result.issues.push("ALPM TAR member extends beyond captured bytes".into());
            return result;
        }
        trailer = match usize::try_from(row.offset)
            .ok()
            .zip(usize::try_from(row.size).ok())
            .and_then(|(offset, size)| offset.checked_add(size))
            .and_then(|end| crate::align(end, 512).ok())
        {
            Some(end) => end,
            None => {
                result.issues.push("ALPM TAR padded member range overflow".into());
                return result;
            }
        };
        if row.mode.is_none() {
            result.issues.push("ALPM TAR mode is malformed".into());
            result.entries.push(row);
            return result;
        }
        result.entries.push(row);
    }
    // TAR readers normally stop at the first zero header. Check the whole tail so an
    // appended archive cannot hide a second control member from uniqueness checks.
    match bytes.get(trailer..) {
        Some(tail) if tail.len() >= 1024 && tail.iter().all(|byte| *byte == 0) => result.complete = true,
        _ => result.issues.push("ALPM TAR has no complete zero trailer or has unread trailing data".into()),
    }
    result
}

#[derive(Debug)]
struct Field {
    name: String,
    value: String,
    line: usize,
    offset: usize,
    length: usize,
}

fn fields(bytes: &[u8], build: bool) -> Result<Vec<Field>> {
    if bytes.len() > MAX_CONTROL {
        return Err("ALPM metadata exceeds the 1 MiB text profile".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "ALPM metadata is not UTF-8")?;
    if text.contains('\0') {
        return Err("ALPM metadata contains NUL".into());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut offset = 0usize;
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        if raw.len() > MAX_LINE {
            return Err("ALPM metadata line exceeds the 16 KiB text profile".into());
        }
        let line = raw.trim_end_matches(['\n', '\r']).trim_start_matches([' ', '\t']);
        if !line.is_empty() && !line.starts_with('#') {
            if result.len() >= MAX_FIELDS {
                return Err("ALPM metadata field budget exhausted".into());
            }
            let (name, value) = line.split_once(" = ").ok_or("ALPM metadata assignment is outside the key = value profile")?;
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err("ALPM metadata key is outside the supported ASCII profile".into());
            }
            let repeated = if build {
                matches!(name, "buildenv" | "options" | "installed")
            } else {
                RELATIONSHIPS.contains(&name) || matches!(name, "license" | "group" | "backup" | "xdata")
            };
            if !repeated && !seen.insert(name.to_string()) {
                return Err(format!("duplicate ALPM scalar field {name}"));
            }
            let value = aa_core::text::redact_named_value(name, value).map_err(str::to_string)?;
            result.push(Field { name: name.to_string(), value, line: index + 1, offset, length: raw.len() });
        }
        offset += raw.len();
    }
    Ok(result)
}

fn one<'a>(fields: &'a [Field], name: &str) -> Option<&'a str> {
    fields.iter().find(|field| field.name == name).map(|field| field.value.as_str())
}

fn identity(fields: &[Field]) -> Result<(&str, &str, &str)> {
    let name = one(fields, "pkgname").ok_or("missing pkgname")?;
    let version = one(fields, "pkgver").ok_or("missing pkgver")?;
    let architecture = one(fields, "arch").ok_or("missing arch")?;
    if name.is_empty()
        || name.len() > 256
        || name.starts_with(['-', '.'])
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte))
    {
        return Err("pkgname is outside the supported ALPM name profile".into());
    }
    if version.is_empty() || version.len() > 256 || !version.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err("pkgver is outside the supported bounded ASCII profile".into());
    }
    if architecture.is_empty() || architecture.len() > 64 || !architecture.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("arch is outside the supported ALPM architecture profile".into());
    }
    Ok((name, version, architecture))
}

fn json_fields(fields: &[Field], base: u64) -> Vec<Value> {
    fields
        .iter()
        .map(|field| {
            json!({"name": field.name, "value": field.value, "line": field.line,
            "offset": base + field.offset as u64, "length": field.length})
        })
        .collect()
}

fn root_entry<'a>(directory: &'a Directory, name: &str) -> Result<Option<&'a Entry>> {
    if !directory.complete {
        return Err("the TAR index is incomplete; root-member uniqueness was not established".into());
    }
    let matches: Vec<_> = directory.entries.iter().filter(|entry| control_alias(&entry.path) == Some(name)).collect();
    match matches.as_slice() {
        [] => Ok(None),
        [entry] if (entry.path == name || entry.path == format!("./{name}")) && entry.regular() => Ok(Some(entry)),
        [_] => Err(format!("{name} is not an unambiguous regular root member")),
        _ => Err(format!("duplicate or aliased root {name} members")),
    }
}

fn outer_package<'a>(tree: &'a dyn Tree, archive: &'a Artifact) -> &'a Artifact {
    let Some(parent) = archive.parent.as_deref().and_then(|path| tree.get(path)) else { return archive };
    // Compression is a visible layer of the same package, not another package identity.
    if parent.unpacked_by.as_deref() == Some("stream")
        && tree.artifacts().iter().filter(|file| file.parent.as_deref() == Some(&parent.path)).count() == 1
    {
        parent
    } else {
        archive
    }
}

fn source_child<'a>(tree: &'a dyn Tree, archive: &Artifact, entry: &Entry) -> Option<&'a Artifact> {
    let path = format!("{}/{}", archive.path, entry.logical.as_deref()?);
    tree.get(&path).filter(|file| {
        file.parent.as_deref() == Some(&archive.path)
            && file.size == entry.size
            && !file.facts.get("engine.entry-name").and_then(|value| value.get("colliding")).and_then(Value::as_bool).unwrap_or(false)
    })
}

impl Analyzer for Arch {
    fn id(&self) -> &'static str {
        "arch"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, archive: &Artifact, out: &mut Output) {
        if archive.unpacked_by.as_deref() != Some("tar") {
            return;
        }
        let bytes = match tree.read(&archive.path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        let directory = directory(&bytes);
        let package = outer_package(tree, archive);
        let named = package.name().contains(".pkg.tar");
        if !named && !directory.entries.iter().any(|entry| control_alias(&entry.path) == Some(".PKGINFO")) {
            return;
        }
        for issue in &directory.issues {
            out.limitation("arch.package-unread", Some(archive), Some(issue.clone()));
        }
        let mut counts = BTreeMap::new();
        for entry in &directory.entries {
            if let Some(path) = &entry.logical {
                *counts.entry(path.as_str()).or_insert(0usize) += 1;
            }
        }
        let entries: Vec<_> = directory
            .entries
            .iter()
            .map(|entry| {
                let captured = entry.regular()
                    && entry.logical.as_deref().is_some_and(|path| counts.get(path) == Some(&1))
                    && source_child(tree, archive, entry).is_some();
                json!({"path": entry.path, "logical_path": entry.logical, "header_offset": entry.header, "offset": entry.offset,
                    "size": entry.size, "mode": entry.mode, "type": entry.kind, "link_target": entry.link, "captured": captured})
            })
            .collect();
        out.fact(archive, "arch.archive-entries", json!({"package": package.path, "complete": directory.complete, "entries": entries}));
        if directory.entries.iter().any(|entry| !entry.regular() && entry.kind != b'5') {
            out.limitation("arch.archive-semantics", Some(archive), None);
        }
        let info = match root_entry(&directory, ".PKGINFO") {
            Ok(Some(info)) => info,
            Ok(None) => {
                out.limitation("arch.package-unread", Some(archive), Some("no regular root .PKGINFO member".into()));
                return;
            }
            Err(detail) => {
                out.limitation("arch.metadata-unread", Some(archive), Some(detail));
                return;
            }
        };
        out.kind(package, "arch-package");
        out.limitation("arch.integrity-unverified", Some(package), None);
        let metadata = match info.bytes(&bytes, MAX_CONTROL).and_then(|bytes| fields(bytes, false)) {
            Ok(metadata) => metadata,
            Err(detail) => {
                out.limitation("arch.metadata-unread", Some(archive), Some(format!(".PKGINFO: {detail}")));
                return;
            }
        };
        let values = json_fields(&metadata, info.offset);
        let dependencies: Vec<_> =
            values.iter().filter(|field| field["name"].as_str().is_some_and(|name| RELATIONSHIPS.contains(&name))).cloned().collect();
        let declared_licenses: Vec<_> = metadata.iter().filter(|field| field.name == "license").map(|field| field.value.as_str()).collect();
        let (name, version, architecture) = match identity(&metadata) {
            Ok(identity) => identity,
            Err(detail) => {
                out.fact(archive, "arch.pkginfo", json!({"fields": values, "identity_complete": false}));
                out.limitation("arch.metadata-unread", Some(archive), Some(format!(".PKGINFO: {detail}")));
                return;
            }
        };
        out.fact(
            package,
            "arch.package",
            json!({"name": name, "version": version, "architecture": architecture, "source": archive.path,
                "member": ".PKGINFO", "offset": info.offset, "length": info.size,
                "captured_source": source_child(tree, archive, info).map(|file| &file.path), "archive": archive.path,
                "fields": values, "dependencies": dependencies, "declared_licenses": declared_licenses}),
        );
        out.finding(
            Finding::new(Section::Identity, "arch", "arch.identity", Confidence::Verified, Severity::Info)
                .param("name", name)
                .param("version", version)
                .param("architecture", architecture)
                .evidence(Evidence::bytes(
                    archive,
                    info.offset,
                    info.size,
                    json!({"member": ".PKGINFO", "name": name, "version": version, "architecture": architecture}),
                )),
        );
        if !dependencies.is_empty() {
            out.finding(
                Finding::new(Section::Composition, "arch", "arch.dependencies", Confidence::Verified, Severity::Info)
                    .param("count", dependencies.len())
                    .evidence(Evidence::bytes(
                        archive,
                        info.offset,
                        info.size,
                        json!({"member": ".PKGINFO", "declarations": dependencies}),
                    )),
            );
        }
        for name in [".BUILDINFO", ".INSTALL", ".MTREE"] {
            match root_entry(&directory, name) {
                Ok(Some(entry)) => retain_optional(package, archive, entry, &bytes, out),
                Ok(None) => {}
                Err(detail) => out.limitation("arch.metadata-unread", Some(archive), Some(detail)),
            }
        }
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        for package in tree.artifacts().iter().filter(|file| file.facts.contains_key("arch.package")) {
            out.kind(package, "arch-package");
        }
    }
}

fn retain_optional(package: &Artifact, archive: &Artifact, entry: &Entry, bytes: &[u8], out: &mut Output) {
    let name = entry.logical.as_deref().unwrap_or("");
    if name == ".MTREE" {
        let data = match entry.bytes(bytes, MAX_TAR_BYTES) {
            Ok(data) => data,
            Err(detail) => {
                out.limitation("arch.metadata-unread", Some(archive), Some(format!(".MTREE: {detail}")));
                return;
            }
        };
        let value = json!({"member": name, "offset": entry.offset, "size": entry.size, "sha256": aa_core::sha256_hex(data),
            "declarations_interpreted": false, "checksums_verified": false});
        out.fact(package, "arch.mtree", value.clone());
        out.finding(
            Finding::new(Section::Structure, "arch", "arch.mtree", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
                archive,
                entry.offset,
                entry.size,
                value,
            )),
        );
        return;
    }
    if name == ".INSTALL" {
        out.limitation("arch.script-semantics", Some(archive), None);
    }
    let data = match entry.bytes(bytes, if name == ".INSTALL" { MAX_SCRIPT } else { MAX_CONTROL }) {
        Ok(data) => data,
        Err(detail) => {
            if name == ".INSTALL" {
                retain_unread_script(package, archive, entry, out);
            }
            out.limitation("arch.metadata-unread", Some(archive), Some(format!("{name}: {detail}")));
            return;
        }
    };
    if name == ".INSTALL" {
        let source = std::str::from_utf8(data)
            .map_err(|_| ".INSTALL is not UTF-8")
            .and_then(|text| if text.contains('\0') { Err(".INSTALL contains NUL") } else { aa_core::text::redact_sensitive_text(text) });
        match source {
            Ok(text) => {
                let value = json!({"package": package.path, "source": archive.path, "member": name, "offset": entry.offset, "length": entry.size, "text": text, "text_retained": true});
                out.fact(package, "arch.installation-declaration", value.clone());
                out.finding(
                    Finding::new(Section::Capabilities, "arch", "arch.install-script", Confidence::Verified, Severity::Info)
                        .evidence(Evidence::bytes(archive, entry.offset, entry.size, value)),
                );
            }
            Err(detail) => {
                retain_unread_script(package, archive, entry, out);
                out.limitation("arch.metadata-unread", Some(archive), Some(detail.into()));
            }
        }
        return;
    }
    let metadata = match fields(data, true) {
        Ok(metadata) => metadata,
        Err(detail) => {
            out.limitation("arch.metadata-unread", Some(archive), Some(format!(".BUILDINFO: {detail}")));
            return;
        }
    };
    if one(&metadata, "format") != Some("2") {
        out.limitation("arch.metadata-unread", Some(archive), Some(".BUILDINFO: only format 2 is interpreted".into()));
        return;
    }
    let selected_field = |field: &&Field| {
        matches!(
            field.name.as_str(),
            "format"
                | "pkgname"
                | "pkgbase"
                | "pkgver"
                | "pkgarch"
                | "pkgbuild_sha256sum"
                | "buildtool"
                | "buildtoolver"
                | "buildenv"
                | "options"
                | "installed"
        )
    };
    let uninterpreted: Vec<_> = metadata
        .iter()
        .filter(|field| !selected_field(field))
        .map(|field| json!({"name": field.name, "line": field.line, "offset": entry.offset + field.offset as u64, "length": field.length}))
        .collect();
    let selected: Vec<_> = metadata.into_iter().filter(|field| selected_field(&field)).collect();
    let value = json!({"source": archive.path, "member": ".BUILDINFO", "format": 2, "fields": json_fields(&selected, entry.offset),
        "uninterpreted_fields": uninterpreted, "reproducibility_verified": false});
    out.fact(package, "arch.build-info", value.clone());
    out.finding(
        Finding::new(Section::Provenance, "arch", "arch.build-info", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
            archive,
            entry.offset,
            entry.size,
            value,
        )),
    );
}

fn retain_unread_script(package: &Artifact, archive: &Artifact, entry: &Entry, out: &mut Output) {
    let value = json!({"package": package.path, "source": archive.path, "member": ".INSTALL", "offset": entry.offset, "length": entry.size, "text": null, "text_retained": false});
    out.fact(package, "arch.installation-declaration", value.clone());
    out.finding(
        Finding::new(Section::Capabilities, "arch", "arch.install-script", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
            archive,
            entry.offset,
            entry.size,
            value,
        )),
    );
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use aa_core::plugin::Bytes;

    use super::*;

    const INFO: &[u8] = b"# constructed fixture\npkgname = fixture\npkgver = 1:2.0-3\narch = any\nlicense = MIT\ndepend = libc>=1\noptdepend = helper: optional description\n";

    fn tar(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, body) in members {
            let mut header = tar::Header::new_ustar();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, Cursor::new(*body)).expect("append constructed member");
        }
        builder.into_inner().expect("finish constructed archive")
    }

    fn artifact(path: &str, size: usize) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: size as u64,
            digests: None,
            detected: None,
            kind: Some("tar".into()),
            entropy: None,
            unpacked_by: Some("tar".into()),
            facts: BTreeMap::new(),
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
            self.bytes.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
    fn analyze(bytes: Vec<u8>) -> Output {
        let tree = TestTree { files: vec![artifact("renamed.data", bytes.len())], bytes: BTreeMap::from([("renamed.data".into(), bytes)]) };
        let mut out = Output::default();
        Arch.analyze_file(&tree, &tree.files[0], &mut out);
        out
    }

    #[test]
    fn identity_and_literal_relationships_come_only_from_a_root_control() {
        let out = analyze(tar(&[(".PKGINFO", INFO), ("usr/.PKGINFO", b"pkgname = impostor\n")]));
        let package = &out.facts.iter().find(|fact| fact.key == "arch.package").expect("package identity").value;
        assert_eq!(package["name"], "fixture");
        assert_eq!(package["version"], "1:2.0-3");
        assert_eq!(package["source"], "renamed.data");
        assert_eq!(package["dependencies"][0]["value"], "libc>=1");
        assert_eq!(package["dependencies"][1]["value"], "helper: optional description");
        let plain = analyze(tar(&[("usr/.PKGINFO", INFO)]));
        assert!(plain.facts.is_empty());
        assert!(plain.findings.is_empty());
    }

    #[test]
    fn duplicate_controls_and_scalar_fields_do_not_establish_an_identity() {
        for bytes in [
            tar(&[(".PKGINFO", INFO), ("./.PKGINFO", INFO)]),
            tar(&[(".PKGINFO", b"pkgname = fixture\npkgname = other\npkgver = 1-1\narch = any\n")]),
            tar(&[(".PKGINFO", b"pkgname = fixture\npkgver = 1-1\n")]),
        ] {
            let out = analyze(bytes);
            assert!(!out.facts.iter().any(|fact| fact.key == "arch.package"));
            assert!(out.limitations.iter().any(|limitation| limitation.code == "arch.metadata-unread"));
        }
    }

    #[test]
    fn build_info_and_script_are_bounded_redacted_source_data() {
        let out = analyze(tar(&[(".PKGINFO", INFO),
            (".BUILDINFO", b"format = 2\npkgname = fixture\nbuildtool = devtools\ninstalled = libc-1-1-any\ninstalled = helper-2-1-any\nbuilddir = /declared/build\n"),
            (".INSTALL", b"post_install() {\n  password='fixture credential'\n  printf 'inert source'\n}\n"),
            (".MTREE", b"opaque-mtree-bytes") ]));
        let script = &out.facts.iter().find(|fact| fact.key == "arch.installation-declaration").expect("source text").value;
        assert!(!script["text"].as_str().expect("script text").contains("fixture credential"));
        assert!(script["text"].as_str().expect("script text").contains("[redacted]"));
        let build = &out.facts.iter().find(|fact| fact.key == "arch.build-info").expect("build declarations").value;
        assert_eq!(build["fields"].as_array().expect("selected fields").len(), 5);
        assert!(!build.to_string().contains("/declared/build"));
        assert!(out.limitations.iter().any(|limitation| limitation.code == "arch.script-semantics"));
        assert!(out.facts.iter().any(|fact| fact.key == "arch.mtree" && fact.value["checksums_verified"] == false));
    }

    #[test]
    fn links_are_original_declarations_and_never_host_targets() {
        let bytes = tar(&[(".PKGINFO", INFO)]);
        let mut builder = tar::Builder::new(Vec::new());
        builder.get_mut().extend_from_slice(&bytes[..bytes.len() - 1024]);
        let mut header = tar::Header::new_ustar();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("/etc/fixture-target").expect("literal link target");
        header.set_cksum();
        builder.append_data(&mut header, "usr/lib/alias", Cursor::new([])).expect("append link declaration");
        let out = analyze(builder.into_inner().expect("finish link archive"));
        let entries = &out.facts.iter().find(|fact| fact.key == "arch.archive-entries").expect("original entries").value["entries"];
        let link = entries.as_array().expect("entry list").iter().find(|entry| entry["path"] == "usr/lib/alias").expect("link metadata");
        assert_eq!(link["link_target"], "/etc/fixture-target");
        assert_eq!(link["captured"], false);
        assert!(out.limitations.iter().any(|limitation| limitation.code == "arch.archive-semantics"));
    }

    #[test]
    fn malformed_text_truncated_archives_and_exhausted_budgets_remain_explicit() {
        assert!(fields(&vec![b'a'; MAX_CONTROL + 1], false).is_err());
        assert!(fields(b"pkgname = one\0\n", false).is_err());
        assert!(fields(b"pkgname=one\n", false).is_err());
        assert!(fields(&format!("pkgdesc = {}\n", "x".repeat(MAX_LINE)).into_bytes(), false).is_err());
        assert!(fields(&"license = MIT\n".repeat(MAX_FIELDS + 1).into_bytes(), false).is_err());
        let bytes = tar(&[(".PKGINFO", INFO), ("payload", b"payload")]);
        let index = directory(&bytes);
        assert!(index.complete);
        let cut = directory(&bytes[..1025]);
        assert!(!cut.complete);
        assert!(root_entry(&cut, ".PKGINFO").is_err());
        let mut appended = bytes.clone();
        appended.extend(tar(&[(".PKGINFO", INFO)]));
        assert!(!directory(&appended).complete);
        let long_script = vec![b'x'; MAX_SCRIPT + 1];
        let out = analyze(tar(&[(".PKGINFO", INFO), (".INSTALL", &long_script)]));
        assert!(out.limitations.iter().any(|limitation| limitation.code == "arch.metadata-unread"));
        assert!(out.facts.iter().any(|fact| fact.key == "arch.installation-declaration" && fact.value["text_retained"] == false));
    }

    #[test]
    fn real_arch_libutf8proc_package_retains_identity_build_declarations_and_links() {
        let compressed = include_bytes!("../tests/data/libutf8proc-2.12.0-1-x86_64.pkg.tar.zst");
        assert_eq!(aa_core::sha256_hex(compressed), "297205aba0d093921dbfbc70b9ecf7359838f0c3418b6265af960aed12bfd072");
        let mut reader = ruzstd::decoding::StreamingDecoder::new(&compressed[..]).expect("real fixture zstd frame");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("bounded real fixture decompression");
        let out = analyze(bytes);
        let package = &out.facts.iter().find(|fact| fact.key == "arch.package").expect("real ALPM package").value;
        assert_eq!(package["name"], "libutf8proc");
        assert_eq!(package["version"], "2.12.0-1");
        assert_eq!(package["architecture"], "x86_64");
        assert_eq!(package["declared_licenses"], json!(["MIT", "custom"]));
        let directory = &out.facts.iter().find(|fact| fact.key == "arch.archive-entries").expect("real archive entries").value;
        assert_eq!(directory["complete"], true);
        assert_eq!(directory["entries"].as_array().expect("entries").len(), 16);
        assert!(
            directory["entries"]
                .as_array()
                .expect("entries")
                .iter()
                .any(|entry| entry["path"] == "usr/lib/libutf8proc.so" && entry["link_target"] == "/usr/lib/libutf8proc.so.3.3.0")
        );
        assert!(out.facts.iter().any(|fact| fact.key == "arch.build-info"));
        assert!(out.facts.iter().any(|fact| fact.key == "arch.mtree"));
        assert!(
            !out.limitations.iter().any(|limitation| matches!(limitation.code.as_str(), "arch.package-unread" | "arch.metadata-unread"))
        );
    }
}
