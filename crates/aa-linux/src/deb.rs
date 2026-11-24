//! Debian ar members and the control archive's literal Deb822 declarations.

use std::collections::BTreeSet;

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::{MAX_METADATA, Result, extent};

pub struct Deb;

const RULES: &[Rule] = &[
    Rule {
        id: "deb.triggers",
        title_en: "Declared Debian triggers",
        title_zh: "Debian 触发器声明",
        text_en: "The control archive contains trigger declarations. Their source text is retained as data; activation, ordering and effects were not evaluated.",
        text_zh: "控制归档包含触发器声明。原文作为数据保留，没有求值其激活、顺序或效果。",
    },
    Rule {
        id: "deb.action-unread",
        title_en: "Debian installation declaration text could not be retained",
        title_zh: "Debian 安装声明文本无法保留",
        text_en: "An installation declaration was captured as bytes, but its text could not be retained unambiguously within the supported profile.",
        text_zh: "已捕获安装声明的字节，但无法在支持范围内唯一确定并保留其文本。",
    },
    Rule {
        id: "deb.trigger-semantics",
        title_en: "Debian trigger behavior remains unresolved",
        title_zh: "Debian 触发器行为未确定",
        text_en: "Trigger declarations are source data. Their runtime activation, ordering and resulting system changes were not established.",
        text_zh: "触发器声明是源数据，没有确定其运行时激活、顺序或最终系统变化。",
    },
    Rule {
        id: "deb.archive-semantics",
        title_en: "Debian archive semantics remain unresolved",
        title_zh: "Debian 归档语义未确定",
        text_en: "A TAR link or special-file declaration was retained as metadata. Its target and installation effects were not followed or materialized.",
        text_zh: "TAR 链接或特殊文件声明作为元数据保留，没有跟随目标或实现安装效果。",
    },
    Rule {
        id: "deb.contents",
        title_en: "Debian package contents",
        title_zh: "Debian 包内容",
        text_en: "The Debian package declares separate control and payload archives. Their bytes were read without installation.",
        text_zh: "Debian 包分别声明了控制归档与载荷归档，按字节读取，没有安装。",
    },
    Rule {
        id: "deb.identity",
        title_en: "Declared Debian package identity",
        title_zh: "Debian 包身份声明",
        text_en: "The control file declares package {name}, version {version}, architecture {architecture}. These are declarations, not an installed-state check.",
        text_zh: "控制文件声明了包 {name}、版本 {version}、架构 {architecture}。这些是声明，没有检查安装状态。",
    },
    Rule {
        id: "deb.dependencies",
        title_en: "Debian dependency declarations",
        title_zh: "Debian 依赖声明",
        text_en: "The control file contains {count} dependency or package-relationship fields. Alternatives and version constraints are retained literally; no repository or host resolution was performed.",
        text_zh: "控制文件包含 {count} 个依赖或包关系字段。按字面保留候选项与版本约束，没有查询仓库或本机状态。",
    },
    Rule {
        id: "deb.install-script",
        title_en: "Declared Debian maintainer script",
        title_zh: "Debian 维护脚本声明",
        text_en: "The control archive contains {name}. Its source bytes are available as evidence; the script was not run or evaluated.",
        text_zh: "控制归档包含 {name}。原始字节作为证据保留，没有运行或求值脚本。",
    },
    Rule {
        id: "deb.script-semantics",
        title_en: "Debian script behavior remains unresolved",
        title_zh: "Debian 脚本行为未确定",
        text_en: "Maintainer scripts are retained as source data. Shell control flow, runtime values and resulting system changes were not established.",
        text_zh: "维护脚本作为源数据保留，没有确定 Shell 控制流、运行时值或最终系统变化。",
    },
    Rule {
        id: "deb.control-unread",
        title_en: "Debian control information could not be read",
        title_zh: "Debian 控制信息无法读取",
        text_en: "The required control file or its unambiguous container could not be read within this profile.",
        text_zh: "无法在此支持范围内读取必需的控制文件或确定其唯一容器。",
    },
    Rule {
        id: "deb.member-unread",
        title_en: "Debian member could not be read",
        title_zh: "Debian 成员无法读取",
        text_en: "A package member could not be retained or its compression profile is unsupported.",
        text_zh: "无法保留一个包成员，或其压缩方式不受支持。",
    },
    Rule {
        id: "deb.integrity-unverified",
        title_en: "Debian package authenticity was not established",
        title_zh: "Debian 包来源真实性未确定",
        text_en: "Reading the package and its checksum declarations does not authenticate it. Repository metadata, package signatures and declared member checksums were not verified.",
        text_zh: "读取包及其摘要声明不能认证来源。没有验证仓库元数据、包签名或成员摘要声明。",
    },
];

struct Member {
    name: String,
    header: usize,
    offset: usize,
    size: usize,
}
struct Directory {
    members: Vec<Member>,
    control: usize,
    data: usize,
    version: String,
}

fn parse(bytes: &[u8]) -> Result<Directory> {
    if !bytes.starts_with(b"!<arch>\n") {
        return Err("missing ar magic".into());
    }
    let mut at = 8usize;
    let mut members = Vec::new();
    let mut seen = BTreeSet::new();
    while at < bytes.len() {
        if members.len() >= 512 {
            return Err("Debian ar member budget exhausted".into());
        }
        let header = extent(bytes, at, 60)?;
        if &header[58..60] != b"`\n" {
            return Err("invalid ar header terminator".into());
        }
        let name = std::str::from_utf8(&header[..16]).map_err(|_| "ar name is not UTF-8")?.trim_end_matches(' ').trim_end_matches('/');
        if name.is_empty() || name.contains(['/', '\\', '\0']) || name.starts_with('#') {
            return Err("ar long names, path names and empty names are outside the Debian profile".into());
        }
        if !seen.insert(name.to_string()) {
            return Err("duplicate Debian ar member name".into());
        }
        let size = std::str::from_utf8(&header[48..58]).map_err(|_| "ar size is not ASCII")?.trim();
        if size.is_empty() || !size.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid decimal ar size".into());
        }
        let size = size.parse::<usize>().map_err(|_| "ar size exceeds address space")?;
        let offset = at + 60;
        extent(bytes, offset, size)?;
        let end = offset.checked_add(size).ok_or("ar member overflow")?;
        if size % 2 != 0 && extent(bytes, end, 1)? != b"\n" {
            return Err("invalid ar padding".into());
        }
        members.push(Member { name: name.to_string(), header: at, offset, size });
        at = end.checked_add(size % 2).ok_or("ar padding overflow")?;
    }
    let first = members.first().ok_or("empty Debian ar")?;
    if first.name != "debian-binary" || first.size > 4096 {
        return Err("missing bounded debian-binary member".into());
    }
    let version = std::str::from_utf8(extent(bytes, first.offset, first.size)?)
        .map_err(|_| "Debian format version is not UTF-8")?
        .lines()
        .next()
        .ok_or("empty Debian format version")?
        .to_string();
    let minor = version.strip_prefix("2.").ok_or("unsupported Debian package major version")?;
    if minor.is_empty() || !minor.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid Debian format version".into());
    }
    let mut required = members.iter().enumerate().skip(1).filter(|(_, member)| !member.name.starts_with('_'));
    let (control, member) = required.next().ok_or("missing Debian control archive")?;
    if !archive(&member.name, "control.tar") {
        return Err("unsupported or out-of-order Debian control archive".into());
    }
    let (data, member) = required.next().ok_or("missing Debian payload archive")?;
    if !archive(&member.name, "data.tar") {
        return Err("unsupported or out-of-order Debian payload archive".into());
    }
    if members.iter().skip(data + 1).any(|member| archive(&member.name, "control.tar") || archive(&member.name, "data.tar")) {
        return Err("ambiguous repeated Debian control or payload archives".into());
    }
    Ok(Directory { members, control, data, version })
}

fn archive(name: &str, stem: &str) -> bool {
    name == stem || name.strip_prefix(stem).is_some_and(|suffix| matches!(suffix, ".gz" | ".xz" | ".zst" | ".bz2" | ".lzma"))
}

impl Unpacker for Deb {
    fn id(&self) -> &'static str {
        "deb"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if bytes.starts_with(b"0.939000\n") {
            return Unpack::Failed { kind: "deb", detail: "old pre-ar Debian packages are outside the supported profile".into() };
        }
        if !bytes.starts_with(b"!<arch>\n") {
            return Unpack::NotMine;
        }
        if !bytes.get(8..24).is_some_and(|name| name.starts_with(b"debian-binary")) && file.extension().as_deref() != Some("deb") {
            return Unpack::NotMine;
        }
        let directory = match parse(bytes) {
            Ok(value) => value,
            Err(detail) => return Unpack::Failed { kind: "deb", detail },
        };
        for member in &directory.members {
            if member.name.ends_with(".lzma") {
                sink.limitation(
                    "deb.member-unread",
                    Some(format!("{}: raw LZMA stream is outside the supported compression profile", member.name)),
                );
            }
            let mut data = &bytes[member.offset..member.offset + member.size];
            match sink.add(&member.name, &mut data) {
                Ok(()) => {}
                Err(SinkError::LimitReached) => break,
                Err(SinkError::Read(detail)) => sink.limitation("deb.member-unread", Some(format!("{}: {detail}", member.name))),
            }
        }
        Unpack::Done { kind: "deb" }
    }
}

struct Field {
    name: String,
    value: String,
    line: usize,
}

fn control(bytes: &[u8]) -> Result<Vec<Field>> {
    if bytes.len() > MAX_METADATA {
        return Err("Debian control exceeds the 16 MiB metadata budget".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Debian control is not UTF-8")?;
    if text.contains('\0') {
        return Err("Debian control contains NUL".into());
    }
    let mut fields: Vec<Field> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut ended = false;
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() {
            ended = !fields.is_empty();
            continue;
        }
        if ended {
            return Err("Debian binary control has multiple stanzas".into());
        }
        if line.starts_with([' ', '\t']) {
            let previous = fields.last_mut().ok_or("orphan Debian control continuation")?;
            previous.value.push('\n');
            previous.value.push_str(line);
            continue;
        }
        if fields.len() >= 4096 {
            return Err("Debian control field budget exhausted".into());
        }
        let (name, value) = line.split_once(':').ok_or("Debian control field has no colon")?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err("invalid Debian control field name".into());
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(format!("duplicate Debian control field {name}"));
        }
        fields.push(Field { name: name.into(), value: value.trim_start_matches([' ', '\t']).into(), line: index + 1 });
    }
    for name in ["Package", "Version", "Architecture"] {
        if !fields.iter().any(|field| field.name.eq_ignore_ascii_case(name) && !field.value.is_empty() && !field.value.contains('\n')) {
            return Err(format!("missing or invalid Debian identity field {name}"));
        }
    }
    Ok(fields)
}

fn clean(file: &Artifact) -> bool {
    !file.facts.get("engine.entry-name").and_then(|value| value.get("colliding")).and_then(Value::as_bool).unwrap_or(false)
}

fn package_tar<'a>(tree: &'a dyn Tree, package: &Artifact, member: &str) -> Result<&'a Artifact> {
    let name = format!("{}/{member}", package.path);
    let mut container = tree
        .get(&name)
        .filter(|file| file.parent.as_deref() == Some(&package.path) && clean(file))
        .ok_or("control archive was not captured unambiguously")?;
    if !member.ends_with(".tar") {
        if container.unpacked_by.as_deref() != Some("stream") {
            return Err("control compression was not decoded".into());
        }
        let stem = member.rsplit_once('.').ok_or("missing compression suffix")?.0;
        let path = format!("{}/{stem}", container.path);
        container = tree
            .get(&path)
            .filter(|file| file.parent.as_deref() == Some(&container.path) && clean(file))
            .ok_or("decompressed package archive is missing or ambiguous")?;
    }
    if container.unpacked_by.as_deref() != Some("tar") {
        return Err("control archive TAR profile was not decoded".into());
    }
    Ok(container)
}

impl Analyzer for Deb {
    fn id(&self) -> &'static str {
        "deb"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("deb") {
            return;
        }
        let result = tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| parse(&bytes));
        match result {
            Ok(directory) => {
                let members: Vec<_> = directory
                    .members
                    .iter()
                    .map(|member| {
                        json!({"name": member.name, "header_offset": member.header,
                    "offset": member.offset, "size": member.size})
                    })
                    .collect();
                out.fact(
                    file,
                    "deb.package",
                    json!({"format_version": directory.version, "members": members,
                    "control_member": directory.members[directory.control].name, "data_member": directory.members[directory.data].name}),
                );
                out.finding(
                    Finding::new(Section::Structure, "deb", "deb.contents", Confidence::Verified, Severity::Info)
                        .evidence(Evidence::bytes(file, 8, 60, json!({"format_version": directory.version}))),
                );
                out.limitation("deb.integrity-unverified", Some(file), None);
            }
            Err(detail) => out.limitation("deb.control-unread", Some(file), Some(detail)),
        }
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        for package in tree.artifacts().iter().filter(|file| file.facts.contains_key("deb.package")) {
            let Some(member) = package.facts["deb.package"]["control_member"].as_str() else {
                continue;
            };
            for field in ["control_member", "data_member"] {
                if let Some(name) = package.facts["deb.package"][field].as_str() {
                    match package_tar(tree, package, name).and_then(|tar| retain_archive(tree, package, tar, out)) {
                        Ok(()) => {}
                        Err(detail) => out.limitation("deb.member-unread", Some(package), Some(format!("{name}: {detail}"))),
                    }
                }
            }
            let tar = match package_tar(tree, package, member) {
                Ok(tar) => tar,
                Err(detail) => {
                    out.limitation("deb.control-unread", Some(package), Some(detail));
                    continue;
                }
            };
            let path = format!("{}/control", tar.path);
            let field_file = tree.get(&path).filter(|file| file.parent.as_deref() == Some(&tar.path) && clean(file));
            if let Some(file) = field_file {
                match tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| control(&bytes)) {
                    Ok(fields) => retain_control(package, file, &fields, out),
                    Err(detail) => out.limitation("deb.control-unread", Some(file), Some(detail)),
                }
            } else {
                out.limitation("deb.control-unread", Some(package), Some("missing or colliding control file".into()));
            }
            for name in ["preinst", "postinst", "prerm", "postrm", "config", "triggers"] {
                let path = format!("{}/{name}", tar.path);
                if let Some(script) = tree.get(&path).filter(|file| file.parent.as_deref() == Some(&tar.path)) {
                    if !clean(script) {
                        out.limitation("deb.action-unread", Some(script), Some("colliding installation declaration names".into()));
                        continue;
                    }
                    let source = tree.read(&script.path).map_err(|error| error.to_string()).and_then(|bytes| {
                        if bytes.len() > 256 * 1024 {
                            return Err("installation declaration exceeds the 256 KiB text profile".into());
                        }
                        let text = std::str::from_utf8(&bytes).map_err(|_| "installation declaration is not UTF-8")?;
                        aa_core::text::redact_sensitive_text(text).map_err(str::to_string)
                    });
                    let evidence = match source {
                        Ok(text) => {
                            out.fact(script, "deb.installation-declaration", json!({"package": package.path, "role": name, "text": text}));
                            Evidence::bytes(script, 0, script.size, json!({"role": name, "text": text}))
                        }
                        Err(detail) => {
                            out.limitation("deb.action-unread", Some(script), Some(detail));
                            Evidence::whole(script, json!({"role": name, "size": script.size, "text_retained": false}))
                        }
                    };
                    let trigger = name == "triggers";
                    out.finding(
                        Finding::new(
                            Section::Capabilities,
                            "deb",
                            if trigger { "deb.triggers" } else { "deb.install-script" },
                            Confidence::Verified,
                            Severity::Info,
                        )
                        .param("name", name)
                        .evidence(evidence),
                    );
                    out.limitation(if trigger { "deb.trigger-semantics" } else { "deb.script-semantics" }, Some(script), None);
                }
            }
        }
    }
}

fn retain_archive(tree: &dyn Tree, package: &Artifact, file: &Artifact, out: &mut Output) -> Result<()> {
    let bytes = tree.read(&file.path).map_err(|error| error.to_string())?;
    let mut archive = tar::Archive::new(&bytes[..]);
    let mut entries = Vec::new();
    let mut text_size = 0usize;
    let mut unresolved = false;
    for entry in archive.entries().map_err(|error| error.to_string())? {
        if entries.len() >= crate::MAX_ENTRIES {
            return Err("Debian TAR entry budget exhausted".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path_bytes();
        let link = entry.link_name_bytes();
        let extra = path.len().checked_add(link.as_ref().map_or(0, |link| link.len())).ok_or("Debian TAR name overflow")?;
        text_size = text_size.checked_add(extra).ok_or("Debian TAR metadata overflow")?;
        if path.len() > 4096 || link.as_ref().is_some_and(|link| link.len() > 4096) || text_size > MAX_METADATA {
            return Err("Debian TAR name or metadata budget exhausted".into());
        }
        let path = std::str::from_utf8(&path).map_err(|_| "Debian TAR path is not UTF-8")?;
        let target = link
            .as_ref()
            .map(|link| {
                std::str::from_utf8(link).map_err(|_| "Debian TAR link is not UTF-8").and_then(aa_core::text::redact_sensitive_text)
            })
            .transpose()
            .map_err(str::to_string)?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            unresolved = true;
        }
        entries.push(json!({"path": path, "header_offset": entry.raw_header_position(), "offset": entry.raw_file_position(),
            "size": entry.size(), "mode": entry.header().mode().map_err(|error| error.to_string())?, "type": kind.as_byte(), "link_target": target}));
    }
    out.fact(file, "deb.archive-entries", json!({"package": package.path, "entries": entries}));
    if unresolved {
        out.limitation("deb.archive-semantics", Some(file), None);
    }
    Ok(())
}

fn retain_control(package: &Artifact, file: &Artifact, fields: &[Field], out: &mut Output) {
    let mut values = Vec::new();
    for field in fields {
        let value = match aa_core::text::redact_named_value(&field.name, &field.value) {
            Ok(value) => value,
            Err(detail) => {
                out.limitation("deb.control-unread", Some(file), Some(detail.into()));
                return;
            }
        };
        values.push(json!({"name": field.name, "value": value, "line": field.line}));
    }
    let value = |name: &str| -> Value {
        values
            .iter()
            .find(|field| field["name"].as_str().is_some_and(|key| key.eq_ignore_ascii_case(name)))
            .map(|field| field["value"].clone())
            .unwrap_or(Value::Null)
    };
    let name = value("Package");
    let version = value("Version");
    let architecture = value("Architecture");
    out.fact(
        package,
        "deb.control",
        json!({"source": file.path, "fields": values, "name": name, "version": version, "architecture": architecture}),
    );
    out.finding(
        Finding::new(Section::Identity, "deb", "deb.identity", Confidence::Verified, Severity::Info)
            .param("name", name.clone())
            .param("version", version.clone())
            .param("architecture", architecture.clone())
            .evidence(Evidence::field(file, "Deb822 identity", json!({"Package": name, "Version": version, "Architecture": architecture}))),
    );
    let dependencies: Vec<_> = values
        .iter()
        .filter(|field| {
            field["name"].as_str().is_some_and(|key| {
                [
                    "depends",
                    "pre-depends",
                    "recommends",
                    "suggests",
                    "enhances",
                    "breaks",
                    "conflicts",
                    "provides",
                    "replaces",
                    "built-using",
                    "static-built-using",
                ]
                .contains(&key.to_ascii_lowercase().as_str())
            })
        })
        .cloned()
        .collect();
    if !dependencies.is_empty() {
        out.finding(
            Finding::new(Section::Composition, "deb", "deb.dependencies", Confidence::Verified, Severity::Info)
                .param("count", dependencies.len())
                .evidence(Evidence::field(file, "Deb822 relationships", json!(dependencies))),
        );
    }
}
