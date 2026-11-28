//! Literal Linux launch and application declarations. No host state is consulted.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::text::redact_named_value;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_FIELDS: usize = 4096;
const MAX_LINE: usize = 32 * 1024;
const MAX_XML_NODES: u32 = 16_384;
const MAX_XML_DEPTH: usize = 32;
const MAX_ISSUES: usize = 32;
const MAX_REFERENCE_PATH: usize = 8192;
const MAX_REFERENCE_OUTPUT: usize = 16 * 1024 * 1024;
const APPSTREAM_NS: &str = "https://specifications.freedesktop.org/metainfo/1.0";

pub struct Declarations;

const RULES: &[Rule] = &[
    Rule {
        id: "linux.systemd-unit",
        title_en: "Systemd unit declarations",
        title_zh: "Systemd 单元声明",
        text_en: "The unit contains {count} literal fields, including its command, dependency and installation declarations where present. These do not establish an effective unit or running service.",
        text_zh: "单元包含 {count} 个字面字段，并保留其中的命令、依赖和安装声明。这些不能确定实际生效的单元或运行中的服务。",
    },
    Rule {
        id: "linux.desktop-entry",
        title_en: "Desktop Entry declarations",
        title_zh: "桌面入口声明",
        text_en: "The Desktop Entry contains {count} literal fields. Commands, actions and visibility declarations remain source data; launcher availability and execution were not established.",
        text_zh: "桌面入口包含 {count} 个字面字段。命令、操作和可见性声明作为源数据保留，没有确定启动器是否可用或实际执行。",
    },
    Rule {
        id: "linux.appstream",
        title_en: "AppStream component declarations",
        title_zh: "AppStream 组件声明",
        text_en: "The metainfo document declares component {name}. Its identity, launchables, licences and requirements are declarations, without repository lookup or installation checks.",
        text_zh: "元信息文档声明了组件 {name}。身份、启动入口、许可证和要求均为声明，没有查询仓库或检查安装状态。",
    },
    Rule {
        id: "linux.declaration-unread",
        title_en: "Linux declaration could not be read",
        title_zh: "Linux 声明无法读取",
        text_en: "A declaration file is malformed, uses an unsupported encoding or exceeds the bounded reader profile.",
        text_zh: "声明文件格式损坏、编码不受支持，或超出有界读取范围。",
    },
    Rule {
        id: "linux.declaration-partial",
        title_en: "Some Linux declaration semantics remain unread",
        title_zh: "部分 Linux 声明语义未读取",
        text_en: "Unsupported or ambiguous declarations were retained where possible. They were not treated as effective settings or resolved commands.",
        text_zh: "尽可能保留了不受支持或有歧义的声明，没有将其视为实际生效的设置或已解析的命令。",
    },
    Rule {
        id: "linux.declaration-semantics",
        title_en: "Linux runtime declaration semantics were not established",
        title_zh: "Linux 声明的运行时语义未确定",
        text_en: "Drop-ins, masks, environment and specifier expansion, command evaluation, host dependencies, launcher visibility and runtime state were not evaluated. Supplied-file links do not prove installation or execution.",
        text_zh: "没有求值配置覆盖、屏蔽、环境与说明符展开、命令、本机依赖、启动器可见性或运行状态。所提供文件之间的关联不能证明安装或执行。",
    },
    Rule {
        id: "linux.supplied-entry",
        title_en: "Launchable declaration matches a supplied file",
        title_zh: "启动入口声明匹配所提供的文件",
        text_en: "A literal AppStream launchable identifies an unambiguous supplied declaration in the same namespace. This is a captured identity relationship, not a runtime target resolution.",
        text_zh: "AppStream 的字面启动入口标识了同一命名空间中唯一的声明文件。这是已捕获的身份关系，没有解析运行时目标。",
    },
];

#[derive(Default)]
struct State {
    issues: Vec<Value>,
    issue_count: usize,
}

impl State {
    fn issue(&mut self, line: usize, reason: &'static str) {
        self.issue_count += 1;
        if self.issues.len() < MAX_ISSUES {
            self.issues.push(json!({"line": line, "reason": reason}));
        }
    }

    fn finish(&self, file: &Artifact, out: &mut Output) {
        out.limitation("linux.declaration-semantics", Some(file), None);
        if self.issue_count > 0 {
            out.limitation(
                "linux.declaration-partial",
                Some(file),
                Some(format!("{} unsupported or ambiguous declarations; first issues: {}", self.issue_count, json!(self.issues))),
            );
        }
    }
}

fn unit_name(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, suffix)| {
        matches!(suffix, "service" | "socket" | "target" | "timer" | "path" | "mount" | "automount" | "swap" | "slice" | "scope" | "device")
    })
}

fn format(file: &Artifact) -> Option<&'static str> {
    if unit_name(file.name())
        || file.name().ends_with(".conf") && file.path.split('/').any(|part| part.ends_with(".d") && unit_name(part.trim_end_matches(".d")))
    {
        Some("systemd-unit")
    } else if file.name().ends_with(".desktop") {
        Some("desktop-entry")
    } else if file.name().ends_with(".metainfo.xml") || file.name().ends_with(".appdata.xml") {
        Some("appstream")
    } else {
        None
    }
}

fn source(bytes: &[u8]) -> Result<&str, &'static str> {
    if bytes.len() > MAX_BYTES {
        return Err("declaration exceeds the 1 MiB byte limit");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "only UTF-8 declarations are supported")?;
    if text.contains('\0') || text.starts_with('\u{feff}') {
        return Err("NUL characters and byte-order marks are outside this profile");
    }
    Ok(text)
}

fn category(group: &str, key: &str, systemd: bool) -> &'static str {
    if systemd {
        if group == "Unit"
            && matches!(
                key,
                "Requires"
                    | "Requisite"
                    | "Wants"
                    | "BindsTo"
                    | "PartOf"
                    | "Upholds"
                    | "Conflicts"
                    | "Before"
                    | "After"
                    | "OnFailure"
                    | "OnSuccess"
                    | "PropagatesReloadTo"
                    | "ReloadPropagatedFrom"
                    | "RequiresMountsFor"
                    | "WantsMountsFor"
            )
        {
            "dependency"
        } else if group == "Service"
            && matches!(key, "ExecStart" | "ExecStartPre" | "ExecStartPost" | "ExecStop" | "ExecStopPost" | "ExecReload" | "ExecCondition")
        {
            "command"
        } else if group == "Install" && matches!(key, "WantedBy" | "RequiredBy" | "UpheldBy" | "Also" | "Alias" | "DefaultInstance") {
            "installation"
        } else if matches!(
            key,
            "Description"
                | "Documentation"
                | "SourcePath"
                | "Type"
                | "User"
                | "Group"
                | "DynamicUser"
                | "WorkingDirectory"
                | "RootDirectory"
                | "Environment"
                | "EnvironmentFile"
                | "Restart"
                | "PIDFile"
                | "RemainAfterExit"
                | "BusName"
                | "ListenStream"
                | "ListenDatagram"
                | "Service"
                | "Unit"
                | "OnBootSec"
                | "OnCalendar"
                | "PathExists"
                | "PathChanged"
                | "What"
                | "Where"
                | "Options"
                | "TimeoutStartSec"
                | "TimeoutStopSec"
        ) {
            "setting"
        } else {
            "uninterpreted"
        }
    } else {
        let base = key.split('[').next().unwrap_or(key);
        if (group == "Desktop Entry" || group.starts_with("Desktop Action ")) && matches!(base, "Exec" | "TryExec") {
            "command"
        } else if group == "Desktop Entry"
            && matches!(
                base,
                "Name"
                    | "GenericName"
                    | "Comment"
                    | "Type"
                    | "Version"
                    | "Icon"
                    | "URL"
                    | "Path"
                    | "Terminal"
                    | "NoDisplay"
                    | "Hidden"
                    | "OnlyShowIn"
                    | "NotShowIn"
                    | "DBusActivatable"
                    | "StartupNotify"
                    | "StartupWMClass"
                    | "Categories"
                    | "MimeType"
                    | "Keywords"
                    | "Actions"
                    | "Implements"
                    | "PrefersNonDefaultGPU"
                    | "SingleMainWindow"
            )
            || group.starts_with("Desktop Action ") && matches!(base, "Name" | "Icon")
        {
            "setting"
        } else {
            "uninterpreted"
        }
    }
}

fn key_valid(key: &str, systemd: bool) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key.chars().all(|c| c.is_ascii_alphanumeric() || if systemd { c == '-' } else { matches!(c, '-' | '_' | '[' | ']' | '@' | '.') })
}

fn parse_ini(text: &str, systemd: bool) -> Result<(Vec<Value>, State), &'static str> {
    let mut fields = Vec::new();
    let mut state = State::default();
    let mut group = String::new();
    let mut groups = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut offset = 0usize;
    let mut continuation = false;
    for (index, raw) in text.split_inclusive('\n').enumerate() {
        let line_number = index + 1;
        if raw.len() > MAX_LINE {
            return Err("declaration line exceeds the 32 KiB line limit");
        }
        let start = offset;
        offset += raw.len();
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || systemd && line.starts_with(';') {
            continue;
        }
        if continuation {
            continuation = line.ends_with('\\');
            state.issue(line_number, "continued line retained only through the original bytes; no fields inferred");
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = &line[1..line.len() - 1];
            if name.is_empty() || name.len() > 256 || name.contains(['[', ']']) {
                return Err("invalid or oversized section name");
            }
            if !systemd && !groups.insert(name.to_string()) {
                state.issue(line_number, "duplicate Desktop Entry group; no effective settings inferred");
            }
            group = name.to_string();
            continue;
        }
        if line.starts_with('[') {
            group.clear();
            state.issue(line_number, "malformed section header; following fields have no established section");
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            state.issue(line_number, "line is neither a section nor a key/value declaration");
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if group.is_empty() || !key_valid(key, systemd) {
            state.issue(line_number, "field has no section or has an unsupported key spelling");
            continue;
        }
        if fields.len() == MAX_FIELDS {
            return Err("declaration exceeds the 4096 field limit");
        }
        let mut kind = category(&group, key, systemd);
        if !systemd && !keys.insert((group.clone(), key.to_string())) {
            state.issue(line_number, "duplicate Desktop Entry key; all occurrences remain literal");
        }
        if systemd && value.ends_with('\\') {
            continuation = true;
            kind = "uninterpreted";
            state.issue(line_number, "systemd continuation is outside the literal single-line profile");
        }
        if kind == "uninterpreted" {
            state.issue(line_number, "unknown or unsupported field retained literally");
        }
        if value.contains(['%', '$', '\\', '@']) {
            state.issue(line_number, "specifier, environment, field-code or escape expansion is not evaluated");
        }
        let redacted = redact_named_value(key, value)?;
        fields.push(json!({"group": group, "key": key, "value": redacted, "line": line_number,
            "offset": start, "length": raw.trim_end_matches(['\r', '\n']).len(), "category": kind,
            "empty_assignment": value.is_empty(), "redacted": redacted != value}));
    }
    if continuation {
        state.issue(text.lines().count(), "unfinished systemd continuation");
    }
    if !systemd && !groups.contains("Desktop Entry") {
        return Err("required Desktop Entry group is missing");
    }
    if fields.is_empty() {
        return Err("no declaration fields were found");
    }
    Ok((fields, state))
}

fn field_value<'a>(fields: &'a [Value], group: &str, key: &str) -> Option<&'a str> {
    let mut matches = fields.iter().filter(|field| field["group"] == group && field["key"] == key);
    let found = matches.next()?;
    if matches.next().is_some() || found["category"] == "uninterpreted" {
        return None;
    }
    found["value"].as_str()
}

fn ini(file: &Artifact, text: &str, systemd: bool, out: &mut Output) -> Result<(), &'static str> {
    let (fields, mut state) = parse_ini(text, systemd)?;
    if !systemd && !matches!(field_value(&fields, "Desktop Entry", "Type"), Some("Application" | "Link" | "Directory")) {
        state.issue(0, "Desktop Entry Type is missing, duplicate or unsupported");
    }
    let name = if systemd { Some(file.name()) } else { field_value(&fields, "Desktop Entry", "Name") };
    let commands: Vec<_> = fields.iter().filter(|field| field["category"] == "command").cloned().collect();
    let dependencies: Vec<_> =
        fields.iter().filter(|field| field["category"] == "dependency" || field["category"] == "installation").cloned().collect();
    let kind = if systemd { "systemd-unit" } else { "desktop-entry" };
    let rule = if systemd { "linux.systemd-unit" } else { "linux.desktop-entry" };
    let mut finding = Finding::new(Section::Capabilities, "linux", rule, Confidence::Verified, Severity::Info).param("count", fields.len());
    for field in fields.iter().take(12) {
        finding = finding.evidence(Evidence::bytes(
            file,
            field["offset"].as_u64().unwrap_or(0),
            field["length"].as_u64().unwrap_or(0),
            field.clone(),
        ));
    }
    out.kind(file, kind);
    out.fact(
        file,
        rule,
        json!({"name": name, "fields": fields, "commands": commands, "dependencies": dependencies,
        "issues": state.issues, "issue_count": state.issue_count, "effective_settings_established": false,
        "runtime_target_resolved": false, "host_state_checked": false}),
    );
    out.finding(finding);
    state.finish(file, out);
    Ok(())
}

fn appstream(file: &Artifact, text: &str, out: &mut Output) -> Result<(), &'static str> {
    if let Some(header) = text.strip_prefix("<?xml").and_then(|tail| tail.split_once("?>").map(|(header, _)| header))
        && let Some((_, encoding)) = header.split_once("encoding")
    {
        let value = encoding.trim_start().strip_prefix('=').map(str::trim_start).ok_or("invalid XML encoding declaration")?;
        let quote = value.chars().next().filter(|value| matches!(value, '\'' | '"')).ok_or("invalid XML encoding declaration")?;
        let encoding = value.get(1..).and_then(|value| value.split(quote).next()).ok_or("invalid XML encoding declaration")?;
        if !encoding.eq_ignore_ascii_case("utf-8") && !(encoding.eq_ignore_ascii_case("us-ascii") && text.is_ascii()) {
            return Err("only UTF-8 and matching ASCII XML encoding declarations are supported");
        }
    }
    let options = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_XML_NODES };
    let document =
        roxmltree::Document::parse_with_options(text, options).map_err(|_| "malformed AppStream XML or XML node budget exceeded")?;
    let root = document.root_element();
    if root.tag_name().name() != "component" || !matches!(root.tag_name().namespace(), None | Some(APPSTREAM_NS)) {
        return Err("only one upstream AppStream component document is supported");
    }
    let mut state = State::default();
    let mut declarations = Vec::new();
    for node in root.descendants().filter(roxmltree::Node::is_element) {
        if declarations.len() == MAX_FIELDS || node.ancestors().count() > MAX_XML_DEPTH {
            return Err("AppStream declaration count or XML depth budget exceeded");
        }
        let range = node.range();
        let line = document.text_pos_at(range.start).row as usize;
        let name = node.tag_name().name();
        let supported = matches!(
            name,
            "component"
                | "id"
                | "name"
                | "summary"
                | "metadata_license"
                | "project_license"
                | "developer_name"
                | "developer"
                | "launchable"
                | "provides"
                | "binary"
                | "library"
                | "mediatype"
                | "modalias"
                | "font"
                | "dbus"
                | "requires"
                | "recommends"
                | "supports"
                | "control"
                | "display_length"
                | "internet"
                | "memory"
                | "kernel"
                | "firmware"
                | "url"
                | "pkgname"
                | "bundle"
                | "categories"
                | "category"
                | "description"
                | "p"
                | "ul"
                | "ol"
                | "li"
                | "em"
                | "code"
        );
        if !supported || !matches!(node.tag_name().namespace(), None | Some(APPSTREAM_NS)) {
            state.issue(line, "element has no interpreted semantics in this AppStream profile");
        }
        let mut attributes = BTreeMap::new();
        for attribute in node.attributes() {
            if attribute.value().len() > MAX_LINE || attributes.len() == 32 {
                return Err("AppStream attribute budget exceeded");
            }
            let key = if attribute.namespace() == Some("http://www.w3.org/XML/1998/namespace") {
                format!("xml:{}", attribute.name())
            } else if let Some(namespace) = attribute.namespace() {
                format!("{{{namespace}}}{}", attribute.name())
            } else {
                attribute.name().to_string()
            };
            attributes.insert(key, redact_named_value(attribute.name(), attribute.value())?);
        }
        let mut value = String::new();
        for child in node.children().filter(roxmltree::Node::is_text) {
            let part = child.text().unwrap_or("");
            if value.len().saturating_add(part.len()) > MAX_LINE {
                return Err("AppStream direct-text budget exceeded");
            }
            value.push_str(part);
        }
        let value = redact_named_value(name, value.trim())?;
        let parent = node.parent_element().map(|parent| parent.tag_name().name());
        let literal_text = !node.children().any(|child| child.is_element());
        if matches!(name, "id" | "launchable") && !literal_text {
            state.issue(line, "structured identity or launchable text is outside the literal profile");
        }
        declarations.push(json!({"element": name, "parent": parent, "line": line, "offset": range.start,
            "length": range.len(), "attributes": attributes, "value": value,
            "direct_component_child": node.parent_element() == Some(root), "literal_text": literal_text, "interpreted": supported && matches!(node.tag_name().namespace(), None | Some(APPSTREAM_NS))}));
    }
    let ids: Vec<_> = declarations
        .iter()
        .filter(|node| node["element"] == "id" && node["direct_component_child"] == true && node["interpreted"] == true)
        .collect();
    let name =
        if ids.len() == 1 && ids[0]["literal_text"] == true { ids[0]["value"].as_str().filter(|value| !value.is_empty()) } else { None };
    if name.is_none() {
        state.issue(0, "one nonempty direct component id is required for unambiguous identity");
    }
    let launchables: Vec<_> = declarations
        .iter()
        .filter(|node| {
            node["element"] == "launchable"
                && node["direct_component_child"] == true
                && node["interpreted"] == true
                && node["literal_text"] == true
        })
        .cloned()
        .collect();
    out.kind(file, "appstream");
    let mut finding = Finding::new(Section::Identity, "linux", "linux.appstream", Confidence::Verified, Severity::Info)
        .param("name", name.unwrap_or("(unresolved)"));
    for node in ids.iter().take(4) {
        finding = finding.evidence(Evidence::bytes(
            file,
            node["offset"].as_u64().unwrap_or(0),
            node["length"].as_u64().unwrap_or(0),
            (*node).clone(),
        ));
    }
    if ids.is_empty() {
        finding = finding.evidence(Evidence::bytes(file, root.range().start as u64, root.range().len() as u64, "component"));
    }
    let component_type = root.attribute("type").map(|value| redact_named_value("type", value)).transpose()?;
    out.fact(
        file,
        "linux.appstream",
        json!({"name": name, "component_type": component_type, "declarations": declarations,
        "launchables": launchables, "issues": state.issues, "issue_count": state.issue_count,
        "schema_validated": false, "host_state_checked": false, "runtime_target_resolved": false}),
    );
    out.finding(finding);
    state.finish(file, out);
    Ok(())
}

fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|name| name["normalized"] != true && name["colliding"] != true)
}

fn desktop_id<'a>(file: &'a Artifact, parent: Option<&str>) -> Option<&'a str> {
    if file.parent.as_deref() != parent || !original(file) {
        return None;
    }
    let relative = if let Some(parent) = parent { file.path.strip_prefix(parent)?.strip_prefix('/')? } else { &file.path };
    relative.strip_prefix("usr/share/applications/").filter(|value| !value.contains('/') && !value.is_empty())
}

fn supplied(tree: &dyn Tree, out: &mut Output) {
    let artifacts = tree.artifacts();
    if !artifacts.iter().any(|file| file.facts.contains_key("linux.appstream")) {
        return;
    }
    if artifacts.len() > 100_000
        || artifacts.iter().any(|file| file.path.len() > MAX_REFERENCE_PATH)
        || artifacts.iter().fold(0usize, |total, file| total.saturating_add(file.path.len())) > 16 * MAX_BYTES
    {
        out.limitation(
            "linux.declaration-partial",
            None,
            Some("supplied declaration index exceeds 100,000 files, 8 KiB per path or 16 MiB of path bytes".into()),
        );
        return;
    }
    if tree.summary().get("engine.input-listing").and_then(|listing| listing["complete"].as_bool()) != Some(true) {
        out.limitation(
            "linux.declaration-partial",
            None,
            Some("supplied input listing is incomplete; uniqueness was not established".into()),
        );
        return;
    }
    let mut desktop_index: BTreeMap<(Option<&str>, &str), Vec<&Artifact>> = BTreeMap::new();
    for file in artifacts.iter().filter(|file| file.facts.contains_key("linux.desktop-entry")) {
        if let Some(id) = desktop_id(file, file.parent.as_deref()) {
            desktop_index.entry((file.parent.as_deref(), id)).or_default().push(file);
        }
    }
    let mut reference_count = 0usize;
    let mut output_bytes = 0usize;
    for (source_index, file) in artifacts.iter().filter(|file| file.facts.contains_key("linux.appstream")).enumerate() {
        if source_index == 1024 {
            out.limitation("linux.declaration-partial", None, Some("supplied launchable source budget exhausted".into()));
            break;
        }
        let Some(launchables) = file.facts["linux.appstream"]["launchables"].as_array() else { continue };
        let mut references = Vec::new();
        let mut truncated = false;
        for declaration in launchables {
            if reference_count == MAX_FIELDS {
                truncated = true;
                out.limitation("linux.declaration-partial", Some(file), Some("supplied launchable reference budget exhausted".into()));
                break;
            }
            reference_count += 1;
            let literal = declaration["value"].as_str().unwrap_or("");
            let namespace_complete = file.parent.as_deref().is_none_or(|parent| {
                tree.get(parent).is_some_and(|container| {
                    container.facts.get("engine.container-listing").is_some_and(|listing| listing["complete"] == true)
                })
            });
            let target = if original(file)
                && namespace_complete
                && declaration["attributes"]["type"] == "desktop-id"
                && !literal.contains(['/', '\\', '%', '$'])
            {
                desktop_index
                    .get(&(file.parent.as_deref(), literal))
                    .filter(|files| files.len() == 1)
                    .and_then(|files| files.first().copied())
            } else {
                None
            };
            let reference = json!({"field": format!("launchable (line {})", declaration["line"]), "basis": "captured-desktop-file-id",
                "declared": literal, "status": if target.is_some() { "matched-supplied-declaration" } else { "unresolved" },
                "target": target.map(|target| &target.path), "target_sha256": target.and_then(|target| target.digests.as_ref().map(|digest| &digest.sha256)),
                "reason": if target.is_some() { None } else { Some("no unambiguous original desktop-id target in the supplied applications namespace") }});
            let finding = target.map(|target| {
                Finding::new(Section::Structure, "linux", "linux.supplied-entry", Confidence::Verified, Severity::Info)
                    .evidence(Evidence::bytes(
                        file,
                        declaration["offset"].as_u64().unwrap_or(0),
                        declaration["length"].as_u64().unwrap_or(0),
                        declaration.clone(),
                    ))
                    .evidence(Evidence::whole(target, json!({"path": target.path, "desktop_file_id": literal})))
            });
            // Count serialized evidence as well as rows: repeated short declarations can
            // otherwise multiply one long archive namespace into a much larger report.
            let finding_bytes = finding
                .as_ref()
                .map_or(0, |finding| serde_json::to_vec(finding).map_or(MAX_REFERENCE_OUTPUT + 1, |bytes| bytes.len().saturating_add(128)));
            let needed = reference.to_string().len().saturating_add(finding_bytes).saturating_add(file.path.len());
            if needed > MAX_REFERENCE_OUTPUT.saturating_sub(output_bytes) {
                truncated = true;
                reference_count = MAX_FIELDS;
                out.limitation(
                    "linux.declaration-partial",
                    Some(file),
                    Some("shared 16 MiB supplied relationship/evidence budget exhausted".into()),
                );
                break;
            }
            output_bytes += needed;
            references.push(reference);
            if let Some(finding) = finding {
                out.finding(finding);
            }
        }
        if !references.is_empty() {
            out.fact(
                file,
                "linux.supplied-file",
                json!({"references": references, "runtime_target_resolved": false,"truncated":truncated}),
            );
        }
    }
}

impl Analyzer for Declarations {
    fn id(&self) -> &'static str {
        "linux"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        let Some(kind) = format(file) else { return };
        if file.size > MAX_BYTES as u64 {
            out.limitation("linux.declaration-unread", Some(file), Some("declaration exceeds the 1 MiB byte limit".into()));
            return;
        }
        let result = tree.read(&file.path).map_err(|_| "declaration bytes are unavailable").and_then(|bytes| {
            let text = source(&bytes)?;
            if kind == "appstream" { appstream(file, text, out) } else { ini(file, text, kind == "systemd-unit", out) }
        });
        if let Err(reason) = result {
            out.limitation("linux.declaration-unread", Some(file), Some(reason.into()));
        }
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        supplied(tree, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::plugin::Bytes;

    struct Supplied {
        files: Vec<Artifact>,
        contents: BTreeMap<String, Vec<u8>>,
        summary: BTreeMap<String, Value>,
    }

    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.contents.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::other("fixture bytes missing"))
        }
        fn summary(&self) -> &BTreeMap<String, Value> {
            &self.summary
        }
    }

    fn file(path: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: "0".repeat(32), sha1: "0".repeat(40), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn analyze(path: &str, bytes: &[u8]) -> Output {
        let artifact = file(path, bytes);
        let tree =
            Supplied { files: vec![artifact.clone()], contents: BTreeMap::from([(path.into(), bytes.to_vec())]), summary: BTreeMap::new() };
        let mut out = Output::default();
        Declarations.analyze_file(&tree, &artifact, &mut out);
        out
    }

    fn fact<'a>(out: &'a Output, key: &str) -> &'a Value {
        &out.facts.iter().find(|fact| fact.key == key).expect("expected declaration fact").value
    }

    #[test]
    fn systemd_preserves_repeats_resets_and_source_bytes_without_expansion() {
        let bytes = b"[Unit]\r\nDescription=Example\r\nAfter=network.target\r\n[Service]\r\nExecStart=/usr/bin/example --token fixture-secret\r\nExecStart=\r\nExecStart=/usr/bin/example %i $VALUE\r\nEnvironment=PASSWORD=fixture-hidden\r\nFutureKey=opaque\r\n";
        let out = analyze("example@.service", bytes);
        let parsed = fact(&out, "linux.systemd-unit");
        assert_eq!(parsed["commands"].as_array().expect("commands").len(), 3);
        assert_eq!(parsed["commands"][1]["empty_assignment"], true);
        assert_eq!(parsed["dependencies"][0]["value"], "network.target");
        assert_eq!(parsed["effective_settings_established"], false);
        let fields = parsed["fields"].as_array().expect("fields");
        for field in fields {
            let offset = field["offset"].as_u64().expect("offset") as usize;
            let length = field["length"].as_u64().expect("length") as usize;
            assert!(
                std::str::from_utf8(&bytes[offset..offset + length]).expect("field UTF-8").contains(field["key"].as_str().expect("key"))
            );
        }
        let published = serde_json::to_string(parsed).expect("fact JSON");
        assert!(!published.contains("fixture-secret"));
        assert!(!published.contains("fixture-hidden"));
        assert!(published.contains("%i $VALUE"));
        assert!(out.limitations.iter().any(|limit| limit.code == "linux.declaration-partial"));
        let repeated = analyze("example@.service", bytes);
        assert_eq!(out.facts, repeated.facts);
        assert_eq!(out.findings, repeated.findings);
    }

    #[test]
    fn continuation_payload_is_never_reinterpreted_as_independent_keys() {
        let text = "[Service]\nExecStart=/bin/example \\\n# skipped continuation comment\nEnvironment=NOT_A_FIELD \\\nExecStop=ALSO_NOT_A_FIELD\nUser=normal\n";
        let (fields, state) = parse_ini(text, true).expect("literal unit");
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["category"], "uninterpreted");
        assert_eq!(fields[1]["key"], "User");
        assert!(state.issue_count >= 3);
    }

    #[test]
    fn desktop_duplicates_locales_actions_and_utf8_offsets_remain_explicit() {
        let text = "[Desktop Entry]\nType=Application\nName=工具\nName[zh_CN]=工具名\nExec=/bin/one %F\nExec=/bin/two\nActions=Edit;\n[Desktop Action Edit]\nName=Edit\nExec=/bin/editor\n";
        let out = analyze("example.desktop", text.as_bytes());
        let parsed = fact(&out, "linux.desktop-entry");
        let fields = parsed["fields"].as_array().expect("fields");
        assert_eq!(fields[2]["value"], "工具名");
        assert_eq!(parsed["commands"].as_array().expect("commands").len(), 3);
        assert!(parsed["issue_count"].as_u64().expect("issue count") >= 2);
        assert!(field_value(fields, "Desktop Entry", "Exec").is_none());
        for finding in &out.findings {
            assert!(!finding.evidence.is_empty());
        }
        assert!(analyze("missing.desktop", b"[Other]\nName=Wrong\n").facts.is_empty());
    }

    #[test]
    fn appstream_retains_structured_requirements_without_interpreting_foreign_ids() {
        let bytes = br#"<component type="desktop-application"><id>org.example.App</id><name>Example</name><launchable type="desktop-id">org.example.App.desktop</launchable><requires><memory>2048</memory></requires><x:extra xmlns:x="urn:fixture"><x:id>forged</x:id></x:extra></component>"#;
        let out = analyze("example.metainfo.xml", bytes);
        let parsed = fact(&out, "linux.appstream");
        assert_eq!(parsed["name"], "org.example.App");
        assert_eq!(parsed["launchables"][0]["value"], "org.example.App.desktop");
        assert_eq!(parsed["schema_validated"], false);
        assert!(parsed["issue_count"].as_u64().expect("issues") >= 2);
        let duplicate = analyze("duplicate.metainfo.xml", b"<component><id>one</id><id>two</id></component>");
        assert!(fact(&duplicate, "linux.appstream")["name"].is_null());
    }

    #[test]
    fn malformed_encodings_dtds_and_budgets_are_explicit_limitations() {
        for (path, bytes) in [
            ("bad.service", b"[Service]\nUser=\xff".to_vec()),
            ("bad.desktop", b"[Desktop Entry]\nName=bad\0".to_vec()),
            (
                "bad.metainfo.xml",
                b"<!DOCTYPE component [<!ENTITY secret SYSTEM 'file:///not-read'>]><component><id>&secret;</id></component>".to_vec(),
            ),
            ("large.service", vec![b'a'; MAX_BYTES + 1]),
            ("line.service", format!("[Service]\nUser={}\n", "x".repeat(MAX_LINE)).into_bytes()),
            ("count.service", format!("[Service]\n{}", "User=fixture\n".repeat(MAX_FIELDS + 1)).into_bytes()),
            (
                "deep.metainfo.xml",
                format!(
                    "<component>{}<id>deep</id>{}</component>",
                    "<description>".repeat(MAX_XML_DEPTH),
                    "</description>".repeat(MAX_XML_DEPTH)
                )
                .into_bytes(),
            ),
        ] {
            let out = analyze(path, &bytes);
            assert!(out.facts.is_empty(), "{path}");
            assert!(out.limitations.iter().any(|limit| limit.code == "linux.declaration-unread"), "{path}");
        }
    }

    #[test]
    fn licensed_upstream_declarations_are_read_as_their_actual_profile() {
        let unit = include_bytes!("../tests/data/declarations/syncthing.service");
        let out = analyze("syncthing.service", unit);
        assert_eq!(fact(&out, "linux.systemd-unit")["commands"][0]["value"], "/usr/bin/syncthing serve --no-browser --no-restart");
        let desktop = include_bytes!("../tests/data/declarations/syncthing-start.desktop");
        let out = analyze("syncthing-start.desktop", desktop);
        assert_eq!(fact(&out, "linux.desktop-entry")["name"], "Start Syncthing");
        let metainfo = include_bytes!("../tests/data/declarations/org.flameshot.Flameshot.metainfo.xml");
        let out = analyze("org.flameshot.Flameshot.metainfo.xml", metainfo);
        assert_eq!(fact(&out, "linux.appstream")["name"], "org.flameshot.Flameshot");
        let template = include_bytes!("../tests/data/declarations/org.flameshot.Flameshot.desktop");
        let out = analyze("org.flameshot.Flameshot.desktop", template);
        assert!(fact(&out, "linux.desktop-entry")["commands"][0]["value"].as_str().expect("command").contains("@LAUNCHER_EXECUTABLE@"));
        assert!(out.limitations.iter().any(|limit| limit.code == "linux.declaration-partial"));
    }

    #[test]
    fn long_namespaces_and_repeated_launchables_cannot_expand_relationship_evidence_without_limit() {
        for prefix in ["z".repeat(64 * 1024), "z".repeat(7000)] {
            let mut container = file(&prefix, b"archive");
            container.facts.insert("engine.container-listing".into(), json!({"complete":true}));
            let mut source = file(&format!("{prefix}/usr/share/metainfo/example.metainfo.xml"), b"metadata");
            source.parent = Some(prefix.clone());
            let declaration = json!({"value":"example.desktop","attributes":{"type":"desktop-id"},"line":1,"offset":0,"length":8});
            source.facts.insert("linux.appstream".into(), json!({"launchables":vec![declaration;MAX_FIELDS]}));
            let mut target = file(&format!("{prefix}/usr/share/applications/example.desktop"), b"desktop");
            target.parent = Some(prefix.clone());
            target.facts.insert("linux.desktop-entry".into(), json!({"name":"Example"}));
            let mut files = vec![container, source, target];
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let tree = Supplied {
                files,
                contents: BTreeMap::new(),
                summary: BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]),
            };
            let mut out = Output::default();
            supplied(&tree, &mut out);
            assert!(out.limitations.iter().any(|limit| limit.code == "linux.declaration-partial"));
            let evidence_bytes = serde_json::to_vec(&out.findings).expect("serialized findings").len();
            let fact_bytes = out.facts.iter().map(|fact| fact.value.to_string().len()).sum::<usize>();
            assert!(evidence_bytes + fact_bytes <= MAX_REFERENCE_OUTPUT, "shared rows and evidence budget");
            if prefix.len() > MAX_REFERENCE_PATH {
                assert!(out.facts.is_empty() && out.findings.is_empty());
            } else {
                assert_eq!(fact(&out, "linux.supplied-file")["truncated"], true);
                assert!(out.findings.len() < MAX_FIELDS);
            }
        }
    }

    #[test]
    fn supplied_desktop_ids_are_namespace_local_and_never_runtime_resolutions() {
        let mut source = file("usr/share/metainfo/example.metainfo.xml", b"metadata");
        source.facts.insert("linux.appstream".into(), json!({"launchables": [{"value": "example.desktop", "attributes": {"type": "desktop-id"}, "line": 1, "offset": 0, "length": 8}]}));
        let mut target = file("usr/share/applications/example.desktop", b"desktop");
        target.facts.insert("linux.desktop-entry".into(), json!({"name": "Example"}));
        let check = |files: Vec<Artifact>, mut summary: BTreeMap<String, Value>| {
            summary.entry("engine.input-listing".into()).or_insert_with(|| json!({"complete": true}));
            let tree = Supplied { files, contents: BTreeMap::new(), summary };
            let mut out = Output::default();
            supplied(&tree, &mut out);
            out
        };
        let out = check(vec![source.clone(), target.clone()], BTreeMap::new());
        assert_eq!(fact(&out, "linux.supplied-file")["references"][0]["target"], target.path);
        assert_eq!(fact(&out, "linux.supplied-file")["runtime_target_resolved"], false);
        assert_eq!(out.findings[0].evidence.len(), 2);
        target.facts.insert("engine.entry-name".into(), json!({"colliding": true}));
        let out = check(vec![source.clone(), target], BTreeMap::new());
        assert_eq!(fact(&out, "linux.supplied-file")["references"][0]["status"], "unresolved");
        assert!(out.findings.is_empty());
        let out = check(vec![source], BTreeMap::from([("engine.input-listing".into(), json!({"complete": false}))]));
        assert!(out.facts.is_empty());
        assert!(!out.limitations.is_empty());
    }
}
