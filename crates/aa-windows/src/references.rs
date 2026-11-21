//! Relates declarations to supplied artifacts only. This pass never reads a target or the host.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::{Value, json};

const MAX_INDEX_FILES: usize = 100_000;
const MAX_INDEX_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOURCES: usize = 10_000;
const MAX_REFERENCES: usize = 512;
const MAX_TEXT: usize = 8192;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Basis {
    ShortcutDirectory,
    InfDirectory,
    HostContext,
    CommandLine,
    Uri,
}

#[derive(Serialize)]
struct Reference<'a> {
    field: String,
    basis: Basis,
    declared: Option<&'a str>,
    declared_bytes: usize,
    status: &'static str,
    reason: Option<&'static str>,
    target: Option<&'a str>,
    target_sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_literal: Option<&'a str>,
}

struct Pending<'a> {
    field: String,
    text: &'a str,
    basis: Basis,
    source_literal: Option<&'a str>,
}

#[derive(Default)]
struct Collected<'a> {
    pending: Vec<Pending<'a>>,
    truncated: bool,
}

impl<'a> Collected<'a> {
    fn add(&mut self, field: String, text: &'a str, basis: Basis) {
        if self.pending.len() < MAX_REFERENCES {
            self.pending.push(Pending { field, text, basis, source_literal: None });
        } else {
            self.truncated = true;
        }
    }
}

fn children(node: &Value) -> impl Iterator<Item = &Value> {
    node.get("children")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|c| c.get("interpreted").and_then(Value::as_bool) == Some(true))
}

fn collect(file: &Artifact) -> Collected<'_> {
    let mut result = Collected::default();
    if let Some(sections) = file.facts.get("windows.inf").and_then(|f| f.get("sections")).and_then(Value::as_array) {
        for (section_index, section) in sections.iter().enumerate() {
            if !section["name"].as_str().is_some_and(|s| s.eq_ignore_ascii_case("version")) {
                continue;
            }
            for entry in section["entries"].as_array().into_iter().flatten() {
                let Some(key) = entry["key"].as_str() else {
                    continue;
                };
                if !matches!(
                    key.to_ascii_lowercase().as_str(),
                    "catalogfile"
                        | "catalogfile.nt"
                        | "catalogfile.ntx86"
                        | "catalogfile.ntia64"
                        | "catalogfile.ntamd64"
                        | "catalogfile.ntarm"
                        | "catalogfile.ntarm64"
                ) {
                    continue;
                }
                let Some(fields) = entry["fields"].as_array().filter(|v| v.len() == 1) else {
                    continue;
                };
                let Some(literal) = fields[0].as_str() else {
                    continue;
                };
                let text = entry["neutral_fields"].as_array().and_then(|v| v.first()).and_then(Value::as_str).unwrap_or(literal);
                let before = result.pending.len();
                result.add(format!("Version[{section_index}]/line {}/{key}", entry["line"]), text, Basis::InfDirectory);
                if result.pending.len() > before {
                    result.pending.last_mut().expect("reference was appended").source_literal = Some(literal);
                }
            }
        }
    }
    if let Some(fields) = file.facts.get("windows.shell-link").and_then(|f| f.get("declarations")).and_then(Value::as_array) {
        for field in fields {
            let (Some(name), Some(value)) = (field.get("field").and_then(Value::as_str), field.get("value").and_then(Value::as_str)) else {
                continue;
            };
            let basis = if name == "RelativePath" {
                Basis::ShortcutDirectory
            } else if matches!(
                name,
                "IconLocation"
                    | "LinkInfo/LocalBasePath"
                    | "LinkInfo/LocalBasePathUnicode"
                    | "LinkInfo/Network/NetName"
                    | "LinkInfo/Network/NetNameUnicode"
                    | "Environment/TargetAnsi"
                    | "Environment/TargetUnicode"
                    | "Environment/IconAnsi"
                    | "Environment/IconUnicode"
            ) {
                Basis::HostContext
            } else {
                continue;
            };
            result.add(name.into(), value, basis);
        }
    }
    if let Some(fields) = file.facts.get("windows.internet-shortcut").and_then(|f| f.get("fields")).and_then(Value::as_array) {
        for (index, field) in fields.iter().enumerate() {
            let (Some(name), Some(value)) = (field.get(0).and_then(Value::as_str), field.get(1).and_then(Value::as_str)) else {
                continue;
            };
            if matches!(name, "url" | "iconfile") {
                result.add(
                    format!("InternetShortcut/{name}[{}]", index + 1),
                    value,
                    if name == "url" { Basis::Uri } else { Basis::HostContext },
                );
            }
        }
    }
    if let Some(entries) = file.facts.get("windows.registry").and_then(|f| f.get("entries")).and_then(Value::as_array) {
        for entry in entries {
            if entry.get("operation").and_then(Value::as_str) != Some("set_value") {
                continue;
            }
            let (Some(name), Some(key), Some(value)) = (
                entry.get("name").and_then(Value::as_str),
                entry.get("key").and_then(Value::as_str),
                entry.get("value").and_then(Value::as_str),
            ) else {
                continue;
            };
            let key = key.to_ascii_lowercase();
            let name = name.to_ascii_lowercase();
            let tags = entry.get("tags").and_then(Value::as_array);
            let has = |tag| tags.is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(tag)));
            let classes = key.starts_with("hkey_classes_root\\")
                || key.starts_with("hkey_local_machine\\software\\classes\\")
                || key.starts_with("hkey_current_user\\software\\classes\\");
            let command = has("autostart")
                || has("service") && name == "imagepath"
                || classes && name.is_empty() && key.ends_with("\\shell\\open\\command");
            let path = has("service") && name == "servicedll";
            if command || path {
                result.add(
                    entry
                        .get("line")
                        .and_then(Value::as_u64)
                        .map_or_else(|| "registry value declaration".into(), |line| format!("line {line}: value")),
                    value,
                    if command { Basis::CommandLine } else { Basis::HostContext },
                );
            }
        }
    }
    if let Some(task) = file.facts.get("windows.scheduled-task").and_then(|f| f.get("declarations")) {
        for actions in children(task).filter(|n| n.get("element").and_then(Value::as_str) == Some("Actions")) {
            for exec in children(actions).filter(|n| n.get("element").and_then(Value::as_str) == Some("Exec")) {
                for command in children(exec).filter(|n| n.get("element").and_then(Value::as_str) == Some("Command")) {
                    if let (Some(value), Some(path)) =
                        (command.get("text").and_then(Value::as_str), command.get("path").and_then(Value::as_str))
                    {
                        result.add(path.into(), value, Basis::HostContext);
                    }
                }
            }
        }
    }
    result
}

fn local_path(file: &Artifact) -> Option<&str> {
    match file.parent.as_deref() {
        Some(parent) => file.path.strip_prefix(parent)?.strip_prefix('/'),
        None => Some(&file.path),
    }
}

fn name_changed(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_some_and(|f| {
        f.get("normalized").and_then(Value::as_bool) == Some(true) || f.get("colliding").and_then(Value::as_bool) == Some(true)
    })
}

fn ordinary_component(part: &str) -> bool {
    if part.is_empty()
        || part.len() > 255
        || !part.is_ascii()
        || part.ends_with([' ', '.'])
        || part.bytes().any(|b| b < 32 || matches!(b, b':' | b'<' | b'>' | b'"' | b'|' | b'?' | b'*' | b'~' | b'%' | b'\\' | b'/'))
    {
        return false;
    }
    let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        && !stem
            .strip_prefix("COM")
            .or_else(|| stem.strip_prefix("LPT"))
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

struct Index<'a> {
    names: BTreeMap<(Option<&'a str>, String), Vec<&'a Artifact>>,
    unicode_scopes: BTreeSet<Option<&'a str>>,
    input_listing_complete: bool,
    container_listings: BTreeMap<&'a str, bool>,
}

impl<'a> Index<'a> {
    fn directory_supplied(&self, scope: Option<&str>, path: &str) -> bool {
        if path.is_empty() {
            return true;
        }
        let prefix = format!("{path}/").to_ascii_lowercase();
        self.names
            .range((scope, prefix.clone())..)
            .next()
            .is_some_and(|((namespace, name), _)| *namespace == scope && name.starts_with(&prefix))
    }

    fn new(artifacts: &'a [Artifact], input_listing_complete: bool) -> Result<Self, &'static str> {
        if artifacts.len() > MAX_INDEX_FILES {
            return Err("supplied-file index exceeds 100,000 artifacts");
        }
        let mut index =
            Self { names: BTreeMap::new(), unicode_scopes: BTreeSet::new(), input_listing_complete, container_listings: BTreeMap::new() };
        let mut bytes = 0usize;
        for file in artifacts {
            let path = local_path(file).ok_or("artifact namespace is inconsistent")?;
            bytes = bytes.saturating_add(file.path.len());
            if bytes > MAX_INDEX_BYTES || file.path.len() > MAX_TEXT {
                return Err("supplied-file index exceeds its path byte budget");
            }
            let scope = file.parent.as_deref();
            if let Some(complete) = file.facts.get("engine.container-listing").and_then(|f| f.get("complete")).and_then(Value::as_bool) {
                index.container_listings.insert(&file.path, complete);
            }
            if !path.is_ascii() {
                index.unicode_scopes.insert(scope);
            }
            index.names.entry((scope, path.to_ascii_lowercase())).or_default().push(file);
        }
        Ok(index)
    }

    fn resolve(&self, source: &Artifact, pending: &Pending<'_>) -> Result<&'a Artifact, &'static str> {
        let text = pending.text;
        if text.is_empty() {
            return Err("empty-reference");
        }
        if text.len() > MAX_TEXT {
            return Err("reference-text-limit");
        }
        if text.contains("[redacted") {
            return Err("redacted-reference");
        }
        if text.contains('%') {
            return Err("variables-or-escaped-uri-not-expanded");
        }
        if matches!(pending.basis, Basis::InfDirectory) && text.contains(['/', '\\']) {
            return Err("inf-catalog-declaration-is-not-a-sibling-name");
        }
        if matches!(pending.basis, Basis::Uri) {
            return Err("uri-not-resolved");
        }
        if matches!(pending.basis, Basis::CommandLine) {
            return Err("command-line-not-resolved");
        }
        if text.starts_with(['/', '\\']) || text.contains(':') {
            return Err("absolute-or-device-path-not-anchored");
        }
        if !matches!(pending.basis, Basis::ShortcutDirectory | Basis::InfDirectory) {
            return Err("host-relative-base-not-established");
        }
        if name_changed(source) {
            return Err("source-entry-name-not-original-or-unique");
        }
        let scope = source.parent.as_deref();
        match scope {
            None if !self.input_listing_complete => return Err("input-listing-completeness-not-established"),
            Some(container) if self.container_listings.get(container) != Some(&true) => {
                return Err("container-listing-completeness-not-established");
            }
            _ => {}
        }
        if self.unicode_scopes.contains(&scope) {
            return Err("unicode-alias-profile-not-established");
        }
        let local = local_path(source).ok_or("source-namespace-inconsistent")?;
        if !local.split('/').all(ordinary_component) {
            return Err("source-path-outside-match-profile");
        }
        let mut parts: Vec<&str> = local.rsplit_once('/').map(|(folder, _)| folder.split('/').collect()).unwrap_or_default();
        for length in 1..=parts.len() {
            if self.names.contains_key(&(scope, parts[..length].join("/").to_ascii_lowercase())) {
                return Err("source-directory-is-also-a-file");
            }
        }
        let raw: Vec<_> = text.split(['/', '\\']).collect();
        if raw.len() > 512 {
            return Err("reference-component-limit");
        }
        if matches!(raw.last().copied(), Some("" | "." | "..")) {
            return Err("directory-reference-not-an-artifact");
        }
        for (position, part) in raw.iter().enumerate() {
            match *part {
                "." => continue,
                ".." => {
                    if parts.pop().is_none() {
                        return Err("reference-escapes-container-namespace");
                    }
                }
                ordinary if ordinary_component(ordinary) => parts.push(ordinary),
                _ => return Err("reference-path-outside-match-profile"),
            }
            if position + 1 < raw.len() {
                let path = parts.join("/").to_ascii_lowercase();
                if self.names.contains_key(&(scope, path.clone())) {
                    return Err("intermediate-component-is-a-file");
                }
                if !self.directory_supplied(scope, &path) {
                    return Err("intermediate-directory-not-supplied");
                }
            }
        }
        let path = parts.join("/").to_ascii_lowercase();
        let candidates = self.names.get(&(scope, path)).ok_or("target-not-supplied-in-same-container")?;
        if candidates.len() != 1 {
            return Err("case-alias-or-duplicate-target");
        }
        let target = candidates[0];
        if name_changed(target) {
            return Err("target-entry-name-not-original-or-unique");
        }
        if target.digests.is_none() {
            return Err("target-content-unreadable");
        }
        Ok(target)
    }
}

fn is_source(file: &Artifact) -> bool {
    ["windows.shell-link", "windows.internet-shortcut", "windows.registry", "windows.scheduled-task", "windows.inf"]
        .iter()
        .any(|key| file.facts.contains_key(*key))
}

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    if !tree.artifacts().iter().any(is_source) {
        return;
    }
    let complete = tree.summary().get("engine.input-listing").and_then(|f| f.get("complete")).and_then(Value::as_bool) == Some(true);
    let index = match Index::new(tree.artifacts(), complete) {
        Ok(index) => index,
        Err(reason) => {
            out.limitation("windows.input-reference-limit", None, Some(reason.into()));
            return;
        }
    };
    for (sources, source) in tree.artifacts().iter().filter(|f| is_source(f)).enumerate() {
        if sources == MAX_SOURCES {
            out.limitation("windows.input-reference-limit", None, Some("only the first 10,000 declaration sources were considered".into()));
            break;
        }
        let collected = collect(source);
        if collected.pending.is_empty() && !collected.truncated {
            continue;
        }
        let mut references = Vec::new();
        let mut matches = Vec::new();
        let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
        for pending in &collected.pending {
            let resolved = index.resolve(source, pending);
            let (target, reason) = match resolved {
                Ok(target) => {
                    matches.push((pending, target));
                    (Some(target), None)
                }
                Err(reason) => {
                    *reasons.entry(reason).or_default() += 1;
                    (None, Some(reason))
                }
            };
            references.push(Reference {
                field: pending.field.clone(),
                basis: pending.basis,
                declared: (pending.text.len() <= MAX_TEXT).then_some(pending.text),
                declared_bytes: pending.text.len(),
                status: if target.is_some() { "matched-supplied-declaration" } else { "unresolved" },
                reason,
                target: target.map(|t| t.path.as_str()),
                target_sha256: target.and_then(|t| t.digests.as_ref().map(|d| d.sha256.as_str())),
                source_literal: pending.source_literal,
            });
        }
        out.fact(source, "windows.input-references", json!({"profile": "ascii-relative-paths-within-container", "references": references, "truncated": collected.truncated, "runtime_target_resolved": false}));
        if !matches.is_empty() {
            let mut finding = Finding::new(Section::Structure, "windows", "windows.input-reference", Confidence::Derived, Severity::Info)
                .param("count", matches.len());
            for (pending, target) in matches.iter().take(12) {
                finding = finding
                    .evidence(Evidence::field(source, &pending.field, pending.source_literal.unwrap_or(pending.text)))
                    .evidence(Evidence::whole(target, target.digests.as_ref().map(|d| d.sha256.as_str())));
                if pending.source_literal.is_some_and(|literal| literal != pending.text) {
                    finding =
                        finding.evidence(Evidence::field(source, format!("{}/neutral-strings-projection", pending.field), pending.text));
                }
            }
            out.finding(finding);
        }
        if !reasons.is_empty() {
            out.limitation("windows.input-reference-unresolved", Some(source), Some(json!(reasons).to_string()));
        }
        if collected.truncated {
            out.limitation(
                "windows.input-reference-limit",
                Some(source),
                Some("only the first 512 reference declarations were considered".into()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;

    struct Supplied {
        artifacts: Vec<Artifact>,
    }
    impl Tree for Supplied {
        fn summary(&self) -> &BTreeMap<String, Value> {
            static COMPLETE: std::sync::LazyLock<BTreeMap<String, Value>> =
                std::sync::LazyLock::new(|| BTreeMap::from([("engine.input-listing".into(), json!({"complete": true}))]));
            &COMPLETE
        }
        fn artifacts(&self) -> &[Artifact] {
            &self.artifacts
        }
        fn read(&self, _: &str) -> std::io::Result<aa_core::plugin::Bytes> {
            panic!("reference checking must not read any target")
        }
    }
    fn file(path: &str, parent: Option<&str>) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: 7,
            digests: Some(Digests { md5: "0".repeat(32), sha1: "0".repeat(40), sha256: aa_core::sha256_hex(b"payload") }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    fn shortcut(path: &str, parent: Option<&str>, relative: &str) -> Artifact {
        let mut source = file(path, parent);
        source.facts.insert("windows.shell-link".into(), json!({"declarations": [{"field": "RelativePath", "value": relative}]}));
        source
    }
    fn container(path: &str) -> Artifact {
        let mut file = file(path, None);
        file.facts.insert("engine.container-listing".into(), json!({"complete": true}));
        file
    }
    fn fact<'a>(out: &'a Output, path: &str) -> &'a Value {
        &out.facts
            .iter()
            .find(|f| f.artifact.as_deref() == Some(path) && f.key == "windows.input-references")
            .expect("reference fact")
            .value
    }
    fn check(artifacts: Vec<Artifact>, source: &str) -> Value {
        let mut out = Output::default();
        analyze(&Supplied { artifacts }, &mut out);
        fact(&out, source)["references"][0].clone()
    }

    #[test]
    fn relative_declarations_match_supplied_siblings_without_reading_them() {
        let source = shortcut("app/shortcuts/launch.lnk", None, r"..\BIN\Tool.EXE");
        let target = file("app/bin/tool.exe", None);
        let mut out = Output::default();
        analyze(&Supplied { artifacts: vec![source, target] }, &mut out);
        let reference = &fact(&out, "app/shortcuts/launch.lnk")["references"][0];
        assert_eq!(reference["target"], "app/bin/tool.exe");
        assert_eq!(reference["status"], "matched-supplied-declaration");
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].evidence.len(), 2);
        assert_eq!(out.findings[0].evidence[1].value, aa_core::sha256_hex(b"payload"));
        assert_eq!(fact(&out, "app/shortcuts/launch.lnk")["runtime_target_resolved"], false);
    }

    #[test]
    fn namespace_escapes_aliases_changed_names_and_file_directory_conflicts_do_not_link() {
        for relative in [
            r"C:\target.exe",
            r"\\server\share\target.exe",
            r"\target.exe",
            r"%X%\target.exe",
            "[redacted]",
            "target.exe:stream",
            "target.exe.",
            "target.exe ",
            "PROGRA~1/target.exe",
            "NUL.exe",
            "../target.exe",
        ] {
            let reference = check(vec![shortcut("launch.lnk", None, relative), file("target.exe", None)], "launch.lnk");
            assert_eq!(reference["status"], "unresolved", "{relative}");
            assert!(reference["target"].is_null());
        }
        let alias =
            check(vec![shortcut("launch.lnk", None, "target.exe"), file("target.exe", None), file("TARGET.EXE", None)], "launch.lnk");
        assert_eq!(alias["reason"], "case-alias-or-duplicate-target");
        let unicode = check(vec![shortcut("launch.lnk", None, "target.exe"), file("target.exe", None), file("ı.exe", None)], "launch.lnk");
        assert_eq!(unicode["reason"], "unicode-alias-profile-not-established");
        let conflict =
            check(vec![shortcut("launch.lnk", None, "folder/../target.exe"), file("folder", None), file("target.exe", None)], "launch.lnk");
        assert_eq!(conflict["reason"], "intermediate-component-is-a-file");
        let missing_directory = check(vec![shortcut("launch.lnk", None, "missing/../target.exe"), file("target.exe", None)], "launch.lnk");
        assert_eq!(missing_directory["reason"], "intermediate-directory-not-supplied");
        let mut changed = file("target.exe", None);
        changed.facts.insert("engine.entry-name".into(), json!({"colliding": true}));
        let changed = check(vec![shortcut("launch.lnk", None, "target.exe"), changed], "launch.lnk");
        assert_eq!(changed["reason"], "target-entry-name-not-original-or-unique");
        let escape = check(
            vec![container("pack.zip"), shortcut("pack.zip/launch.lnk", Some("pack.zip"), "../target.exe"), file("target.exe", None)],
            "pack.zip/launch.lnk",
        );
        assert_eq!(escape["reason"], "reference-escapes-container-namespace");
        let other = check(
            vec![
                container("pack.zip"),
                container("other.zip"),
                shortcut("pack.zip/launch.lnk", Some("pack.zip"), "target.exe"),
                file("other.zip/target.exe", Some("other.zip")),
            ],
            "pack.zip/launch.lnk",
        );
        assert_eq!(other["reason"], "target-not-supplied-in-same-container");
        let same = check(
            vec![
                container("pack.zip"),
                shortcut("pack.zip/sub/launch.lnk", Some("pack.zip"), "../target.exe"),
                file("pack.zip/target.exe", Some("pack.zip")),
            ],
            "pack.zip/sub/launch.lnk",
        );
        assert_eq!(same["target"], "pack.zip/target.exe");
    }

    #[test]
    fn task_registry_and_url_bases_are_not_guessed_from_the_configuration_folder() {
        let mut task = file("task.xml", None);
        task.facts.insert("windows.scheduled-task".into(), json!({"declarations": {"children": [{"element": "Actions", "interpreted": true, "children": [{"element": "Exec", "interpreted": true, "children": [{"element": "Command", "interpreted": true, "path": "Task/Actions[1]/Exec[1]/Command[1]", "text": "target.exe"}]}]}]}}));
        let mut reg = file("settings.reg", None);
        reg.facts.insert("windows.registry".into(), json!({"entries": [{"operation": "set_value", "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Fixture", "value": "target.exe", "line": 3, "tags": ["autostart"]}, {"operation": "delete_value", "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Old", "value": "target.exe", "line": 4, "tags": ["autostart"]}]}));
        let mut url = file("launch.url", None);
        url.facts.insert("windows.internet-shortcut".into(), json!({"fields": [["url", "file:target.exe"]]}));
        let mut out = Output::default();
        analyze(&Supplied { artifacts: vec![task, reg, url, file("target.exe", None)] }, &mut out);
        assert!(out.findings.is_empty());
        assert_eq!(fact(&out, "task.xml")["references"][0]["reason"], "host-relative-base-not-established");
        assert_eq!(fact(&out, "settings.reg")["references"][0]["reason"], "command-line-not-resolved");
        assert_eq!(
            fact(&out, "settings.reg")["references"].as_array().expect("references").len(),
            1,
            "deletions are not launch references"
        );
        assert_eq!(fact(&out, "launch.url")["references"][0]["reason"], "uri-not-resolved");
    }

    #[test]
    fn limits_never_turn_a_partial_index_into_a_unique_match() {
        let mut out = Output::default();
        let mut artifacts = vec![shortcut("launch.lnk", None, "target.exe"), file("target.exe", None)];
        artifacts.push(file(&"x".repeat(MAX_TEXT + 1), None));
        analyze(&Supplied { artifacts }, &mut out);
        assert!(out.findings.is_empty());
        assert!(out.facts.is_empty());
        assert_eq!(out.limitations[0].code, "windows.input-reference-limit");
        let large = check(vec![shortcut("launch.lnk", None, &"x".repeat(MAX_TEXT + 1))], "launch.lnk");
        assert!(large["declared"].is_null());
        assert_eq!(large["declared_bytes"], MAX_TEXT + 1);
        let mut many = file("launch.lnk", None);
        many.facts.insert("windows.shell-link".into(), json!({"declarations": (0..MAX_REFERENCES + 1).map(|_| json!({"field": "RelativePath", "value": "missing.exe"})).collect::<Vec<_>>()}));
        let mut out = Output::default();
        analyze(&Supplied { artifacts: vec![many] }, &mut out);
        assert_eq!(fact(&out, "launch.lnk")["references"].as_array().expect("limited references").len(), MAX_REFERENCES);
        assert_eq!(fact(&out, "launch.lnk")["truncated"], true);
    }

    #[test]
    fn total_index_count_and_byte_budgets_close_the_index() {
        let template = file("", None);
        let many = vec![template.clone(); MAX_INDEX_FILES + 1];
        assert!(Index::new(&many, true).err().expect("index count limit").contains("100,000"));
        drop(many);
        let prefix = "p/".repeat((MAX_TEXT - 6) / 2);
        let long: Vec<_> = (0..MAX_INDEX_BYTES / MAX_TEXT + 1)
            .map(|i| {
                let mut artifact = template.clone();
                artifact.path = format!("{prefix}{i:06}");
                artifact
            })
            .collect();
        assert_eq!(long[0].path.len(), MAX_TEXT);
        assert!(Index::new(&long, true).err().expect("total index byte limit").contains("byte budget"));
    }

    #[test]
    fn sources_after_the_global_budget_are_not_silently_claimed_as_checked() {
        let artifacts = (0..MAX_SOURCES + 1).map(|i| shortcut(&format!("launch-{i:05}.lnk"), None, "missing.exe")).collect();
        let mut out = Output::default();
        analyze(&Supplied { artifacts }, &mut out);
        assert_eq!(out.facts.len(), MAX_SOURCES);
        assert!(!out.facts.iter().any(|f| f.artifact.as_deref() == Some("launch-10000.lnk")));
        assert!(out.limitations.iter().any(|l| l.code == "windows.input-reference-limit" && l.artifact.is_none()));
    }

    #[test]
    fn absent_listing_metadata_does_not_establish_uniqueness() {
        struct UnknownListing(Vec<Artifact>);
        impl Tree for UnknownListing {
            fn artifacts(&self) -> &[Artifact] {
                &self.0
            }
            fn read(&self, _: &str) -> std::io::Result<aa_core::plugin::Bytes> {
                panic!("must not read targets")
            }
        }
        let mut out = Output::default();
        analyze(&UnknownListing(vec![shortcut("launch.lnk", None, "target.exe"), file("target.exe", None)]), &mut out);
        assert!(out.findings.is_empty());
        assert_eq!(fact(&out, "launch.lnk")["references"][0]["reason"], "input-listing-completeness-not-established");
        let unknown_container = check(
            vec![
                file("pack.zip", None),
                shortcut("pack.zip/launch.lnk", Some("pack.zip"), "target.exe"),
                file("pack.zip/target.exe", Some("pack.zip")),
            ],
            "pack.zip/launch.lnk",
        );
        assert_eq!(unknown_container["reason"], "container-listing-completeness-not-established");
    }
}
