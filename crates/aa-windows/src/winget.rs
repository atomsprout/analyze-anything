//! Literal WinGet YAML declarations, associated only with supplied artifacts.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use yaml_rust2::parser::{Event, Parser};

const MAX_BYTES: usize = 256 * 1024;

struct Node {
    line: usize,
    value: Yaml,
}

enum Yaml {
    Scalar(String),
    Mapping(BTreeMap<String, Node>),
    Sequence(Vec<Node>),
}

impl Node {
    fn field(&self, key: &str) -> Option<&Self> {
        match &self.value {
            Yaml::Mapping(children) => children.get(key),
            _ => None,
        }
    }

    fn sequence(&self) -> Option<&[Self]> {
        match &self.value {
            Yaml::Sequence(children) => Some(children),
            _ => None,
        }
    }

    fn literal(&self) -> Option<&str> {
        match &self.value {
            Yaml::Scalar(value) if !value.is_empty() && value.len() <= 1024 && !value.chars().any(char::is_control) => Some(value),
            _ => None,
        }
    }

    fn text(&self, key: &str) -> Option<String> {
        let value = self.field(key)?.literal()?;
        aa_core::text::redact_sensitive_text(value).ok().filter(|sanitized| sanitized == value)
    }
}

struct Reader<'a> {
    parser: Parser<std::str::Chars<'a>>,
    events: usize,
}

impl Reader<'_> {
    fn next(&mut self) -> Result<(Event, usize), &'static str> {
        self.events += 1;
        if self.events > 12_000 {
            return Err("YAML event count limit");
        }
        self.parser.next_token().map(|(event, mark)| (event, mark.line())).map_err(|_| "malformed YAML")
    }

    fn node(&mut self, event: Event, line: usize, depth: usize) -> Result<Node, &'static str> {
        if depth > 24 {
            return Err("YAML nesting limit");
        }
        let value = match event {
            Event::Scalar(value, _, 0, None) => Yaml::Scalar(value),
            Event::MappingStart(0, None) => {
                let mut fields = BTreeMap::new();
                loop {
                    let key = match self.next()?.0 {
                        Event::MappingEnd => break,
                        Event::Scalar(key, _, 0, None) if !key.is_empty() && key.len() <= 128 && key != "<<" => key,
                        _ => return Err("unsupported YAML mapping key"),
                    };
                    let (event, line) = self.next()?;
                    let value = self.node(event, line, depth + 1)?;
                    if fields.insert(key, value).is_some() {
                        return Err("duplicate YAML mapping key");
                    }
                }
                Yaml::Mapping(fields)
            }
            Event::SequenceStart(0, None) => {
                let mut rows = Vec::new();
                loop {
                    let (event, line) = self.next()?;
                    if event == Event::SequenceEnd {
                        break;
                    }
                    rows.push(self.node(event, line, depth + 1)?);
                }
                Yaml::Sequence(rows)
            }
            _ => return Err("unsupported YAML tags, anchors or aliases"),
        };
        Ok(Node { line, value })
    }
}

fn document(text: &str) -> Result<Node, &'static str> {
    let mut reader = Reader { parser: Parser::new_from_str(text), events: 0 };
    if reader.next()?.0 != Event::StreamStart || reader.next()?.0 != Event::DocumentStart {
        return Err("missing YAML document");
    }
    let (event, line) = reader.next()?;
    let root = reader.node(event, line, 0)?;
    if !matches!(root.value, Yaml::Mapping(_)) || reader.next()?.0 != Event::DocumentEnd || reader.next()?.0 != Event::StreamEnd {
        return Err("expected one YAML mapping document");
    }
    Ok(root)
}

fn switches(node: Option<&Node>, output: &mut BTreeMap<&'static str, String>) -> bool {
    let Some(node) = node else { return true };
    let Yaml::Mapping(values) = &node.value else { return false };
    let names = ["Silent", "SilentWithProgress", "Interactive", "InstallLocation", "Log", "Upgrade", "Custom", "Repair"];
    let mut recognized = 0;
    for name in names {
        if values.contains_key(name) {
            recognized += 1;
            // A redacted override must never fall back to a less specific declaration.
            output.remove(name);
            if let Some(value) = node.text(name) {
                output.insert(name, value);
            }
        }
    }
    recognized == values.len() && names.iter().all(|name| !values.contains_key(*name) || output.contains_key(name))
}

fn package_dependencies(node: &Node, incomplete: &mut bool) -> Vec<Value> {
    let Some(dependencies) = node.field("Dependencies") else { return Vec::new() };
    let Yaml::Mapping(fields) = &dependencies.value else {
        *incomplete = true;
        return Vec::new();
    };
    let mut declared = Vec::new();
    for (kind, list) in fields {
        let Some(rows) = list.sequence() else {
            *incomplete = true;
            continue;
        };
        *incomplete |= rows.len() > 128;
        for row in rows.iter().take(128) {
            let dependency = match kind.as_str() {
                "PackageDependencies" => row.text("PackageIdentifier").map(|id| {
                    let minimum = row.text("MinimumVersion");
                    let supported = row.field("MinimumVersion").is_none() || minimum.is_some();
                    *incomplete |= !supported;
                    json!({"kind":"package","id":id,"minimum_version":minimum,"minimum_version_supported":supported,"line":row.line})
                }),
                "WindowsFeatures" | "WindowsLibraries" | "ExternalDependencies" => row
                    .literal()
                    .and_then(|value| aa_core::text::redact_sensitive_text(value).ok().filter(|clean| clean == value))
                    .map(|name| json!({"kind":kind,"name":name,"line":row.line})),
                _ => None,
            };
            if let Some(dependency) = dependency {
                declared.push(dependency);
            } else {
                *incomplete = true;
            }
        }
    }
    declared
}

fn read(text: &str) -> Result<Value, &'static str> {
    let document = document(text)?;
    let version_character = |ch: char| !matches!(ch, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|');
    let id = document
        .text("PackageIdentifier")
        .filter(|id| {
            id.chars().count() <= 128
                && (2..=8).contains(&id.split('.').count())
                && id.split('.').all(|part| {
                    (1..=32).contains(&part.chars().count()) && part.chars().all(|ch| !ch.is_whitespace() && version_character(ch))
                })
        })
        .ok_or("unsupported PackageIdentifier")?;
    let version = document
        .text("PackageVersion")
        .filter(|version| version.chars().count() <= 128 && version.chars().all(version_character))
        .ok_or("missing supported PackageVersion")?;
    let kind = document
        .text("ManifestType")
        .filter(|kind| matches!(kind.as_str(), "singleton" | "version" | "installer" | "defaultLocale" | "locale"))
        .ok_or("unsupported ManifestType")?;
    let schema = document
        .text("ManifestVersion")
        .filter(|schema| {
            schema.starts_with("1.")
                && schema.split('.').count() == 3
                && schema.split('.').all(|part| part.bytes().all(|byte| byte.is_ascii_digit()) && part.parse::<u16>().is_ok())
        })
        .ok_or("only version 1.x manifest declarations are supported")?;
    let mut incomplete = false;
    if matches!(kind.as_str(), "singleton" | "defaultLocale") {
        incomplete |= ["PackageLocale", "Publisher", "PackageName", "License"].iter().any(|key| document.text(key).is_none());
    }
    let mut rows = Vec::new();
    let mut default_switches = BTreeMap::new();
    incomplete |= !switches(document.field("InstallerSwitches"), &mut default_switches);
    if matches!(kind.as_str(), "singleton" | "installer") {
        if let Some(installers) = document.field("Installers").and_then(Node::sequence) {
            incomplete |= installers.is_empty() || installers.len() > 128 || (kind == "singleton" && installers.len() != 1);
            for installer in installers.iter().take(128) {
                let installer_type = if installer.field("InstallerType").is_some() {
                    installer.text("InstallerType")
                } else {
                    document.text("InstallerType")
                };
                let architecture = installer.text("Architecture");
                let url = installer.text("InstallerUrl");
                let sha256 = installer
                    .text("InstallerSha256")
                    .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
                    .map(|hash| hash.to_ascii_lowercase());
                let store_id = installer.text("MSStoreProductIdentifier");
                incomplete |= architecture.is_none()
                    || installer_type.is_none()
                    || if installer_type.as_deref() == Some("msstore") { store_id.is_none() } else { url.is_none() || sha256.is_none() };
                let mut effective_switches =
                    if installer.field("InstallerSwitches").is_some_and(|node| !matches!(node.value, Yaml::Mapping(_))) {
                        BTreeMap::new()
                    } else {
                        default_switches.clone()
                    };
                incomplete |= !switches(installer.field("InstallerSwitches"), &mut effective_switches);
                let dependencies = package_dependencies(installer, &mut incomplete);
                rows.push(json!({
                    "line":installer.line,"architecture":architecture,"installer_type":installer_type,
                    "url":url,"sha256":sha256,"store_id":store_id,"switches":effective_switches,
                    "dependencies":dependencies,
                }));
            }
        } else {
            incomplete = true;
        }
    }
    let dependencies = package_dependencies(&document, &mut incomplete);
    Ok(json!({
        "id":id,"version":version,"type":kind,"schema_version":schema,
        "publisher":document.text("Publisher"),"display_name":document.text("PackageName"),"license":document.text("License"),
        "locale":document.text("PackageLocale"),"default_locale":document.text("DefaultLocale"),
        "identity_line":document.field("PackageIdentifier").map(|node| node.line),
        "installers":rows,"dependencies":dependencies,"incomplete":incomplete,
    }))
}

fn recognizable(text: &str) -> bool {
    let head = &text.as_bytes()[..text.len().min(16 * 1024)];
    [b"PackageIdentifier".as_slice(), b"ManifestType", b"ManifestVersion"]
        .iter()
        .all(|key| head.windows(key.len()).any(|window| window == *key))
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !matches!(file.extension().as_deref(), Some("yaml" | "yml")) {
        return;
    }
    let Ok(text) = crate::text::decode(bytes, MAX_BYTES) else {
        let prefix = &bytes[..bytes.len().min(16 * 1024)];
        if recognizable(&String::from_utf8_lossy(prefix)) {
            out.limitation("windows.winget-unreadable", Some(file), Some("YAML encoding or byte limit".into()));
        }
        return;
    };
    if !recognizable(&text) {
        return;
    }
    let mut manifest = match read(&text) {
        Ok(manifest) => manifest,
        Err(reason) => {
            out.limitation("windows.winget-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    let sha256 = aa_core::sha256_hex(bytes);
    if file.digests.as_ref().is_none_or(|d| d.sha256 != sha256) {
        out.limitation("windows.winget-unreadable", Some(file), Some("YAML differs from captured bytes".into()));
        return;
    }
    if manifest["incomplete"] == true {
        out.limitation("windows.winget-manifest-incomplete", Some(file), None);
    }
    manifest["source_sha256"] = json!(sha256);
    out.finding(
        Finding::new(Section::Composition, "windows", "windows.winget-manifest", Confidence::Verified, Severity::Info)
            .param("name", manifest["id"].clone())
            .param("version", manifest["version"].clone())
            .param("type", manifest["type"].clone())
            .evidence(Evidence::field(
                file,
                "PackageIdentifier/PackageVersion/ManifestType",
                json!({"id":manifest["id"],"version":manifest["version"],"type":manifest["type"],"line":manifest["identity_line"]}),
            )),
    );
    out.kind(file, "winget-manifest");
    out.fact(file, "windows.winget-manifest", manifest);
}

type Scope<'a> = (Option<&'a str>, &'a str);
type Digests<'a> = BTreeMap<&'a str, Vec<&'a Artifact>>;

fn scope(artifact: &Artifact) -> Scope<'_> {
    (artifact.parent.as_deref(), artifact.path.rsplit_once('/').map_or("", |(directory, _)| directory))
}

fn complete(tree: &dyn Tree, scope: Scope<'_>) -> bool {
    match scope.0 {
        Some(parent) => tree.get(parent).is_some_and(|artifact| artifact.facts["engine.container-listing"]["complete"] == true),
        None => tree.summary()["engine.input-listing"]["complete"] == true,
    }
}

fn grouped<'a>(group: &[(&'a Artifact, &'a Value)], kind: &str) -> Option<(&'a Artifact, &'a Value)> {
    let mut matches = group.iter().copied().filter(|(_, manifest)| manifest["type"] == kind);
    matches.next().filter(|_| matches.next().is_none())
}

fn associated_installers(installer: &Value, members: Option<&Digests<'_>>, complete: bool) -> Vec<Value> {
    installer["installers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|row| {
            let mut row = row.clone();
            let mut matched = None;
            let status = if !complete {
                "incomplete-input"
            } else if let Some(hash) = row["sha256"].as_str() {
                match members.and_then(|index| index.get(hash)).map(Vec::as_slice) {
                    Some([member]) if !crate::references::name_changed(member) => {
                        matched = Some(member.path.as_str());
                        "sha256-match"
                    }
                    Some([_]) => "unqualified-sha256-match",
                    Some(_) => "ambiguous-sha256",
                    None => "no-supplied-sha256-match",
                }
            } else {
                "no-declared-sha256"
            };
            row["status"] = json!(status);
            row["target"] = json!(matched);
            row
        })
        .collect()
}

pub(super) fn analyze_tree(tree: &dyn Tree, out: &mut Output) {
    let artifacts = tree.artifacts();
    if !artifacts.iter().any(|artifact| artifact.facts.contains_key("windows.winget-manifest")) {
        return;
    }
    if artifacts.len() > 100_000 {
        out.limitation("windows.winget-set-unresolved", None, Some("artifact count limit".into()));
        return;
    }
    let mut indexed = BTreeMap::<Scope<'_>, Digests<'_>>::new();
    let mut groups = BTreeMap::<(Scope<'_>, &str, &str), Vec<(&Artifact, &Value)>>::new();
    for artifact in artifacts {
        if let Some(manifest) = artifact.facts.get("windows.winget-manifest")
            && let (Some(id), Some(version)) = (manifest["id"].as_str(), manifest["version"].as_str())
        {
            let scope = scope(artifact);
            indexed.entry(scope).or_default();
            groups.entry((scope, id, version)).or_default().push((artifact, manifest));
        }
    }
    for artifact in artifacts {
        if let Some(index) = indexed.get_mut(&scope(artifact))
            && let Some(digests) = &artifact.digests
        {
            index.entry(&digests.sha256).or_default().push(artifact);
        }
    }
    for (index, ((scope, id, version), group)) in groups.into_iter().enumerate() {
        if index == 128 {
            out.limitation("windows.winget-set-unresolved", None, Some("manifest set count limit".into()));
            break;
        }
        let listing_complete = complete(tree, scope);
        let members = indexed.get(&scope);
        if let [(source, manifest)] = group.as_slice()
            && manifest["type"] == "singleton"
            && !crate::references::name_changed(source)
        {
            emit(source, manifest, (source, manifest), &group, members, listing_complete, out);
            continue;
        }
        let set = grouped(&group, "version").zip(grouped(&group, "installer")).zip(grouped(&group, "defaultLocale"));
        if let Some((((source, source_manifest), (installer_file, installer)), (_, locale))) = set
            && listing_complete
            && group.len() <= 128
            && source_manifest["default_locale"].is_string()
            && source_manifest["default_locale"] == locale["locale"]
            && group.iter().all(|(file, member)| {
                member["schema_version"] == source_manifest["schema_version"]
                    && member["type"] != "singleton"
                    && !crate::references::name_changed(file)
            })
            && unique_locales(&group)
        {
            emit(source, locale, (installer_file, installer), &group, members, listing_complete, out);
        } else {
            out.limitation(
                "windows.winget-set-unresolved",
                group.first().map(|(file, _)| *file),
                Some(format!("could not associate a unique complete manifest set for {id} {version}")),
            );
        }
    }
}

fn unique_locales(group: &[(&Artifact, &Value)]) -> bool {
    let mut locales = BTreeSet::new();
    group
        .iter()
        .filter(|(_, manifest)| matches!(manifest["type"].as_str(), Some("locale" | "defaultLocale")))
        .all(|(_, manifest)| manifest["locale"].as_str().is_some_and(|locale| locales.insert(locale.to_ascii_lowercase())))
}

fn emit(
    source: &Artifact,
    locale: &Value,
    (installer_file, installer): (&Artifact, &Value),
    group: &[(&Artifact, &Value)],
    members: Option<&Digests<'_>>,
    listing_complete: bool,
    out: &mut Output,
) {
    let installers = associated_installers(installer, members, listing_complete);
    let manifests: Vec<_> = group
        .iter()
        .map(|(file, metadata)| {
            json!({
                "path":file.path,"sha256":metadata["source_sha256"],"role":metadata["type"],"locale":metadata["locale"],
            })
        })
        .collect();
    out.fact(
        source,
        "windows.winget-package",
        json!({
            "id":locale["id"],"version":locale["version"],"publisher":locale["publisher"],"display_name":locale["display_name"],
            "license":locale["license"],"manifests":manifests,"installer_manifest":installer_file.path,
            "installer_manifest_sha256":installer["source_sha256"],"installers":installers,"dependencies":installer["dependencies"],
        }),
    );
}
