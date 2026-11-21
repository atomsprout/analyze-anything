//! Read literal VSIX deployment declarations and associate them with captured ZIP members.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use roxmltree::Node;
use serde_json::{Value, json};

const NAMESPACE: &str = "http://schemas.microsoft.com/developer/vsx-schema/2011";
const MAX_XML: usize = 1024 * 1024;
const MAX_ROWS: usize = 512;

fn named(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(NAMESPACE) && node.tag_name().name() == name
}

fn children<'a, 'input>(node: Node<'a, 'input>, name: &'static str) -> impl Iterator<Item = Node<'a, 'input>> + Clone {
    node.children().filter(move |node| named(*node, name))
}

fn one<'a, 'input>(node: Node<'a, 'input>, name: &'static str) -> Option<Node<'a, 'input>> {
    let mut matches = children(node, name);
    matches.next().filter(|_| matches.next().is_none())
}

fn declared(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return None;
    }
    aa_core::text::redact_sensitive_text(value).ok().filter(|text| text == value)
}

fn scalar(node: Node<'_, '_>) -> Option<String> {
    if node.children().any(|child| child.is_element()) {
        return None;
    }
    let text: String = node.children().filter(Node::is_text).filter_map(|child| child.text()).collect();
    declared(&text)
}

fn version(value: &str) -> Option<[Option<i32>; 4]> {
    let mut parts = [None; 4];
    for (index, part) in value.split('.').enumerate() {
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        *parts.get_mut(index)? = Some(part.parse().ok()?);
    }
    parts[1].is_some().then_some(parts)
}

#[derive(Default)]
struct Issues {
    rows: Vec<Value>,
    omitted: usize,
}

impl Issues {
    fn add(&mut self, node: Node<'_, '_>, reason: &'static str) {
        if self.rows.len() < 64 {
            self.rows.push(json!({"utf8_offset":node.range().start,"reason":reason}));
        } else {
            self.omitted += 1;
        }
    }
}

fn rows(root: Node<'_, '_>, section: &'static str, item: &'static str, fields: &[(&str, &str)], issues: &mut Issues) -> Vec<Value> {
    let mut all = children(root, section);
    let Some(parent) = all.next() else { return Vec::new() };
    if all.next().is_some() {
        issues.add(parent, "repeated section");
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut dependency_ids = BTreeSet::new();
    for (index, node) in parent.children().filter(Node::is_element).enumerate() {
        if index == MAX_ROWS {
            issues.add(node, "declaration count limit");
            break;
        }
        if !named(node, item) {
            issues.add(node, "unsupported element in declaration section");
            continue;
        }
        let mut row = json!({"utf8_offset":node.range().start});
        for &(attr, key) in fields {
            if let Some(raw) = node.attribute(attr) {
                if let Some(value) = declared(raw) {
                    row[key] = json!(value);
                } else {
                    issues.add(node, "attribute outside the supported text profile");
                }
            }
        }
        if fields.first().is_some_and(|(_, key)| row.get(*key).is_none()) || (item == "Asset" && row.get("path").is_none()) {
            issues.add(node, "required declaration field missing");
            continue;
        }
        if item == "InstallationTarget" && children(node, "ProductArchitecture").next().is_some() {
            if let Some(architecture) = one(node, "ProductArchitecture").and_then(scalar) {
                row["architecture"] = json!(architecture);
            } else {
                issues.add(node, "invalid or repeated product architecture");
            }
        }
        if item == "Dependency"
            && let Some(id) = row["id"].as_str()
            && !dependency_ids.insert(id.to_owned())
        {
            issues.add(node, "repeated dependency identity");
        }
        found.push(row);
    }
    found
}

fn read(bytes: &[u8]) -> Result<Value, &'static str> {
    let text = crate::msix_xml::decode(bytes, MAX_XML)?;
    let document = roxmltree::Document::parse_with_options(&text, roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 20_000 })
        .map_err(|_| "VSIX XML is malformed, contains a DTD or exceeds its node budget")?;
    let root = document.root_element();
    if !named(root, "PackageManifest") || !matches!(root.attribute("Version"), Some("2.0" | "2.0.0")) {
        return Err("only the VSIX 2.0 deployment manifest is supported");
    }
    let metadata = one(root, "Metadata").ok_or("expected one qualified Metadata section")?;
    let identity = one(metadata, "Identity").ok_or("expected one qualified Identity declaration")?;
    let id = identity.attribute("Id").and_then(declared).ok_or("missing supported Identity Id")?;
    let package_version =
        identity.attribute("Version").filter(|v| v.len() <= 64 && version(v).is_some()).ok_or("unsupported Identity Version")?;
    let publisher = identity.attribute("Publisher").and_then(declared).ok_or("missing supported Identity Publisher")?;
    let mut issues = Issues::default();
    let mut optional = |node, name| {
        let value = one(node, name).and_then(scalar);
        if value.is_none() && children(node, name).next().is_some() {
            issues.add(node, "invalid or repeated metadata field");
        }
        value
    };
    let display_name = optional(metadata, "DisplayName");
    let license = optional(metadata, "License");
    let targets = rows(root, "Installation", "InstallationTarget", &[("Id", "id"), ("Version", "range"), ("Scope", "scope")], &mut issues);
    let dependencies = rows(
        root,
        "Dependencies",
        "Dependency",
        &[("Id", "id"), ("Version", "range"), ("Location", "location"), ("DisplayName", "display_name")],
        &mut issues,
    );
    let prerequisites =
        rows(root, "Prerequisites", "Prerequisite", &[("Id", "id"), ("Version", "range"), ("DisplayName", "display_name")], &mut issues);
    let assets = rows(root, "Assets", "Asset", &[("Type", "type"), ("Path", "path"), ("TargetVersion", "target_version")], &mut issues);
    let installation = one(root, "Installation").map(|node| {
        json!({
            "all_users":node.attribute("AllUsers").and_then(declared),
            "installed_by_msi":node.attribute("InstalledByMsi").and_then(declared),
            "system_component":node.attribute("SystemComponent").and_then(declared),
            "scope":node.attribute("Scope").and_then(declared),
        })
    });
    Ok(json!({
        "id":id,"name":display_name,"version":package_version,"publisher":publisher,"license_path":license,
        "language":identity.attribute("Language").and_then(declared),"installation":installation,
        "targets":targets,"dependencies":dependencies,"prerequisites":prerequisites,"assets":assets,
        "source_sha256":aa_core::sha256_hex(bytes),"offset_basis":"decoded-UTF8",
        "identity_utf8_offset":identity.range().start,"issues":issues.rows,"issues_omitted":issues.omitted
    }))
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("vsixmanifest") {
        return;
    }
    let manifest = read(bytes).and_then(|value| {
        file.digests.as_ref().filter(|d| value["source_sha256"] == d.sha256).map(|_| value).ok_or("manifest differs from captured bytes")
    });
    let manifest = match manifest {
        Ok(manifest) => manifest,
        Err(reason) => {
            out.limitation("windows.vsix-manifest-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    if manifest["issues"].as_array().is_some_and(|rows| !rows.is_empty()) {
        out.limitation("windows.vsix-manifest-incomplete", Some(file), None);
    }
    out.finding(
        Finding::new(Section::Composition, "windows", "windows.vsix-identity", Confidence::Verified, Severity::Info)
            .param("name", manifest["id"].clone())
            .param("version", manifest["version"].clone())
            .param("publisher", manifest["publisher"].clone())
            .evidence(Evidence::field(
                file,
                "PackageManifest/Metadata/Identity",
                json!({
                    "id":manifest["id"],"version":manifest["version"],"publisher":manifest["publisher"],
                    "utf8_offset":manifest["identity_utf8_offset"]
                }),
            )),
    );
    out.kind(file, "vsix-manifest");
    out.fact(file, "windows.vsix-manifest", manifest);
}

fn qualified_manifest<'a>(package: &Artifact, children: &[&'a Artifact]) -> Option<&'a Artifact> {
    if crate::references::name_changed(package)
        || package.unpacked_by.as_deref() != Some("zip")
        || package.facts["engine.container-listing"]["complete"] != true
        || package.digests.is_none()
    {
        return None;
    }
    let prefix = format!("{}/", package.path);
    let mut matching = children
        .iter()
        .copied()
        .filter(|member| member.path.strip_prefix(&prefix).is_some_and(|relative| relative.eq_ignore_ascii_case("extension.vsixmanifest")));
    matching.next().filter(|member| {
        matching.next().is_none() && !crate::references::name_changed(member) && member.facts.contains_key("windows.vsix-manifest")
    })
}

fn bind<'a>(path: &str, members: &BTreeMap<String, Vec<&'a Artifact>>) -> (&'static str, Option<&'a Artifact>) {
    if path.contains("://") {
        return ("external-location", None);
    }
    let relative = path.replace('\\', "/");
    if !relative.split('/').all(crate::references::ordinary_component) {
        return ("outside-relative-member-profile", None);
    }
    match members.get(&relative.to_ascii_lowercase()).map(Vec::as_slice) {
        Some([member]) if !crate::references::name_changed(member) && member.digests.is_some() => ("present", Some(*member)),
        Some([_]) => ("unqualified-member", None),
        Some(_) => ("ambiguous-member", None),
        None => ("member-not-captured", None),
    }
}

fn row_binding(row: &Value, field: &str, members: &BTreeMap<String, Vec<&Artifact>>) -> Value {
    let (status, member) = row[field].as_str().map_or(("no-location-declared", None), |path| bind(path, members));
    json!({
        "utf8_offset":row["utf8_offset"],"declared_path":row[field],"status":status,
        "target":member.map(|member| &member.path),
        "sha256":member.and_then(|member| member.digests.as_ref()).map(|digest| &digest.sha256),
    })
}

pub(super) fn analyze_tree(tree: &dyn Tree, out: &mut Output) {
    let artifacts = tree.artifacts();
    if !artifacts.iter().any(|artifact| artifact.extension().as_deref() == Some("vsix")) {
        return;
    }
    if artifacts.len() > 100_000 {
        out.limitation("windows.vsix-package-unresolved", None, Some("artifact index count limit".into()));
        return;
    }
    let mut children = BTreeMap::<&str, Vec<&Artifact>>::new();
    for member in artifacts {
        if let Some(parent) = member.parent.as_deref() {
            children.entry(parent).or_default().push(member);
        }
    }
    let mut qualified = BTreeMap::new();
    for (index, package) in artifacts.iter().filter(|artifact| artifact.extension().as_deref() == Some("vsix")).enumerate() {
        if index == 128 {
            out.limitation("windows.vsix-package-unresolved", None, Some("package count limit".into()));
            break;
        }
        let direct = children.get(package.path.as_str()).map_or(&[][..], Vec::as_slice);
        if let Some(manifest) = qualified_manifest(package, direct) {
            qualified.insert(package.path.as_str(), (package, manifest, direct));
        } else {
            out.limitation(
                "windows.vsix-package-unresolved",
                Some(package),
                Some("requires a complete ZIP and one qualified root manifest".into()),
            );
        }
    }
    for (&path, &(package, manifest, direct)) in &qualified {
        let fact = &manifest.facts["windows.vsix-manifest"];
        let prefix = format!("{path}/");
        let mut members = BTreeMap::<String, Vec<&Artifact>>::new();
        for member in direct {
            if let Some(relative) = member.path.strip_prefix(&prefix) {
                members.entry(relative.to_ascii_lowercase()).or_default().push(member);
            }
        }
        let assets: Vec<_> = fact["assets"].as_array().into_iter().flatten().map(|row| row_binding(row, "path", &members)).collect();
        let dependencies: Vec<_> = fact["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|row| {
                let mut binding = row_binding(row, "location", &members);
                binding["id"] = row["id"].clone();
                binding["declared_range"] = row["range"].clone();
                if let Some(target) = binding["target"].as_str() {
                    let status = if let Some((_, target_manifest, _)) = qualified.get(target) {
                        let target_fact = &target_manifest.facts["windows.vsix-manifest"];
                        if row["id"] != target_fact["id"] {
                            "identity-mismatch"
                        } else if let Some(exact) = row["range"].as_str().and_then(exact_version) {
                            if target_fact["version"].as_str().and_then(version) == Some(exact) {
                                "exact-match"
                            } else {
                                "version-mismatch"
                            }
                        } else {
                            "unresolved-range"
                        }
                    } else {
                        "unqualified-nested-vsix"
                    };
                    binding["status"] = json!(status);
                }
                binding
            })
            .collect();
        let license = row_binding(&json!({"license":fact["license_path"]}), "license", &members);
        out.kind(package, "vsix-package");
        out.fact(
            package,
            "windows.vsix-package",
            json!({
                "id":fact["id"],"name":fact["name"],"version":fact["version"],"publisher":fact["publisher"],
                "source_manifest":manifest.path,"source_sha256":fact["source_sha256"],
                "package_sha256":package.digests.as_ref().map(|d| &d.sha256),
            "assets":assets,"license":license,"dependencies":dependencies,
            "declarations_complete":fact["issues"].as_array().is_some_and(Vec::is_empty),
            }),
        );
    }
}

fn exact_version(value: &str) -> Option<[Option<i32>; 4]> {
    version(value.strip_prefix('[').and_then(|value| value.strip_suffix(']')).map_or(value, str::trim))
}
