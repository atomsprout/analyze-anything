//! Bounded NuGet package metadata projection.

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use roxmltree::Node;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_DEPENDENCIES: usize = 512;
const MAX_FIELD: usize = 1024;

fn field(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > MAX_FIELD || raw.chars().any(char::is_control) {
        return None;
    }
    aa_core::text::redact_sensitive_text(raw).ok().filter(|text| text == raw)
}

fn scalar(node: Node<'_, '_>) -> Option<String> {
    if node.children().any(|child| child.is_element()) || node.attributes().len() != 0 {
        return None;
    }
    let text: String = node.children().filter(Node::is_text).filter_map(|child| child.text()).collect();
    field(&text)
}

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn version(value: &str) -> bool {
    if value.len() > 64 {
        return false;
    }
    let (base, build) = value.split_once('+').map_or((value, None), |(base, build)| (base, Some(build)));
    let (base, pre) = base.split_once('-').map_or((base, None), |(base, pre)| (base, Some(pre)));
    let labels =
        |value: &str| value.split('.').all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    let mut count = 0;
    for number in base.split('.') {
        count += 1;
        if count > 4 || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) || number.parse::<i32>().is_err() {
            return false;
        }
    }
    pre.is_none_or(labels) && build.is_none_or(labels)
}

struct Model {
    issues: Vec<Value>,
    omitted: usize,
    dependencies: usize,
}

impl Model {
    fn issue(&mut self, node: Node<'_, '_>, reason: &str) {
        if self.issues.len() < 64 {
            self.issues.push(json!({"utf8_offset":node.range().start,"reason":reason}));
        } else {
            self.omitted += 1;
        }
    }

    fn dependency_rows<'a, 'input: 'a>(&mut self, nodes: impl Iterator<Item = Node<'a, 'input>>) -> Vec<Value> {
        let mut rows = Vec::new();
        for node in nodes {
            if self.dependencies == MAX_DEPENDENCIES {
                self.issue(node, "dependency count budget");
                break;
            }
            self.dependencies += 1;
            let name = node.attribute("id").and_then(field).filter(|value| id(value));
            let range = node.attribute("version").and_then(field);
            let include = node.attribute("include").and_then(field);
            let exclude = node.attribute("exclude").and_then(field);
            if name.is_none()
                || (node.attribute("version").is_some() && range.is_none())
                || (node.attribute("include").is_some() && include.is_none())
                || (node.attribute("exclude").is_some() && exclude.is_none())
                || node
                    .children()
                    .any(|child| child.is_element() || child.text().is_some_and(|text| child.is_text() && !text.trim().is_empty()))
            {
                self.issue(node, "dependency identity, range or contents outside the supported profile");
                continue;
            }
            rows.push(json!({"id":name,"declared_range":range,"include":include,"exclude":exclude,
                "utf8_offset":node.range().start}));
        }
        rows
    }
}

fn is(node: Node<'_, '_>, ns: Option<&str>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == ns && node.tag_name().name() == name
}

fn one<'a, 'input>(node: Node<'a, 'input>, ns: Option<&str>, name: &str) -> Option<Node<'a, 'input>> {
    let mut nodes = node.children().filter(|child| is(*child, ns, name));
    let first = nodes.next()?;
    nodes.next().is_none().then_some(first)
}

pub(super) fn read(bytes: &[u8]) -> Result<Value, &'static str> {
    let text = crate::msix_xml::decode(bytes, MAX_BYTES)?;
    let doc = roxmltree::Document::parse_with_options(&text, roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 20_000 })
        .map_err(|_| "nuspec XML is malformed, contains a DTD or exceeds its node budget")?;
    let root = doc.root_element();
    let ns = root.tag_name().namespace();
    if root.tag_name().name() != "package"
        || !matches!(
            ns,
            None | Some(
                "http://schemas.microsoft.com/packaging/2010/07/nuspec.xsd"
                    | "http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd"
                    | "http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd"
                    | "http://schemas.microsoft.com/packaging/2013/01/nuspec.xsd"
                    | "http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"
            )
        )
    {
        return Err("nuspec root outside the supported namespace profile");
    }
    let metadata = one(root, ns, "metadata").ok_or("nuspec requires one qualified metadata section")?;
    let name = one(metadata, ns, "id").and_then(scalar).filter(|value| id(value)).ok_or("no unique qualified NuGet ID")?;
    let package_version =
        one(metadata, ns, "version").and_then(scalar).filter(|value| version(value)).ok_or("no unique supported NuGet version")?;
    let mut model = Model { issues: Vec::new(), omitted: 0, dependencies: 0 };
    let mut groups = Vec::new();
    let mut sections = metadata.children().filter(|node| is(*node, ns, "dependencies"));
    if let Some(dependencies) = sections.next() {
        if sections.next().is_some() {
            model.issue(dependencies, "repeated dependency section");
        } else {
            let entries = dependencies.children().filter(Node::is_element);
            let flat = entries.clone().any(|node| is(node, ns, "dependency"));
            if flat && entries.clone().any(|node| is(node, ns, "group")) {
                model.issue(dependencies, "mixed flat dependencies and framework groups");
            }
            if flat {
                groups.push(json!({"layout":"flat","target_framework":null,"dependencies":model.dependency_rows(entries.clone().filter(|node|is(*node, ns, "dependency")))}));
            }
            for node in entries.filter(|node| !is(*node, ns, "dependency")) {
                if groups.len() >= MAX_GROUPS {
                    model.issue(node, "dependency group count budget");
                    break;
                }
                if !is(node, ns, "group") {
                    model.issue(node, "foreign or unsupported dependency element");
                    continue;
                }
                let framework = node.attribute("targetFramework").and_then(field);
                if node.attribute("targetFramework").is_some() && framework.is_none() {
                    model.issue(node, "target framework outside the supported text profile");
                    continue;
                }
                let children = node.children().filter(Node::is_element);
                if children.clone().any(|child| !is(child, ns, "dependency")) {
                    model.issue(node, "foreign or unsupported dependency group contents");
                }
                groups.push(json!({"layout":"group","target_framework":framework,"dependencies":model.dependency_rows(children.filter(|node|is(*node, ns, "dependency")))}));
            }
        }
    }
    let license = one(metadata, ns, "license").and_then(|node| {
        let kind = node.attribute("type").filter(|value| matches!(*value, "expression" | "file"))?;
        if node.children().any(|child| child.is_element()) {
            return None;
        }
        let text: String = node.children().filter(Node::is_text).filter_map(|child| child.text()).collect();
        Some(json!({"kind":kind,"value":field(&text)?}))
    });
    if metadata.children().any(|node| is(node, ns, "license")) && license.is_none() {
        model.issue(metadata, "repeated or unsupported license declaration");
    }
    Ok(json!({"name":name,"version":package_version,"license":license,"dependency_groups":groups,
        "source_sha256":aa_core::sha256_hex(bytes),"offset_basis":"decoded-UTF8",
        "issues":model.issues,"issues_omitted":model.omitted,"schema_validated":false}))
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("nuspec") {
        return;
    }
    let metadata = match read(bytes) {
        Ok(metadata) if file.digests.as_ref().is_some_and(|d| metadata["source_sha256"] == d.sha256) => metadata,
        Ok(_) => {
            out.limitation("windows.nuspec-unreadable", Some(file), Some("manifest bytes differ from captured source".into()));
            return;
        }
        Err(reason) => {
            out.limitation("windows.nuspec-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    if metadata["issues"].as_array().is_some_and(|rows| !rows.is_empty()) {
        out.limitation("windows.nuspec-incomplete", Some(file), None);
    }
    out.finding(
        Finding::new(Section::Composition, "windows", "windows.nuspec-identity", Confidence::Verified, Severity::Info)
            .param("name", metadata["name"].clone())
            .param("version", metadata["version"].clone())
            .evidence(Evidence::field(
                file,
                "package/metadata",
                json!({"id":metadata["name"],"version":metadata["version"],"license":metadata["license"]}),
            )),
    );
    out.kind(file, "nuget-manifest");
    out.fact(file, "windows.nuspec", metadata);
}

fn asset_kind(path: &str) -> Option<&'static str> {
    let (folder, _) = path.split_once('/')?;
    match folder.to_ascii_lowercase().as_str() {
        "lib" => Some("library"),
        "ref" => Some("reference"),
        "runtimes" => Some("runtime"),
        "build" | "buildtransitive" | "buildmultitargeting" => Some("build"),
        "tools" => Some("tool"),
        "analyzers" => Some("analyzer"),
        "contentfiles" => Some("content"),
        _ => None,
    }
}

pub(super) fn analyze_tree(tree: &dyn Tree, out: &mut Output) {
    let artifacts = tree.artifacts();
    if !artifacts.iter().any(|a| a.extension().as_deref() == Some("nupkg")) {
        return;
    }
    if artifacts.len() > 100_000 {
        out.limitation("windows.nupkg-unresolved", None, Some("package artifact index count budget".into()));
        return;
    }
    let mut children = BTreeMap::<&str, Vec<&Artifact>>::new();
    for child in artifacts {
        if let Some(parent) = child.parent.as_deref() {
            children.entry(parent).or_default().push(child);
        }
    }
    for (index, package) in artifacts.iter().filter(|a| a.extension().as_deref() == Some("nupkg")).enumerate() {
        if index == 128 {
            out.limitation("windows.nupkg-unresolved", None, Some("package count budget".into()));
            break;
        }
        let prefix = format!("{}/", package.path);
        let rows = children.get(package.path.as_str()).map_or(&[][..], Vec::as_slice);
        let root_manifest = |a: &&Artifact| {
            a.extension().as_deref() == Some("nuspec") && a.path.strip_prefix(&prefix).is_some_and(|relative| !relative.contains('/'))
        };
        let mut manifests = rows.iter().copied().filter(root_manifest);
        let manifest = manifests.next().filter(|_| manifests.next().is_none());
        let complete = package.unpacked_by.as_deref() == Some("zip") && package.facts["engine.container-listing"]["complete"] == true;
        let qualified = manifest
            .filter(|a| !crate::references::name_changed(a) && !crate::references::name_changed(package))
            .and_then(|a| Some((a, a.facts.get("windows.nuspec")?)));
        let (Some(digest), Some((manifest, metadata))) = (package.digests.as_ref(), qualified.filter(|_| complete)) else {
            out.limitation(
                "windows.nupkg-unresolved",
                Some(package),
                Some("package requires a complete captured ZIP and one qualified root manifest".into()),
            );
            continue;
        };
        let mut assets = Vec::new();
        let mut asset_count = 0usize;
        for asset in rows {
            let Some(relative) = asset.path.strip_prefix(&prefix) else { continue };
            let Some(kind) = asset_kind(relative) else { continue };
            asset_count += 1;
            if assets.len() == 256 || relative.len() > MAX_FIELD {
                continue;
            }
            let Some(path) = field(relative) else { continue };
            assets.push(json!({"kind":kind,"path":path,"size":asset.size,
                "sha256":asset.digests.as_ref().map(|d|&d.sha256),"name_qualified":!crate::references::name_changed(asset)}));
        }
        if assets.len() != asset_count {
            out.limitation("windows.nupkg-unresolved", Some(package), Some("some asset records exceed the output budget".into()));
        }
        out.kind(package, "nuget-package");
        out.fact(
            package,
            "windows.nupkg",
            json!({"name":metadata["name"],"version":metadata["version"],"license":metadata["license"],
            "source_manifest":manifest.path,"source_sha256":metadata["source_sha256"],"package_sha256":digest.sha256,"assets":assets,
            "asset_count":asset_count,"assets_omitted":asset_count-assets.len(),"dependency_resolution_performed":false}),
        );
    }
}
