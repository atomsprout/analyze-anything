//! Android: APK and AAB packages.
//!
//! One analyzer, `android`, working in the tree pass: it finds packages (an APK file, an
//! extracted APK folder, an app bundle, a set of split APKs), decodes the manifest and resource
//! table, verifies the signatures, reads the DEX tables and fingerprints what the package is
//! built from. Nothing is executed or decompiled. See `docs/ANALYZERS.md` for the contract.

mod aab;
mod arsc;
mod attr_ids;
mod axml;
mod crypto;
mod der;
mod dex;
mod elf;
mod emit_code;
mod emit_manifest;
mod emit_signing;
mod jarsign;
mod known_certs;
mod manifest;
mod metadata;
mod netsec;
mod permissions;
mod proto;
mod reader;
mod rules;
mod sdks;
mod sigblock;
mod strpool;
mod unpack;
mod x509;
mod xml;
mod zipraw;

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Bytes, Output, Rule, Tree, Unpacker};
use aa_core::{Artifact, Confidence, Finding, Section, Severity};
use serde_json::{Value as Json, json};

use crate::manifest::Resolver;

/// Largest manifest or resource table decoded.
const MAX_STRUCTURED_FILE: u64 = 512 * 1024 * 1024;

/// Keeps the first four and last two characters: enough to find a value again, not to use it.
pub(crate) fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 6))
}

/// Starts a finding of this analyzer.
pub(crate) fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, "android", rule, confidence, severity)
}

/// Joins up to `cap` items for a sentence, noting how many were left out.
pub(crate) fn listed<S: AsRef<str>>(items: &[S], cap: usize) -> String {
    let mut text = items.iter().take(cap).map(AsRef::as_ref).collect::<Vec<_>>().join(", ");
    if items.len() > cap {
        text.push_str(&format!(" … (+{})", items.len() - cap));
    }
    text
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageKind {
    /// An `.apk` file.
    Apk,
    /// The files of an APK in a folder.
    Folder,
    /// An app bundle; the files are those of its base module.
    Bundle,
}

/// One package and the files that belong to it.
pub(crate) struct Package<'t> {
    pub tree: &'t dyn Tree,
    pub kind: PackageKind,
    /// The package file; `None` for a folder.
    pub container: Option<&'t Artifact>,
    pub manifest: &'t Artifact,
    /// Files by their path inside the package, as an APK would name them.
    pub files: BTreeMap<String, &'t Artifact>,
}

impl<'t> Package<'t> {
    /// The artifact that stands for the package as a whole in evidence.
    pub fn anchor(&self) -> &'t Artifact {
        self.container.unwrap_or(self.manifest)
    }

    pub fn file(&self, name: &str) -> Option<&'t Artifact> {
        self.files.get(name).copied()
    }

    pub fn read(&self, name: &str) -> Option<Bytes> {
        let artifact = self.file(name)?;
        if artifact.size > MAX_STRUCTURED_FILE {
            return None;
        }
        self.tree.read(&artifact.path).ok()
    }
}

/// The resource table of a package, in whichever format it has.
pub(crate) enum Resources<'a> {
    Arsc(arsc::Table<'a>),
    Proto(aab::ProtoTable<'a>),
    None,
}

impl Resolver for Resources<'_> {
    fn resolve(&self, id: u32) -> Option<arsc::Resolved> {
        match self {
            Resources::Arsc(table) => table.resolve(id),
            Resources::Proto(table) => table.resolve(id),
            Resources::None => None,
        }
    }
}

impl Resources<'_> {
    pub fn find_strings(&self, names: &[&str]) -> BTreeMap<String, String> {
        match self {
            Resources::Arsc(table) => table.find_strings(names),
            Resources::Proto(table) => table.find_strings(names),
            Resources::None => BTreeMap::new(),
        }
    }
}

/// Decodes an XML file of a package, binary or protobuf. `None` for anything else.
pub(crate) fn decode_xml(data: &[u8]) -> Option<xml::Document> {
    if axml::looks_like_axml(data) {
        Some(axml::parse(data))
    } else if aab::looks_like_proto_xml(data) {
        Some(aab::parse_xml(data))
    } else {
        None
    }
}

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(Android)]
}

/// The unpackers this crate provides, most specific first. APK, AAB and XAPK files are ZIP
/// archives and are opened by the generic ZIP unpacker; the one here takes the packages that
/// one cannot open but Android can (data in front of the archive, bogus compression methods).
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(unpack::OddApk)]
}

struct Android;

impl Analyzer for Android {
    fn id(&self) -> &'static str {
        "android"
    }

    fn rules(&self) -> &'static [Rule] {
        rules::RULES
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let packages = find_packages(tree);
        let mut summaries: Vec<(String, Json)> = Vec::new();
        for package in &packages {
            if let Some(summary) = analyze_package(package, out) {
                summaries.push((package.anchor().path.clone(), summary));
            }
        }
        find_apk_sets(tree, &summaries, out);
        if !summaries.is_empty() {
            let list: Vec<Json> = summaries.iter().take(200).map(|(_, s)| s.clone()).collect();
            out.summary("android.packages", json!({ "packages": list, "total": summaries.len(), "truncated": summaries.len() > 200 }));
        }
    }
}

/// Finds every package in the tree, in path order.
fn find_packages(tree: &dyn Tree) -> Vec<Package<'_>> {
    let mut packages = Vec::new();
    for manifest in tree.artifacts().iter().filter(|a| a.name() == "AndroidManifest.xml" && a.digests.is_some()) {
        let dir = manifest.path.strip_suffix("AndroidManifest.xml").unwrap_or("").trim_end_matches('/');
        let parent = manifest.parent.as_deref();
        if parent == Some(dir) {
            // Directly inside a container: an APK.
            let Some(container) = tree.get(dir) else { continue };
            let files = files_below(tree, dir, parent, |name| Some(name.to_string()));
            packages.push(Package { tree, kind: PackageKind::Apk, container: Some(container), manifest, files });
        } else if let Some(container) = parent.and_then(|p| tree.get(p))
            && dir == format!("{}/base/manifest", container.path)
        {
            // The base module of an app bundle. Its files are renamed to their APK paths.
            let module = format!("{}/base", container.path);
            let mut files = files_below(tree, &module, parent, |name| {
                Some(match name.split_once('/') {
                    Some(("manifest", rest)) | Some(("dex", rest)) | Some(("root", rest)) => rest.to_string(),
                    _ => name.to_string(),
                })
            });
            files.extend(files_below(tree, &container.path, parent, |name| name.starts_with("META-INF/").then(|| name.to_string())));
            if tree.get(&format!("{}/BundleConfig.pb", container.path)).is_some() {
                packages.push(Package { tree, kind: PackageKind::Bundle, container: Some(container), manifest, files });
            }
        } else if parent.is_none_or(|p| dir.len() > p.len() && dir.starts_with(p)) {
            // In a folder (of the input, or inside some other archive). Accept it as an
            // extracted APK only when the folder looks like one.
            let is_module_manifest = dir.ends_with("/manifest") || dir == "manifest";
            let files = files_below(tree, dir, parent, |name| Some(name.to_string()));
            let looks_like_apk = files.contains_key("resources.arsc")
                || files.contains_key("classes.dex")
                || files.keys().any(|k| k.starts_with("META-INF/"));
            if !is_module_manifest && looks_like_apk {
                packages.push(Package { tree, kind: PackageKind::Folder, container: None, manifest, files });
            }
        }
    }
    packages
}

/// The artifacts under `dir` that came from the same container as the manifest, keyed by the
/// name `rename` gives their path relative to `dir`.
fn files_below<'t>(
    tree: &'t dyn Tree,
    dir: &str,
    parent: Option<&str>,
    rename: impl Fn(&str) -> Option<String>,
) -> BTreeMap<String, &'t Artifact> {
    let prefix = if dir.is_empty() { String::new() } else { format!("{dir}/") };
    let artifacts = tree.artifacts();
    let start = artifacts.partition_point(|a| a.path.as_str() < prefix.as_str());
    let mut files = BTreeMap::new();
    for artifact in &artifacts[start..] {
        let Some(relative) = artifact.path.strip_prefix(&prefix) else { break };
        if artifact.parent.as_deref() != parent {
            continue;
        }
        if let Some(name) = rename(relative) {
            files.entry(name).or_insert(artifact);
        }
    }
    files
}

/// Analyzes one package. Returns its line in the report summary.
fn analyze_package(package: &Package, out: &mut Output) -> Option<Json> {
    let anchor = package.anchor();
    let manifest_bytes = match package.tree.read(&package.manifest.path) {
        Ok(bytes) if package.manifest.size <= MAX_STRUCTURED_FILE => bytes,
        _ => {
            out.limitation("android.manifest-unreadable", Some(package.manifest), Some("the file could not be read".into()));
            return None;
        }
    };
    let Some(document) = decode_xml(&manifest_bytes) else {
        // A manifest in text form (as decoding tools write it) or something else entirely.
        // Only report it where the surroundings say this is an Android package.
        if package.kind != PackageKind::Folder || manifest_bytes.iter().take(512).any(|b| *b == b'<') {
            out.limitation(
                "android.manifest-unreadable",
                Some(package.manifest),
                Some("not binary XML or protobuf XML; text manifests are not decoded".into()),
            );
        }
        return None;
    };
    let resource_file = match package.kind {
        PackageKind::Bundle => "resources.pb",
        _ => "resources.arsc",
    };
    let resource_bytes = package.read(resource_file);
    let resources = match (&resource_bytes, package.kind) {
        (Some(bytes), PackageKind::Bundle) => aab::ProtoTable::parse(bytes).map(Resources::Proto),
        (Some(bytes), _) => arsc::Table::parse(bytes).map(Resources::Arsc),
        (None, _) => None,
    };
    if resources.is_none()
        && let Some(file) = package.file(resource_file)
    {
        out.limitation("android.resources-unreadable", Some(file), None);
    }
    let resources = resources.unwrap_or(Resources::None);
    let Some(manifest) = manifest::extract(&document, &resources) else {
        out.limitation(
            "android.manifest-unreadable",
            Some(package.manifest),
            Some(format!("no <manifest> root element; {}", listed(&document.anomalies, 3))),
        );
        return None;
    };
    if let Some(container) = package.container {
        out.kind(container, if package.kind == PackageKind::Bundle { "aab" } else { "apk" });
    }
    out.kind(package.manifest, "android-manifest");
    if manifest.truncated {
        out.limitation("android.manifest-truncated", Some(package.manifest), None);
    }

    let is_split = manifest.split.is_some();
    emit_manifest::identity(package, &manifest, &document, out);
    let signing = emit_signing::run(package, &manifest, out);
    if !is_split {
        emit_manifest::hardening(package, &manifest, &resources, out);
        emit_manifest::permissions(package, &manifest, out);
        emit_manifest::components(package, &manifest, out);
        emit_manifest::keys(package, &manifest, &resources, out);
        emit_code::run(package, &manifest, out);
    }
    emit_manifest::resources_fact(package, &resources, out);
    out.fact(package.manifest, "android.manifest", manifest.to_json(2000));

    Some(json!({
        "path": anchor.path,
        "kind": match package.kind { PackageKind::Apk => "apk", PackageKind::Folder => "folder", PackageKind::Bundle => "aab" },
        "package": manifest.package,
        "version_name": manifest.version_name,
        "version_code": manifest.version_code,
        "split": manifest.split,
        "min_sdk": manifest.min_sdk,
        "target_sdk": manifest.target_sdk,
        "label": manifest.application.as_ref().and_then(|a| a.label.as_ref()).and_then(|l| l.value.clone()),
        "signer_sha256": signing,
    }))
}

/// Containers of several APKs: `.xapk`, `.apks`, `.apkm`.
fn find_apk_sets(tree: &dyn Tree, summaries: &[(String, Json)], out: &mut Output) {
    for container in tree.artifacts().iter().filter(|a| a.is("zip") && a.unpacked_by.is_some()) {
        let prefix = format!("{}/", container.path);
        let inside: Vec<&(String, Json)> = summaries
            .iter()
            .filter(|(path, _)| {
                path.starts_with(&prefix) && tree.get(path).is_some_and(|a| a.parent.as_deref() == Some(container.path.as_str()))
            })
            .collect();
        if inside.is_empty() {
            continue;
        }
        let has = |name: &str| tree.get(&format!("{prefix}{name}")).is_some();
        let kind = if has("toc.pb") {
            "apks"
        } else if has("manifest.json") {
            "xapk"
        } else if has("info.json") {
            "apkm"
        } else if inside.len() >= 2 || matches!(container.extension().as_deref(), Some("xapk" | "apks" | "apkm")) {
            match container.extension().as_deref() {
                Some("apks") => "apks",
                Some("apkm") => "apkm",
                _ => "xapk",
            }
        } else {
            continue;
        };
        out.kind(container, kind);
        let base: Vec<&Json> = inside.iter().map(|(_, s)| s).filter(|s| s["split"].is_null()).collect();
        let splits: Vec<String> = inside.iter().filter_map(|(_, s)| s["split"].as_str().map(str::to_string)).collect();
        let signers: std::collections::BTreeSet<String> = inside
            .iter()
            .flat_map(|(_, s)| s["signer_sha256"].as_array().cloned().unwrap_or_default())
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        let packages: std::collections::BTreeSet<&str> = inside.iter().filter_map(|(_, s)| s["package"].as_str()).collect();
        out.fact(
            container,
            "android.apk_set",
            json!({
                "format": kind,
                "apks": inside.iter().take(500).map(|(path, s)| json!({
                    "path": path, "package": s["package"], "split": s["split"], "version_code": s["version_code"], "signer_sha256": s["signer_sha256"],
                })).collect::<Vec<_>>(),
                "truncated": inside.len() > 500,
            }),
        );
        let base_name = base.first().and_then(|s| s["path"].as_str()).map(|p| p.strip_prefix(&prefix).unwrap_or(p).to_string());
        let mut finding = finding(Section::Identity, "android.apk-set", Confidence::Verified, Severity::Info)
            .param("format", kind)
            .param("apks", inside.len())
            .param("base", base_name.clone().unwrap_or_else(|| "?".into()))
            .param("package", listed(&packages.iter().collect::<Vec<_>>(), 3))
            .param("splits", if splits.is_empty() { "-".to_string() } else { listed(&splits, 20) });
        for (path, summary) in inside.iter().take(20) {
            if let Some(apk) = tree.get(path) {
                finding = finding.evidence(aa_core::Evidence::field(apk, "manifest@split", summary["split"].clone()));
            }
        }
        out.finding(finding);
        if signers.len() > 1 || packages.len() > 1 {
            let mut finding =
                aa_core::Finding::new(Section::Anomalies, "android", "android.apk-set-mismatch", Confidence::Verified, Severity::High)
                    .param("packages", packages.len())
                    .param("signers", signers.len());
            for (path, summary) in inside.iter().take(20) {
                if let Some(apk) = tree.get(path) {
                    finding =
                        finding.evidence(aa_core::Evidence::field(apk, "signer certificate SHA-256", summary["signer_sha256"].clone()));
                }
            }
            out.finding(finding);
        }
    }
}

#[cfg(test)]
mod tests;
