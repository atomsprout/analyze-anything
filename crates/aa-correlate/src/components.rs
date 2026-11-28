//! One list of the software components found inside the input, gathered from what the format
//! analyzers read: embedded Apple frameworks, NuGet packages a .NET app declares, the Electron
//! runtime and an app's declared npm dependencies, Android SDKs.
//!
//! Summary fact `composition.components`:
//! `{components: [{name, version, kind, ecosystem, purl, source, declared_range}], total, truncated}`.
//! `version` is what the component itself states; `declared_range` is a range a manifest asks
//! for, which says what was wanted, not what was shipped. Either may be null. `source` is the
//! artifact the entry was read from.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

#[path = "language_packages.rs"]
mod language_packages;
#[path = "nuget_relationships.rs"]
mod nuget_relationships;
#[path = "winget_relationships.rs"]
mod winget_relationships;

pub struct Components;

/// Components listed in the summary fact.
const LISTED: usize = 5000;

const RULES: &[Rule] = &[
    Rule {
        id: "composition.components",
        title_zh: "组件清单",
        title_en: "Component list",
        text_zh: "从包内的清单和元数据中读出 {total} 个软件组件（{breakdown}）。这只包括各分析器能从声明信息里读到的组件；静态编译进程序里的库不在其中。完整清单见摘要数据 composition.components，也可导出为 CycloneDX。",
        text_en: "{total} software components were read from manifests and metadata in the package ({breakdown}). Only components that declare themselves are listed; libraries compiled statically into a program are not. The full list is in the summary data composition.components and can be exported as CycloneDX.",
    },
    Rule {
        id: "composition.nuget-dependency-budget",
        title_zh: "NuGet 依赖关系达到报告上限",
        title_en: "NuGet dependency relationship budget reached",
        text_zh: "部分 NuGet 依赖声明未列入组件关系。原始声明见对应的清单数据。",
        text_en: "Some NuGet dependency declarations were omitted from the component relationships. The corresponding manifest facts retain the source declarations.",
    },
    Rule {
        id: "composition.vsix-dependency-budget",
        title_zh: "VSIX 依赖关系达到报告上限",
        title_en: "VSIX dependency relationship budget reached",
        text_zh: "部分 VSIX 依赖关系未列入组件清单。完整的已读取关系见对应的包数据。",
        text_en: "Some VSIX dependency relationships were omitted from the component inventory. The corresponding package facts retain the captured relationships.",
    },
    Rule {
        id: "composition.winget-dependency-budget",
        title_zh: "WinGet 依赖关系达到报告上限",
        title_en: "WinGet dependency relationship budget reached",
        text_zh: "部分 WinGet 依赖声明未列入组件关系。原始声明见对应的包数据。",
        text_en: "Some WinGet dependency declarations were omitted from the component relationships. The corresponding package facts retain the source declarations.",
    },
];

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Component {
    ecosystem: &'static str,
    name: String,
    version: Option<String>,
    kind: &'static str,
    declared_range: Option<String>,
    source: String,
}

impl Component {
    /// A package URL, for ecosystems that have a registry the name and version identify it in.
    fn purl(&self) -> Option<String> {
        let version = self.version.as_ref()?;
        if matches!(self.ecosystem, "pypi" | "npm" | "maven") {
            return language_packages::purl(self.ecosystem, &self.name, version);
        }
        let kind = match self.ecosystem {
            "nuget" => "nuget",
            _ => return None,
        };
        let version = if kind == "nuget" && version.contains('+') {
            std::borrow::Cow::Owned(version.replace('+', "%2B"))
        } else {
            std::borrow::Cow::Borrowed(version.as_str())
        };
        Some(format!("pkg:{kind}/{}@{version}", self.name))
    }
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.trim().is_empty())
}

impl Analyzer for Components {
    fn id(&self) -> &'static str {
        "composition"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let mut found: Vec<Component> = Vec::new();
        let mut declares_packages = false;
        for artifact in tree.artifacts() {
            apple_embedded(tree, artifact, &mut found);
            declares_packages |= dotnet_app(artifact, &mut found);
        }
        let manifests: BTreeMap<_, _> = tree
            .artifacts()
            .iter()
            .filter_map(|artifact| nuget_manifest(artifact).map(|manifest| (artifact.path.as_str(), manifest)))
            .collect();
        let identities: BTreeSet<_> = manifests
            .values()
            .filter_map(|manifest| Some(nuget_relationships::identity(text(manifest, "name")?, text(manifest, "version")?)))
            .collect();
        found.retain(|component| {
            component.ecosystem != "nuget"
                || component
                    .version
                    .as_ref()
                    .is_none_or(|version| !identities.contains(&nuget_relationships::identity(&component.name, version)))
        });
        let mut seen = BTreeSet::new();
        // Prefer a captured package over a loose declaration of the same identity.
        let packaged = |manifest: &&Value| manifest.get("package_sha256").is_some();
        let manifest_rows =
            manifests.iter().filter(|(_, manifest)| packaged(manifest)).chain(manifests.iter().filter(|(_, manifest)| !packaged(manifest)));
        for (&source, manifest) in manifest_rows {
            if let (Some(name), Some(version)) = (text(manifest, "name"), text(manifest, "version")) {
                if !seen.insert(nuget_relationships::identity(name, version)) {
                    continue;
                }
                found.push(Component {
                    ecosystem: "nuget",
                    name: name.to_owned(),
                    version: Some(version.to_owned()),
                    kind: "library",
                    declared_range: None,
                    source: source.to_owned(),
                });
            }
        }
        // Assemblies are the same libraries the package list names, seen as files. They are
        // listed only when no package list was found, so nothing is counted twice.
        if !declares_packages {
            for artifact in tree.artifacts() {
                if !artifact.parent.as_deref().is_some_and(|parent| manifests.contains_key(parent)) {
                    dotnet_assembly(artifact, &mut found);
                }
            }
        }
        electron(tree, &mut found);
        android(tree, &mut found);
        language_packages::collect(tree, &mut found);
        for artifact in tree.artifacts() {
            for (key, ecosystem) in [("deb.control", "deb"), ("rpm.package", "rpm"), ("arch.package", "alpm")] {
                if let Some(package) = artifact.facts.get(key)
                    && let (Some(name), Some(version)) = (text(package, "name"), text(package, "version"))
                {
                    let version = if ecosystem == "rpm" {
                        text(package, "release").map(|release| format!("{version}-{release}")).unwrap_or_else(|| version.to_string())
                    } else {
                        version.to_string()
                    };
                    found.push(Component {
                        ecosystem,
                        name: name.to_string(),
                        version: Some(version),
                        kind: "application",
                        declared_range: None,
                        source: artifact.path.clone(),
                    });
                }
            }
        }
        let extensions: BTreeMap<_, _> = tree
            .artifacts()
            .iter()
            .filter_map(|artifact| {
                artifact
                    .facts
                    .get("windows.vsix-package")
                    .or_else(|| artifact.parent.is_none().then(|| artifact.facts.get("windows.vsix-manifest")).flatten())
                    .map(|manifest| (artifact.path.as_str(), manifest))
            })
            .collect();
        let mut vsix_occurrences = BTreeMap::new();
        let extension_rows = extensions
            .iter()
            .filter(|(_, manifest)| packaged(manifest))
            .chain(extensions.iter().filter(|(_, manifest)| !packaged(manifest)));
        for (&source, manifest) in extension_rows {
            let (Some(name), Some(version), Some(publisher)) =
                (text(manifest, "id"), text(manifest, "version"), text(manifest, "publisher"))
            else {
                continue;
            };
            let count = vsix_occurrences.entry((name, version, publisher)).or_insert(0usize);
            *count += 1;
            if *count == 1 {
                found.push(Component {
                    ecosystem: "vsix",
                    name: name.to_owned(),
                    version: Some(version.to_owned()),
                    kind: "library",
                    declared_range: None,
                    source: source.to_owned(),
                });
            }
        }
        let winget: BTreeMap<_, _> = tree
            .artifacts()
            .iter()
            .filter_map(|artifact| artifact.facts.get("windows.winget-package").map(|fact| (artifact.path.as_str(), fact)))
            .collect();
        for (&source, package) in &winget {
            if let (Some(name), Some(version)) = (text(package, "id"), text(package, "version")) {
                found.push(Component {
                    ecosystem: "winget",
                    name: name.to_owned(),
                    version: Some(version.to_owned()),
                    kind: "application",
                    declared_range: None,
                    source: source.to_owned(),
                });
            }
        }
        if found.is_empty() {
            return;
        }
        found.sort();
        found.dedup_by(|a, b| {
            a.ecosystem != "vsix"
                && (a.ecosystem, &a.name, &a.version, &a.declared_range) == (b.ecosystem, &b.name, &b.version, &b.declared_range)
        });

        let mut by_ecosystem: BTreeMap<&str, usize> = BTreeMap::new();
        for component in &found {
            *by_ecosystem.entry(component.ecosystem).or_default() += 1;
        }
        let breakdown = by_ecosystem.iter().map(|(ecosystem, count)| format!("{ecosystem}: {count}")).collect::<Vec<_>>().join(", ");
        let listed: Vec<Value> = found
            .iter()
            .take(LISTED)
            .map(|c| {
                let mut row = json!({
                    "name": c.name,
                    "version": c.version,
                    "kind": c.kind,
                    "ecosystem": c.ecosystem,
                    "purl": c.purl(),
                    "source": c.source,
                    "declared_range": c.declared_range,
                });
                if let Some(manifest) = manifests.get(c.source.as_str()).filter(|_| c.ecosystem == "nuget") {
                    row["manifest"] = json!({
                        "path": text(manifest, "source_manifest").unwrap_or(&c.source),
                        "sha256": manifest["source_sha256"]
                    });
                    row["license"] = manifest["license"].clone();
                }
                if let Some(manifest) = extensions.get(c.source.as_str()).filter(|_| c.ecosystem == "vsix") {
                    row["manifest"] = json!({
                        "path": text(manifest, "source_manifest").unwrap_or(&c.source),
                        "sha256": manifest["source_sha256"]
                    });
                    row["publisher"] = manifest["publisher"].clone();
                    row["display_name"] = manifest["name"].clone();
                }
                if let Some(package) = winget.get(c.source.as_str()).filter(|_| c.ecosystem == "winget") {
                    row["manifests"] = package["manifests"].clone();
                    row["publisher"] = package["publisher"].clone();
                    row["display_name"] = package["display_name"].clone();
                    row["declared_license"] = package["license"].clone();
                }
                row
            })
            .collect();
        let mut summary = json!({ "components": listed, "total": found.len(), "truncated": found.len() > LISTED });
        nuget_relationships::attach(tree, out, &manifests, &listed, &mut summary);
        vsix_relationships(out, &extensions, &vsix_occurrences, &listed, &mut summary);
        winget_relationships::attach(tree, out, &winget, &mut summary);
        out.summary("composition.components", summary);
        let mut finding = Finding::new(Section::Composition, "composition", "composition.components", Confidence::Derived, Severity::Info)
            .param("total", found.len())
            .param("breakdown", breakdown);
        let mut cited = BTreeSet::new();
        for component in &found {
            if cited.len() < 5
                && cited.insert(component.source.as_str())
                && let Some(source) = tree.get(&component.source)
            {
                finding = finding.evidence(Evidence::whole(source, component.name.as_str()));
            }
        }
        out.finding(finding);
    }
}

fn vsix_relationships(
    out: &mut Output,
    extensions: &BTreeMap<&str, &Value>,
    occurrences: &BTreeMap<(&str, &str, &str), usize>,
    listed: &[Value],
    summary: &mut Value,
) {
    let indexes: BTreeMap<_, _> = listed
        .iter()
        .enumerate()
        .filter(|(_, row)| row["ecosystem"] == "vsix")
        .filter_map(|(index, row)| {
            let identity = (text(row, "name")?, text(row, "version")?, text(row, "publisher")?);
            let source = text(row, "source")?;
            (occurrences.get(&identity) == Some(&1)).then_some((source, index))
        })
        .collect();
    let mut relationships = Vec::new();
    'packages: for (&source, manifest) in extensions {
        if manifest.get("package_sha256").is_none() {
            continue;
        }
        for relationship in manifest["dependencies"].as_array().into_iter().flatten() {
            if relationships.len() == 4096 {
                out.limitation("composition.vsix-dependency-budget", None, None);
                break 'packages;
            }
            let mut row = relationship.clone();
            row["source"] = json!(source);
            row["source_manifest"] = manifest["source_manifest"].clone();
            row["source_sha256"] = manifest["source_sha256"].clone();
            if row["status"] == "exact-match"
                && manifest["declarations_complete"] == true
                && let Some(target) = text(&row, "target")
                && let (Some(from), Some(to)) = (indexes.get(source), indexes.get(target))
            {
                row["components"] = json!([from, to]);
            }
            relationships.push(row);
        }
    }
    if !relationships.is_empty() {
        summary["vsix_dependencies"] = json!(relationships);
    }
}

fn nuget_manifest(artifact: &Artifact) -> Option<&Value> {
    artifact.facts.get("windows.nupkg").or_else(|| artifact.parent.is_none().then(|| artifact.facts.get("windows.nuspec")).flatten())
}

fn apple_embedded(tree: &dyn Tree, artifact: &Artifact, found: &mut Vec<Component>) {
    let Some(items) = artifact.facts.get("apple.embedded").and_then(|f| f.get("items")).and_then(Value::as_array) else { return };
    for item in items {
        let Some(path) = text(item, "path") else { continue };
        let file = path.rsplit('/').next().unwrap_or(path);
        let name = file.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(file);
        let kind = match text(item, "kind") {
            Some("framework") => "framework",
            Some("app" | "appex" | "app-extension" | "xpc") => "application",
            _ => "library",
        };
        found.push(Component {
            ecosystem: "apple",
            name: text(item, "bundle_id").unwrap_or(name).to_string(),
            version: text(item, "version").map(str::to_string),
            kind,
            declared_range: None,
            // A bundle directory is not an artifact. Cite its identity plist, or the
            // containing declaration if the child identity was not captured.
            source: tree.get(&format!("{path}/Info.plist")).unwrap_or(artifact).path.clone(),
        });
    }
}

/// Packages from a .NET `deps.json`, as `Name Version` strings. Returns whether there was one.
fn dotnet_app(artifact: &Artifact, found: &mut Vec<Component>) -> bool {
    let Some(app) = artifact.facts.get("windows.dotnet-app") else { return false };
    let mut any = false;
    for (key, kind) in [("libraries", "library"), ("frameworks", "framework")] {
        for entry in app.get(key).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            let (name, version) = match entry.rsplit_once(' ') {
                Some((name, version)) => (name, Some(version.to_string())),
                None => (entry, None),
            };
            found.push(Component {
                ecosystem: "nuget",
                name: name.to_string(),
                version,
                kind,
                declared_range: None,
                source: artifact.path.clone(),
            });
            any = true;
        }
    }
    any
}

fn dotnet_assembly(artifact: &Artifact, found: &mut Vec<Component>) {
    let Some(assembly) = artifact.facts.get("windows.dotnet").and_then(|f| f.get("assembly")) else { return };
    if let Some(name) = text(assembly, "name") {
        found.push(Component {
            ecosystem: "dotnet-assembly",
            name: name.to_string(),
            version: text(assembly, "version").map(str::to_string),
            kind: "library",
            declared_range: None,
            source: artifact.path.clone(),
        });
    }
}

fn electron(tree: &dyn Tree, found: &mut Vec<Component>) {
    for app in tree.summary().get("windows.electron").and_then(Value::as_array).into_iter().flatten() {
        let Some(folder) = text(app, "folder") else { continue };
        // The facts were read from files under this folder; cite one that exists in the tree.
        let Some(source) = tree.under(folder).first().map(|a| a.path.clone()) else { continue };
        let mut push = |ecosystem, name: &str, version: Option<&str>, kind, declared_range: Option<&str>| {
            found.push(Component {
                ecosystem,
                name: name.to_string(),
                version: version.map(str::to_string),
                kind,
                declared_range: declared_range.map(str::to_string),
                source: source.clone(),
            });
        };
        if let Some(version) = text(app, "electron_version") {
            push("npm", "electron", Some(version), "framework", None);
        }
        if let Some(version) = text(app, "chrome_version") {
            push("runtime", "chromium", Some(version), "framework", None);
        }
        if let Some(name) = text(app, "name") {
            push("application", name, text(app, "version"), "application", None);
        }
        for dependency in app.get("dependencies").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            // `name@range`; a scoped name starts with `@`, so split at the last one.
            match dependency.rfind('@').filter(|at| *at > 0) {
                Some(at) => push("npm", &dependency[..at], None, "library", Some(&dependency[at + 1..])),
                None => push("npm", dependency, None, "library", None),
            }
        }
    }
}

/// SDKs the Android analyzer recognised by their code packages.
fn android(tree: &dyn Tree, found: &mut Vec<Component>) {
    for artifact in tree.artifacts() {
        let Some(sdks) = artifact.facts.get("android.sdks").and_then(|f| f.get("sdks")).and_then(Value::as_array) else { continue };
        for sdk in sdks {
            if let Some(name) = text(sdk, "name") {
                found.push(Component {
                    ecosystem: "android-sdk",
                    name: name.to_string(),
                    version: text(sdk, "version").map(str::to_string),
                    kind: "library",
                    declared_range: None,
                    source: artifact.path.clone(),
                });
            }
        }
    }
}
