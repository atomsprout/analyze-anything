//! One list of the software components found inside the input, gathered from what the format
//! analyzers read: embedded Apple frameworks, NuGet packages a .NET app declares, the Electron
//! runtime and an app's declared npm dependencies, Android SDKs.
//!
//! Summary fact `composition.components`:
//! `{components: [{name, version, kind, ecosystem, purl, source, declared_range}], total, truncated}`.
//! `version` is what the component itself states; `declared_range` is a range a manifest asks
//! for, which says what was wanted, not what was shipped. Either may be null. `source` is the
//! artifact the entry was read from.

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub struct Components;

/// Components listed in the summary fact.
const LISTED: usize = 5000;

const RULES: &[Rule] = &[Rule {
    id: "composition.components",
    title_zh: "组件清单",
    title_en: "Component list",
    text_zh: "从包内的清单和元数据中读出 {total} 个软件组件（{breakdown}）。这只包括各分析器能从声明信息里读到的组件；静态编译进程序里的库不在其中。完整清单见摘要数据 composition.components，也可导出为 CycloneDX。",
    text_en: "{total} software components were read from manifests and metadata in the package ({breakdown}). Only components that declare themselves are listed; libraries compiled statically into a program are not. The full list is in the summary data composition.components and can be exported as CycloneDX.",
}];

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
        let kind = match self.ecosystem {
            "nuget" => "nuget",
            "npm" => "npm",
            "maven" => "maven",
            _ => return None,
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
            apple_embedded(artifact, &mut found);
            declares_packages |= dotnet_app(artifact, &mut found);
        }
        // Assemblies are the same libraries the package list names, seen as files. They are
        // listed only when no package list was found, so nothing is counted twice.
        if !declares_packages {
            for artifact in tree.artifacts() {
                dotnet_assembly(artifact, &mut found);
            }
        }
        electron(tree, &mut found);
        android(tree, &mut found);
        if found.is_empty() {
            return;
        }
        found.sort();
        found.dedup_by(|a, b| {
            (a.ecosystem, &a.name, &a.version, &a.declared_range) == (b.ecosystem, &b.name, &b.version, &b.declared_range)
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
                json!({
                    "name": c.name,
                    "version": c.version,
                    "kind": c.kind,
                    "ecosystem": c.ecosystem,
                    "purl": c.purl(),
                    "source": c.source,
                    "declared_range": c.declared_range,
                })
            })
            .collect();
        out.summary("composition.components", json!({ "components": listed, "total": found.len(), "truncated": found.len() > LISTED }));
        let mut finding = Finding::new(Section::Composition, "composition", "composition.components", Confidence::Derived, Severity::Info)
            .param("total", found.len())
            .param("breakdown", breakdown);
        let mut cited = std::collections::BTreeSet::new();
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

fn apple_embedded(artifact: &Artifact, found: &mut Vec<Component>) {
    let Some(items) = artifact.facts.get("apple.embedded").and_then(|f| f.get("items")).and_then(Value::as_array) else { return };
    for item in items {
        let Some(path) = text(item, "path") else { continue };
        let file = path.rsplit('/').next().unwrap_or(path);
        let name = file.rsplit_once('.').map(|(stem, _)| stem).unwrap_or(file);
        let kind = match text(item, "kind") {
            Some("framework") => "framework",
            Some("app" | "appex" | "xpc") => "application",
            _ => "library",
        };
        found.push(Component {
            ecosystem: "apple",
            name: text(item, "bundle_id").unwrap_or(name).to_string(),
            version: text(item, "version").map(str::to_string),
            kind,
            declared_range: None,
            source: path.to_string(),
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
