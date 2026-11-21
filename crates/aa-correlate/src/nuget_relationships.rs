//! Evidence that one supplied package declares another and that a matching archive is present.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::Artifact;
use aa_core::plugin::{Output, Tree};
use serde_json::{Value, json};

use super::text;

const MAX_ROWS: usize = 4096;

type Scope<'a> = (Option<&'a str>, &'a str);
type Key = (String, [i32; 4]);

fn scope(artifact: &Artifact) -> Scope<'_> {
    let directory = artifact.path.rsplit_once('/').map_or("", |(directory, _)| directory);
    (artifact.parent.as_deref(), directory)
}

fn stable_version(version: &str) -> Option<[i32; 4]> {
    let mut normalized = [0; 4];
    for (index, number) in version.split('.').enumerate() {
        if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *normalized.get_mut(index)? = number.parse().ok()?;
    }
    Some(normalized)
}

fn exact(range: &str) -> Option<[i32; 4]> {
    stable_version(range.strip_prefix('[')?.strip_suffix(']')?.trim())
}

pub(super) fn identity(name: &str, version: &str) -> (String, String) {
    let version = version.split_once('+').map_or(version, |(base, _)| base);
    let (base, suffix) = version.split_once('-').map_or((version, None), |(base, suffix)| (base, Some(suffix)));
    let normalized = stable_version(base).map_or_else(
        || base.to_owned(),
        |[major, minor, patch, revision]| {
            if revision == 0 { format!("{major}.{minor}.{patch}") } else { format!("{major}.{minor}.{patch}.{revision}") }
        },
    );
    let version = suffix.map_or_else(|| normalized.clone(), |suffix| format!("{normalized}-{}", suffix.to_ascii_lowercase()));
    (name.to_ascii_lowercase(), version)
}

pub(super) fn attach(tree: &dyn Tree, out: &mut Output, manifests: &BTreeMap<&str, &Value>, listed: &[Value], summary: &mut Value) {
    if manifests.is_empty() {
        return;
    }
    let mut candidates = BTreeMap::<(Scope<'_>, Key), Vec<&str>>::new();
    let mut occurrences = BTreeMap::new();
    let mut unread = BTreeSet::new();
    for artifact in tree.artifacts().iter().filter(|a| a.extension().as_deref() == Some("nupkg")) {
        let scope = scope(artifact);
        let Some(manifest) = artifact.facts.get("windows.nupkg") else {
            let _ = unread.insert(scope);
            continue;
        };
        if let (Some(name), Some(version)) = (text(manifest, "name"), text(manifest, "version")) {
            *occurrences.entry(identity(name, version)).or_insert(0usize) += 1;
            let version = version.split_once('+').map_or(version, |(base, _)| base);
            if let Some(version) = stable_version(version) {
                candidates.entry((scope, (name.to_ascii_lowercase(), version))).or_default().push(&artifact.path);
            }
        }
    }
    let indexes: BTreeMap<_, _> = listed
        .iter()
        .enumerate()
        .filter(|(_, row)| row["ecosystem"] == "nuget" && row.get("manifest").is_some())
        .filter_map(|(index, row)| {
            let id = identity(text(row, "name")?, text(row, "version")?);
            let source = text(row, "source")?;
            (occurrences.get(&id) == Some(&1)).then_some((source, index))
        })
        .collect();
    let mut relationships = Vec::new();
    'packages: for (&source, metadata) in manifests {
        let Some(artifact) = tree.get(source) else { continue };
        let manifest_path = text(metadata, "source_manifest").unwrap_or(source);
        let Some(manifest) = tree.get(manifest_path).and_then(|a| a.facts.get("windows.nuspec")) else { continue };
        let scope = scope(artifact);
        let complete = !unread.contains(&scope)
            && match scope.0 {
                Some(parent) => tree.get(parent).is_some_and(|a| a.facts["engine.container-listing"]["complete"] == true),
                None => tree.summary()["engine.input-listing"]["complete"] == true,
            };
        for group in manifest["dependency_groups"].as_array().into_iter().flatten() {
            for declaration in group["dependencies"].as_array().into_iter().flatten() {
                if relationships.len() == MAX_ROWS {
                    out.limitation("composition.nuget-dependency-budget", None, None);
                    break 'packages;
                }
                let Some(name) = text(declaration, "id") else { continue };
                let (status, target) = match text(declaration, "declared_range").and_then(exact) {
                    None => ("unresolved-range", None),
                    Some(_) if !complete => ("incomplete-input", None),
                    Some(version) => match candidates.get(&(scope, (name.to_ascii_lowercase(), version))).map(Vec::as_slice) {
                        Some([target]) if *target != source => ("present", Some(*target)),
                        Some([_]) => ("self-reference", None),
                        Some(_) => ("ambiguous", None),
                        None => ("not-supplied", None),
                    },
                };
                let mut row = json!({
                    "source":source,"source_manifest":manifest_path,"source_sha256":manifest["source_sha256"],
                    "utf8_offset":declaration["utf8_offset"],"id":name,"declared_range":declaration["declared_range"],
                    "group_layout":group["layout"],"target_framework":group["target_framework"],"status":status,
                });
                if let Some(target) = target {
                    row["target"] = json!(target);
                    row["target_sha256"] = manifests[target]["package_sha256"].clone();
                    if group["layout"] == "flat"
                        && manifest["issues"].as_array().is_some_and(Vec::is_empty)
                        && artifact.facts.contains_key("windows.nupkg")
                        && let (Some(from), Some(to)) = (indexes.get(source), indexes.get(target))
                    {
                        row["components"] = json!([from, to]);
                    }
                }
                relationships.push(row);
            }
        }
    }
    if !relationships.is_empty() {
        summary["nuget_dependencies"] = json!(relationships);
    }
}
