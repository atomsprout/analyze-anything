//! Associate literal WinGet package dependency declarations with supplied manifests.

use std::collections::BTreeMap;

use aa_core::plugin::{Output, Tree};
use serde_json::{Value, json};

use super::text;

pub(super) fn attach(tree: &dyn Tree, out: &mut Output, packages: &BTreeMap<&str, &Value>, summary: &mut Value) {
    let mut candidates = BTreeMap::<(Option<&str>, &str), Vec<(&str, &Value)>>::new();
    for (&source, &fact) in packages {
        if let (Some(artifact), Some(id)) = (tree.get(source), text(fact, "id")) {
            candidates.entry((artifact.parent.as_deref(), id)).or_default().push((source, fact));
        }
    }
    let mut relationships = Vec::new();
    'packages: for (&source, &fact) in packages {
        let Some(artifact) = tree.get(source) else { continue };
        let scope = artifact.parent.as_deref();
        let complete = match scope {
            Some(parent) => tree.get(parent).is_some_and(|container| container.facts["engine.container-listing"]["complete"] == true),
            None => tree.summary()["engine.input-listing"]["complete"] == true,
        };
        let default = std::iter::once((None, &fact["dependencies"]));
        let installers =
            fact["installers"].as_array().into_iter().flatten().map(|installer| (installer["line"].as_u64(), &installer["dependencies"]));
        for (installer_line, rows) in default.chain(installers) {
            for declaration in rows.as_array().into_iter().flatten() {
                let Some(id) = text(declaration, "id") else { continue };
                if relationships.len() == 4096 {
                    out.limitation("composition.winget-dependency-budget", None, None);
                    break 'packages;
                }
                let minimum = text(declaration, "minimum_version");
                let (status, target) = if !complete {
                    ("incomplete-input", None)
                } else if declaration["minimum_version_supported"] != true {
                    ("unsupported-minimum-version", None)
                } else {
                    match candidates.get(&(scope, id)).map(Vec::as_slice) {
                        Some([(path, _)]) if *path == source => ("self-reference", None),
                        Some([(path, target)]) if minimum.is_none() || minimum == text(target, "version") => {
                            ("supplied-candidate", Some(*path))
                        }
                        Some([_]) => ("unresolved-minimum-version", None),
                        Some(_) => ("ambiguous-candidates", None),
                        None => ("not-supplied", None),
                    }
                };
                relationships.push(json!({
                    "source":source,"source_manifest":fact["installer_manifest"],"source_sha256":fact["installer_manifest_sha256"],
                    "line":declaration["line"],"installer_line":installer_line,"id":id,
                    "minimum_version":minimum,"status":status,"target":target,
                    "target_sha256":target.and_then(|path| tree.get(path)).and_then(|artifact| artifact.digests.as_ref()).map(|d| &d.sha256),
                }));
            }
        }
    }
    if !relationships.is_empty() {
        summary["winget_dependencies"] = json!(relationships);
    }
}
