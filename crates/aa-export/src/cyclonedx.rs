//! CycloneDX 1.5 software bill of materials, from the report's component list.
//!
//! The document carries no serial number or timestamp, so the same report always exports to the
//! same bytes.

use aa_core::Report;
use serde_json::{Value, json};

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The report's components as a CycloneDX document. A report without a component list gives a
/// document with no components, which is a valid statement that none were declared.
pub fn cyclonedx(report: &Report) -> Value {
    let listed = report.summary.get("composition.components");
    let components: Vec<Value> = listed
        .and_then(|f| f.get("components"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .filter_map(|(index, component)| {
            let name = text(component, "name")?;
            let kind = match text(component, "kind") {
                Some("framework") => "framework",
                Some("application") => "application",
                _ => "library",
            };
            let mut entry = json!({ "type": kind, "name": name, "bom-ref": format!("component-{index}") });
            if let Some(version) = text(component, "version") {
                entry["version"] = json!(version);
            }
            if let Some(purl) = text(component, "purl") {
                entry["purl"] = json!(purl);
            }
            let mut properties = Vec::new();
            for (key, property) in [("ecosystem", "aa:ecosystem"), ("source", "aa:source"), ("declared_range", "aa:declared-range")] {
                if let Some(value) = text(component, key) {
                    properties.push(json!({ "name": property, "value": value }));
                }
            }
            entry["properties"] = json!(properties);
            Some(entry)
        })
        .collect();
    let mut subject = json!({ "type": "file", "name": report.input.name, "bom-ref": "input" });
    if let Some(sha256) = &report.input.sha256 {
        subject["hashes"] = json!([{ "alg": "SHA-256", "content": sha256 }]);
    }
    let truncated = listed.and_then(|f| f.get("truncated")).and_then(Value::as_bool).unwrap_or(false);
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{ "name": report.tool.name, "version": report.tool.version }],
            "component": subject,
            "properties": [{ "name": "aa:component-list-truncated", "value": truncated.to_string() }],
        },
        "components": components,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aa_core::{Coverage, Input, InputKind, SCHEMA_VERSION, Tool};

    use super::*;

    fn report(summary: BTreeMap<String, Value>) -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            tool: Tool { name: "analyze-anything".into(), version: "0.0.1".into() },
            input: Input { name: "app.zip".into(), kind: InputKind::File, sha256: Some("ab".repeat(32)) },
            summary,
            artifacts: Vec::new(),
            findings: Vec::new(),
            limitations: Vec::new(),
            coverage: Coverage::default(),
            rules: BTreeMap::new(),
        }
    }

    #[test]
    fn components_are_exported_with_what_is_known() {
        let components = json!({ "total": 2, "truncated": false, "components": [
            { "name": "Humanizer.Core", "version": "2.14.1", "kind": "library", "ecosystem": "nuget", "purl": "pkg:nuget/Humanizer.Core@2.14.1", "source": "app.zip/app.deps.json", "declared_range": null },
            { "name": "ws", "version": null, "kind": "library", "ecosystem": "npm", "purl": null, "source": "app.zip/app.asar", "declared_range": "^8.13.0" },
        ]});
        let bom = cyclonedx(&report(BTreeMap::from([("composition.components".to_string(), components)])));
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["metadata"]["component"]["hashes"][0]["content"], "ab".repeat(32));
        assert_eq!(bom["components"][0]["purl"], "pkg:nuget/Humanizer.Core@2.14.1");
        assert_eq!(bom["components"][0]["version"], "2.14.1");
        let ws = &bom["components"][1];
        assert!(ws.get("version").is_none(), "a requested range is not a shipped version");
        assert!(ws.get("purl").is_none());
        assert_eq!(ws["properties"][2], json!({ "name": "aa:declared-range", "value": "^8.13.0" }));
    }

    #[test]
    fn report_without_components_gives_an_empty_list() {
        let bom = cyclonedx(&report(BTreeMap::new()));
        assert_eq!(bom["components"], json!([]));
        assert_eq!(bom["specVersion"], "1.5");
    }
}
