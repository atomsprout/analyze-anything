//! SARIF 2.1.0, the interchange format code-scanning tools and CI systems read.
//!
//! Each finding becomes a result. Neutral facts (`Severity::Info`) are exported with kind
//! `informational`, so viewers that list problems can leave them out.

use aa_core::{Confidence, Finding, Location, Report, Severity, fill};
use serde_json::{Value, json};

/// Which language the exported texts are in. SARIF has one text per message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Zh,
    En,
}

/// Percent-encodes a tree path for use as a relative URI reference.
fn uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

fn confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Verified => "verified",
        Confidence::Derived => "derived",
        Confidence::Heuristic => "heuristic",
    }
}

fn message(report: &Report, language: Language, finding: &Finding) -> String {
    match (report.rules.get(&finding.rule), language) {
        (Some(rule), Language::Zh) => fill(&rule.text_zh, &finding.params),
        (Some(rule), Language::En) => fill(&rule.text_en, &finding.params),
        (None, _) => finding.rule.clone(),
    }
}

/// The report as a SARIF log.
pub fn sarif(report: &Report, language: Language) -> Value {
    let rule_ids: Vec<&String> = {
        let mut ids: Vec<&String> = report.findings.iter().map(|f| &f.rule).collect();
        ids.sort();
        ids.dedup();
        ids
    };
    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            let (title, text) = match (report.rules.get(*id), language) {
                (Some(rule), Language::Zh) => (rule.title_zh.clone(), rule.text_zh.clone()),
                (Some(rule), Language::En) => (rule.title_en.clone(), rule.text_en.clone()),
                (None, _) => ((*id).clone(), String::new()),
            };
            json!({ "id": id, "shortDescription": { "text": title }, "fullDescription": { "text": text } })
        })
        .collect();
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| {
            let locations: Vec<Value> = finding
                .evidence
                .iter()
                .map(|evidence| {
                    let mut physical = json!({ "artifactLocation": { "uri": uri(&evidence.artifact) } });
                    if let Location::Bytes { offset, length } = evidence.location {
                        physical["region"] = json!({ "byteOffset": offset, "byteLength": length });
                    }
                    json!({ "physicalLocation": physical })
                })
                .collect();
            let mut result = json!({
                "ruleId": finding.rule,
                "ruleIndex": rule_ids.iter().position(|id| **id == finding.rule),
                "kind": if finding.severity == Severity::Info { "informational" } else { "fail" },
                "level": level(finding.severity),
                "message": { "text": message(report, language, finding) },
                "locations": locations,
                "partialFingerprints": { "findingId/v1": finding.id },
                "properties": {
                    "confidence": confidence(finding.confidence),
                    "section": finding.section,
                    "analyzer": finding.analyzer,
                },
            });
            if !finding.references.is_empty() {
                result["properties"]["tags"] = json!(finding.references);
            }
            result
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": report.tool.name,
                "version": report.tool.version,
                "informationUri": "https://github.com/atomsprout/analyze-anything",
                "rules": rules,
            }},
            "results": results,
            "properties": { "input": report.input.name, "inputSha256": report.input.sha256, "truncated": report.coverage.truncated },
        }],
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aa_core::{Artifact, Coverage, Evidence, Input, InputKind, RuleText, SCHEMA_VERSION, Section, Tool};

    use super::*;

    fn report() -> Report {
        let artifact = Artifact {
            path: "dir/a b#.bin".into(),
            parent: None,
            size: 4,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        };
        let high = Finding::new(Section::Secrets, "content", "content.secret", Confidence::Heuristic, Severity::Medium)
            .param("kind", "token")
            .reference("CWE-798")
            .evidence(Evidence::bytes(&artifact, 10, 20, "abcd**"))
            .seal();
        let info = Finding::new(Section::Structure, "structure", "structure.totals", Confidence::Derived, Severity::Info)
            .evidence(Evidence::whole(&artifact, 1))
            .seal();
        let text = RuleText {
            title_zh: "凭据".into(),
            title_en: "Credential".into(),
            text_zh: "发现 {kind}".into(),
            text_en: "Found a {kind}".into(),
        };
        Report {
            schema_version: SCHEMA_VERSION,
            tool: Tool { name: "analyze-anything".into(), version: "0.0.1".into() },
            input: Input { name: "dir".into(), kind: InputKind::Directory, sha256: None },
            summary: BTreeMap::new(),
            artifacts: vec![artifact],
            findings: vec![high, info],
            limitations: Vec::new(),
            coverage: Coverage::default(),
            rules: BTreeMap::from([("content.secret".to_string(), text)]),
        }
    }

    #[test]
    fn findings_become_results_with_locations() {
        let log = sarif(&report(), Language::En);
        assert_eq!(log["version"], "2.1.0");
        let run = &log["runs"][0];
        assert_eq!(run["tool"]["driver"]["rules"].as_array().map(Vec::len), Some(2));
        let secret = &run["results"][0];
        assert_eq!(secret["ruleId"], "content.secret");
        assert_eq!(secret["level"], "warning");
        assert_eq!(secret["kind"], "fail");
        assert_eq!(secret["message"]["text"], "Found a token");
        assert_eq!(secret["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "dir/a%20b%23.bin");
        assert_eq!(secret["locations"][0]["physicalLocation"]["region"], json!({ "byteOffset": 10, "byteLength": 20 }));
        assert_eq!(secret["properties"]["tags"], json!(["CWE-798"]));
        assert_eq!(secret["ruleIndex"], 0);
        let info = &run["results"][1];
        assert_eq!(info["kind"], "informational");
        assert_eq!(info["level"], "none");
        assert_eq!(info["message"]["text"], "structure.totals", "a rule without text falls back to its id");
    }

    #[test]
    fn language_selects_the_text() {
        assert_eq!(sarif(&report(), Language::Zh)["runs"][0]["results"][0]["message"]["text"], "发现 token");
    }
}
