//! What is sent to the model: a digest of the report, and nothing else.
//!
//! The digest holds the report's own words: each finding's title and text as the readable
//! reports print them, where it was found, how sure and how serious it is. Evidence values and
//! bytes of the analyzed files are not part of it. Findings get short names (`F1`, `F2`, …) that
//! the model cites; [`Digest::refs`] maps them back to finding ids.

use std::collections::BTreeMap;

use aa_core::{Report, Severity};
use serde_json::{Value, json};

use crate::Language;

/// Longest text of one finding that is sent, in characters.
const MAX_TEXT: usize = 600;
/// Most findings of one rule that are sent when they are neutral facts.
const MAX_INFO_PER_RULE: usize = 12;
const MAX_LIMITATIONS: usize = 40;
/// A summary fact whose JSON is longer than this is left out.
const MAX_FACT: usize = 2000;

pub struct Digest {
    /// The JSON text that is sent.
    pub text: String,
    /// Finding ids by position: `F1` is `refs[0]`.
    pub refs: Vec<String>,
    /// Findings in the report.
    pub total: usize,
}

fn word<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

fn clip(text: &str, most: usize) -> String {
    if text.chars().count() <= most {
        return text.to_string();
    }
    let mut clipped: String = text.chars().take(most).collect();
    clipped.push('…');
    clipped
}

/// The findings to send, most serious first, at most `most`.
fn choose(report: &Report, most: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..report.findings.len()).collect();
    order.sort_by_key(|&index| (std::cmp::Reverse(report.findings[index].severity), index));
    let mut per_rule: BTreeMap<&str, usize> = BTreeMap::new();
    let mut chosen = Vec::new();
    for index in order {
        let finding = &report.findings[index];
        if finding.severity == Severity::Info {
            let seen = per_rule.entry(finding.rule.as_str()).or_default();
            *seen += 1;
            if *seen > MAX_INFO_PER_RULE {
                continue;
            }
        }
        chosen.push(index);
        if chosen.len() == most {
            break;
        }
    }
    chosen
}

pub fn digest(report: &Report, language: Language, most: usize) -> Digest {
    let words = |code: &str, params: &BTreeMap<String, Value>| match (report.rules.get(code), language) {
        (Some(rule), Language::Zh) => (rule.title_zh.clone(), aa_core::fill(&rule.text_zh, params)),
        (Some(rule), Language::En) => (rule.title_en.clone(), aa_core::fill(&rule.text_en, params)),
        (None, _) => (code.to_string(), String::new()),
    };
    let chosen = choose(report, most);
    let mut refs = Vec::with_capacity(chosen.len());
    let mut findings = Vec::with_capacity(chosen.len());
    for index in chosen {
        let finding = &report.findings[index];
        let (title, text) = words(&finding.rule, &finding.params);
        refs.push(finding.id.clone());
        let mut entry = json!({
            "ref": format!("F{}", refs.len()),
            "section": word(&finding.section),
            "severity": word(&finding.severity),
            "confidence": word(&finding.confidence),
            "title": title,
            "text": clip(&text, MAX_TEXT),
        });
        if let Some(evidence) = finding.evidence.first() {
            entry["file"] = Value::String(evidence.artifact.clone());
        }
        if !finding.references.is_empty() {
            entry["references"] = json!(finding.references);
        }
        findings.push(entry);
    }
    let mut by_severity: BTreeMap<String, usize> = BTreeMap::new();
    for finding in &report.findings {
        let name = word(&finding.severity).as_str().unwrap_or_default().to_string();
        *by_severity.entry(name).or_default() += 1;
    }
    let none = BTreeMap::new();
    let limitations: Vec<Value> = report
        .limitations
        .iter()
        .take(MAX_LIMITATIONS)
        .map(|limitation| json!({ "what": words(&limitation.code, &none).0, "file": limitation.artifact }))
        .collect();
    let facts: BTreeMap<&String, &Value> = report.summary.iter().filter(|(_, value)| value.to_string().len() <= MAX_FACT).collect();
    let all = json!({
        "input": { "name": report.input.name, "kind": word(&report.input.kind) },
        "facts": facts,
        "coverage": word(&report.coverage),
        "limitations": limitations,
        "limitations_total": report.limitations.len(),
        "findings_total": report.findings.len(),
        "findings_by_severity": by_severity,
        "findings": findings,
    });
    Digest { text: serde_json::to_string_pretty(&all).unwrap_or_default(), refs, total: report.findings.len() }
}
