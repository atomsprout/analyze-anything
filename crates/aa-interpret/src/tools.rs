//! What a model may look up in a report: read-only questions with bounded answers.
//!
//! The same questions are offered whoever asks: the model this program talks to itself, or an
//! outside agent over the tool server ([`crate::mcp`]). Every answer comes from the report; the
//! analyzed files are never opened here.

use std::collections::BTreeMap;

use aa_core::{Finding, Location, Report, Severity};
use serde_json::{Value, json};

use crate::Language;

/// Longest text of one finding in a list, in characters.
const MAX_TEXT: usize = 600;
/// Longest evidence value shown, in characters.
const MAX_VALUE: usize = 400;
const MAX_EVIDENCE: usize = 20;
const MAX_LIST: usize = 50;
const MAX_FILES: usize = 100;
/// Findings above "info" shown in the opening brief.
const MAX_BRIEF: usize = 150;
/// A summary fact whose JSON is longer than this is left out of the brief.
const MAX_FACT: usize = 2000;
/// Fewest characters of a finding id that are shown.
const MIN_ID: usize = 10;

/// One tool as a model is told about it.
pub struct Spec {
    pub name: &'static str,
    pub description: &'static str,
    /// JSON Schema of the arguments.
    pub schema: Value,
}

pub fn specs() -> Vec<Spec> {
    vec![
        Spec {
            name: "list_findings",
            description: "List findings of the report, most serious first. Filter by section, by severity, or by words that appear in a finding's title, text or file path. Returns at most 50 at a time; use `offset` for more.",
            schema: json!({
                "type": "object",
                "properties": {
                    "section": { "type": "string", "enum": ["overview", "identity", "provenance", "structure", "composition", "capabilities", "hardening", "network", "secrets", "privacy", "code", "anomalies"] },
                    "severity": { "type": "string", "enum": ["info", "low", "medium", "high"] },
                    "query": { "type": "string", "description": "Words to look for, case-insensitive" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                },
                "additionalProperties": false,
            }),
        },
        Spec {
            name: "get_finding",
            description: "Show one finding in full: its text, the values it was built from, and the evidence behind it (which file, where in it, what was read there).",
            schema: json!({
                "type": "object",
                "properties": { "id": { "type": "string", "description": "The finding's id, or its first characters as the lists show them" } },
                "required": ["id"],
                "additionalProperties": false,
            }),
        },
        Spec {
            name: "list_files",
            description: "List files of the analyzed input, files unpacked from containers included, with size and type. Filter by words in the path. Returns at most 100 at a time; use `offset` for more.",
            schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Words to look for in the path, case-insensitive" },
                    "offset": { "type": "integer" },
                    "limit": { "type": "integer" },
                },
                "additionalProperties": false,
            }),
        },
    ]
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

/// A number argument, or `default` when it is absent or not a whole number.
fn number(input: &Value, name: &str, default: usize) -> usize {
    input.get(name).and_then(Value::as_u64).map_or(default, |n| usize::try_from(n).unwrap_or(usize::MAX))
}

/// A report, ready to be asked about.
pub struct Tools<'a> {
    report: &'a Report,
    language: Language,
    /// How many characters of a finding id are shown: enough that no two look alike.
    shown: usize,
    /// Findings by position, most serious first.
    order: Vec<usize>,
}

impl<'a> Tools<'a> {
    pub fn new(report: &'a Report, language: Language) -> Self {
        let mut shown = MIN_ID;
        loop {
            let mut seen = std::collections::BTreeSet::new();
            if shown >= 64 || report.findings.iter().all(|finding| seen.insert(finding.id.chars().take(shown).collect::<String>())) {
                break;
            }
            shown += 2;
        }
        let mut order: Vec<usize> = (0..report.findings.len()).collect();
        order.sort_by_key(|&index| (std::cmp::Reverse(report.findings[index].severity), index));
        Tools { report, language, shown, order }
    }

    fn words(&self, code: &str, params: &BTreeMap<String, Value>) -> (String, String) {
        match (self.report.rules.get(code), self.language) {
            (Some(rule), Language::Zh) => (rule.title_zh.clone(), aa_core::fill(&rule.text_zh, params)),
            (Some(rule), Language::En) => (rule.title_en.clone(), aa_core::fill(&rule.text_en, params)),
            (None, _) => (code.to_string(), String::new()),
        }
    }

    fn short(&self, finding: &Finding) -> String {
        finding.id.chars().take(self.shown).collect()
    }

    /// The finding whose id starts with `id`, when exactly one does and `id` is long enough to
    /// be a deliberate reference.
    pub fn find(&self, id: &str) -> Option<&'a Finding> {
        let id = id.trim().trim_matches(|c| c == '[' || c == ']' || c == '`').to_ascii_lowercase();
        if id.len() < 8 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut matches = self.report.findings.iter().filter(|finding| finding.id.starts_with(&id));
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }

    fn row(&self, finding: &Finding) -> Value {
        let (title, text) = self.words(&finding.rule, &finding.params);
        let mut row = json!({
            "id": self.short(finding),
            "section": word(&finding.section),
            "severity": word(&finding.severity),
            "confidence": word(&finding.confidence),
            "title": title,
            "text": clip(&text, MAX_TEXT),
        });
        if let Some(evidence) = finding.evidence.first() {
            row["file"] = Value::String(evidence.artifact.clone());
        }
        row
    }

    /// What the model is shown first: what the input is, how much was examined, how many
    /// findings there are of each kind, and every finding above "info".
    pub fn brief(&self) -> Value {
        let report = self.report;
        let mut counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
        for finding in &report.findings {
            let section = word(&finding.section).as_str().unwrap_or_default().to_string();
            let severity = word(&finding.severity).as_str().unwrap_or_default().to_string();
            *counts.entry(section).or_default().entry(severity).or_default() += 1;
        }
        let serious: Vec<&Finding> =
            self.order.iter().map(|&index| &report.findings[index]).filter(|finding| finding.severity > Severity::Info).collect();
        let none = BTreeMap::new();
        let limitations: Vec<Value> = report
            .limitations
            .iter()
            .take(40)
            .map(|limitation| json!({ "what": self.words(&limitation.code, &none).0, "file": limitation.artifact }))
            .collect();
        let facts: BTreeMap<&String, &Value> = report.summary.iter().filter(|(_, value)| value.to_string().len() <= MAX_FACT).collect();
        json!({
            "input": { "name": report.input.name, "kind": word(&report.input.kind) },
            "facts": facts,
            "coverage": word(&report.coverage),
            "limitations": limitations,
            "limitations_total": report.limitations.len(),
            "files_total": report.artifacts.len(),
            "findings_total": report.findings.len(),
            "findings_by_section_and_severity": counts,
            "findings_above_info": serious.iter().take(MAX_BRIEF).map(|finding| self.row(finding)).collect::<Vec<_>>(),
            "findings_above_info_total": serious.len(),
        })
    }

    /// Answers one question. An error is text for the model to read and correct itself by.
    pub fn call(&self, name: &str, input: &Value) -> Result<Value, String> {
        match name {
            "list_findings" => Ok(self.list_findings(input)),
            "get_finding" => self.get_finding(input),
            "list_files" => Ok(self.list_files(input)),
            other => Err(format!("there is no tool named {other}; the tools are list_findings, get_finding and list_files")),
        }
    }

    fn list_findings(&self, input: &Value) -> Value {
        let section = input.get("section").and_then(Value::as_str);
        let severity = input.get("severity").and_then(Value::as_str);
        let query = input.get("query").and_then(Value::as_str).map(str::to_lowercase).filter(|query| !query.trim().is_empty());
        let matching: Vec<Value> = self
            .order
            .iter()
            .map(|&index| &self.report.findings[index])
            .filter(|finding| section.is_none_or(|section| word(&finding.section).as_str() == Some(section)))
            .filter(|finding| severity.is_none_or(|severity| word(&finding.severity).as_str() == Some(severity)))
            .map(|finding| self.row(finding))
            .filter(|row| match &query {
                // Every word must appear somewhere in what the row shows.
                Some(query) => {
                    let shown = row.to_string().to_lowercase();
                    query.split_whitespace().all(|word| shown.contains(word))
                }
                None => true,
            })
            .collect();
        let offset = number(input, "offset", 0);
        let limit = number(input, "limit", 30).clamp(1, MAX_LIST);
        let page: Vec<&Value> = matching.iter().skip(offset).take(limit).collect();
        json!({ "matching": matching.len(), "offset": offset, "findings": page })
    }

    fn get_finding(&self, input: &Value) -> Result<Value, String> {
        let id = input.get("id").and_then(Value::as_str).ok_or("get_finding needs `id`")?;
        let finding = self.find(id).ok_or_else(|| format!("no finding has the id {id}; take ids from list_findings"))?;
        let (title, text) = self.words(&finding.rule, &finding.params);
        let evidence: Vec<Value> = finding
            .evidence
            .iter()
            .take(MAX_EVIDENCE)
            .map(|evidence| {
                let place = match &evidence.location {
                    Location::Bytes { offset, length } => format!("bytes {offset}..{}", offset.saturating_add(*length)),
                    Location::Field(field) => format!("field {field}"),
                    Location::Whole => "the whole file".to_string(),
                };
                let value = match &evidence.value {
                    Value::String(text) => clip(text, MAX_VALUE),
                    other => clip(&other.to_string(), MAX_VALUE),
                };
                json!({ "file": evidence.artifact, "where": place, "value": value })
            })
            .collect();
        let params: BTreeMap<&String, String> =
            finding.params.iter().map(|(name, value)| (name, clip(&value.to_string(), MAX_VALUE))).collect();
        Ok(json!({
            "id": self.short(finding),
            "rule": finding.rule,
            "section": word(&finding.section),
            "severity": word(&finding.severity),
            "confidence": word(&finding.confidence),
            "title": title,
            "text": text,
            "values": params,
            "references": finding.references,
            "evidence": evidence,
            "evidence_total": finding.evidence.len(),
        }))
    }

    fn list_files(&self, input: &Value) -> Value {
        let query = input.get("query").and_then(Value::as_str).map(str::to_lowercase).filter(|query| !query.trim().is_empty());
        let matching: Vec<&aa_core::Artifact> = self
            .report
            .artifacts
            .iter()
            .filter(|artifact| match &query {
                Some(query) => {
                    let path = artifact.path.to_lowercase();
                    query.split_whitespace().all(|word| path.contains(word))
                }
                None => true,
            })
            .collect();
        let offset = number(input, "offset", 0);
        let limit = number(input, "limit", 50).clamp(1, MAX_FILES);
        let page: Vec<Value> = matching
            .iter()
            .skip(offset)
            .take(limit)
            .map(|artifact| json!({ "path": artifact.path, "size": artifact.size, "type": artifact.kind.as_deref().unwrap_or(artifact.mime()) }))
            .collect();
        json!({ "matching": matching.len(), "offset": offset, "files": page })
    }
}
