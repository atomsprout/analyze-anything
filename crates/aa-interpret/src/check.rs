//! Reading the model's answer and keeping only what it can back up.
//!
//! A statement stays when it cites at least one finding and every finding it cites was among
//! those sent. Anything else is dropped and counted: the interpretation may say less than the
//! model did, never more than the report supports.

use serde::Deserialize;

use crate::Statement;

#[derive(Debug, Default, Deserialize)]
pub struct Raw {
    #[serde(default)]
    pub summary: Vec<RawStatement>,
    #[serde(default)]
    pub notable: Vec<RawStatement>,
    #[serde(default)]
    pub next_steps: Vec<RawStatement>,
}

#[derive(Debug, Deserialize)]
pub struct RawStatement {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub cites: Vec<String>,
}

/// The JSON object in the model's answer. Models that were not held to a schema may wrap it in
/// a code fence, put their reasoning before it, or add a remark after it.
pub fn parse(answer: &str) -> Result<Raw, String> {
    let after_reasoning = answer.rfind("</think>").map_or(answer, |end| &answer[end + "</think>".len()..]);
    let (Some(start), Some(end)) = (after_reasoning.find('{'), after_reasoning.rfind('}')) else {
        return Err("the model's answer holds no JSON object".into());
    };
    if end < start {
        return Err("the model's answer holds no JSON object".into());
    }
    serde_json::from_str(&after_reasoning[start..=end])
        .map_err(|error| format!("the model's answer is not the JSON that was asked for: {error}"))
}

/// The finding a citation such as `F12` names: its position in `refs`.
fn position(cite: &str, sent: usize) -> Option<usize> {
    let name = cite.trim().trim_matches(|c| c == '[' || c == ']');
    let number: usize = name.strip_prefix('F').or_else(|| name.strip_prefix('f'))?.parse().ok()?;
    (1..=sent).contains(&number).then(|| number - 1)
}

/// Keeps the statements whose citations all hold, with finding ids in place of the short names.
/// Returns them and how many were dropped.
pub fn keep(statements: Vec<RawStatement>, refs: &[String]) -> (Vec<Statement>, usize) {
    let mut kept = Vec::new();
    let mut dropped = 0;
    for statement in statements {
        let text = statement.text.trim();
        let positions: Option<Vec<usize>> = statement.cites.iter().map(|cite| position(cite, refs.len())).collect();
        match positions {
            Some(mut positions) if !positions.is_empty() && !text.is_empty() => {
                positions.sort_unstable();
                positions.dedup();
                kept.push(Statement { text: text.to_string(), findings: positions.into_iter().map(|at| refs[at].clone()).collect() });
            }
            _ => dropped += 1,
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str, cites: &[&str]) -> RawStatement {
        RawStatement { text: text.into(), cites: cites.iter().map(|c| c.to_string()).collect() }
    }

    #[test]
    fn an_answer_in_a_fence_after_reasoning_is_read() {
        let answer = "<think>{not json}</think>\nHere you go:\n```json\n{\"summary\":[{\"text\":\"a\",\"cites\":[\"F1\"]}]}\n```\n";
        let parsed = parse(answer).expect("parses");
        assert_eq!(parsed.summary.len(), 1);
        assert!(parsed.notable.is_empty());
    }

    #[test]
    fn an_answer_without_json_is_an_error() {
        assert!(parse("I cannot help with that.").is_err());
        assert!(parse("} {").is_err());
        assert!(parse("{\"summary\": 3}").is_err());
    }

    #[test]
    fn only_statements_that_cite_sent_findings_stay() {
        let refs = vec!["aaa".to_string(), "bbb".to_string()];
        let statements = vec![
            raw("backed", &["F2", "[f1]", "F2"]),
            raw("cites nothing", &[]),
            raw("cites a finding that was not sent", &["F1", "F3"]),
            raw("cites something else", &["CWE-798"]),
            raw("  ", &["F1"]),
        ];
        let (kept, dropped) = keep(statements, &refs);
        assert_eq!(kept, vec![Statement { text: "backed".into(), findings: vec!["aaa".into(), "bbb".into()] }]);
        assert_eq!(dropped, 4);
    }
}
