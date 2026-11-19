//! Reading the model's answer and keeping only what it can back up.
//!
//! A statement stays when it cites at least one finding and every finding it cites exists in
//! the report. Anything else is dropped and counted: the interpretation may say less than the
//! model did, never more than the report supports.

use serde::Deserialize;

use crate::Statement;
use crate::tools::Tools;

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

/// The JSON object in the model's answer. A model may wrap it in a code fence, put its
/// reasoning before it, or add a remark after it.
pub fn parse(answer: &str) -> Result<Raw, String> {
    let after_reasoning = answer.rfind("</think>").map_or(answer, |end| &answer[end + "</think>".len()..]);
    let (Some(start), Some(end)) = (after_reasoning.find('{'), after_reasoning.rfind('}')) else {
        return Err("the answer holds no JSON object".into());
    };
    if end < start {
        return Err("the answer holds no JSON object".into());
    }
    serde_json::from_str(&after_reasoning[start..=end])
        .map_err(|error| format!("the answer is not the JSON object that was asked for: {error}"))
}

/// Keeps the statements whose citations all hold, with full finding ids in place of what the
/// model wrote. Returns them and how many were dropped.
pub fn keep(statements: Vec<RawStatement>, tools: &Tools) -> (Vec<Statement>, usize) {
    let mut kept = Vec::new();
    let mut dropped = 0;
    for statement in statements {
        let text = statement.text.trim();
        let findings: Option<Vec<String>> = statement.cites.iter().map(|cite| tools.find(cite).map(|finding| finding.id.clone())).collect();
        match findings {
            Some(mut findings) if !findings.is_empty() && !text.is_empty() => {
                let mut seen = std::collections::BTreeSet::new();
                findings.retain(|id| seen.insert(id.clone()));
                kept.push(Statement { text: text.to_string(), findings });
            }
            _ => dropped += 1,
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_in_a_fence_after_reasoning_is_read() {
        let answer = "<think>{not json}</think>\nHere you go:\n```json\n{\"summary\":[{\"text\":\"a\",\"cites\":[\"0123456789\"]}]}\n```\n";
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
}
