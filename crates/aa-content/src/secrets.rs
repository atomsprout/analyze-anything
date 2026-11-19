//! Finds strings shaped like credentials. Every hit is a pattern match, reported as heuristic,
//! and the value is redacted: a report must not become a second copy of the secret.

use std::sync::LazyLock;

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use regex::bytes::Regex;

/// Hits reported per pattern per file.
const PER_PATTERN: usize = 20;

struct Pattern {
    kind: &'static str,
    regex: Regex,
}

fn pattern(kind: &'static str, regex: &str) -> Pattern {
    // The patterns are constants; a failure here is a programming error caught by the tests.
    Pattern { kind, regex: Regex::new(&format!("(?-u){regex}")).unwrap_or_else(|error| panic!("invalid built-in pattern: {error}")) }
}

/// Token formats with a fixed, distinctive prefix. `\b` keeps a hit from starting inside a longer word.
static TOKENS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    vec![
        pattern("AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        pattern("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        pattern("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
        pattern("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,200}\b"),
        pattern("Stripe live secret key", r"\b[sr]k_live_[0-9A-Za-z]{20,200}\b"),
        pattern("Twilio API key", r"\bSK[0-9a-f]{32}\b"),
        pattern("SendGrid API key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
    ]
});

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?-u)-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----")
        .unwrap_or_else(|error| panic!("invalid built-in pattern: {error}"))
});

/// Keeps the first four and last two characters, enough to find the value again, not to use it.
fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 2..].iter().collect();
    format!("{head}{}{tail}", "*".repeat(chars.len() - 6))
}

pub fn find(file: &Artifact, bytes: &[u8], out: &mut Output) {
    for pattern in TOKENS.iter() {
        for hit in pattern.regex.find_iter(bytes).take(PER_PATTERN) {
            let redacted = redact(&String::from_utf8_lossy(hit.as_bytes()));
            out.finding(
                Finding::new(Section::Secrets, "content", "content.secret", Confidence::Heuristic, Severity::Medium)
                    .param("kind", pattern.kind)
                    .param("redacted", redacted.clone())
                    .reference("CWE-798")
                    .evidence(Evidence::bytes(file, hit.start() as u64, hit.len() as u64, redacted)),
            );
        }
    }
    for hit in PRIVATE_KEY.find_iter(bytes).take(PER_PATTERN) {
        let marker = String::from_utf8_lossy(hit.as_bytes()).into_owned();
        let kind = marker.trim_matches('-').trim_start_matches("BEGIN ").to_string();
        out.finding(
            // The marker is read as written; whether a usable key follows is not checked.
            Finding::new(Section::Secrets, "content", "content.private-key", Confidence::Heuristic, Severity::High)
                .param("kind", kind)
                .reference("CWE-321")
                .evidence(Evidence::bytes(file, hit.start() as u64, hit.len() as u64, marker)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> Artifact {
        Artifact {
            path: "config.json".into(),
            parent: None,
            size: 0,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        }
    }

    fn run(text: &str) -> Vec<Finding> {
        let mut out = Output::default();
        find(&file(), text.as_bytes(), &mut out);
        out.findings
    }

    #[test]
    fn token_is_found_and_never_shown_in_full() {
        // The documented example key from AWS's own guides.
        let key = "AKIAIOSFODNN7EXAMPLE";
        let found = run(&format!("{{\"id\": \"{key}\"}}"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].params["kind"], "AWS access key ID");
        assert_eq!(found[0].params["redacted"], "AKIA**************LE");
        assert!(!serde_json::to_string(&found).unwrap_or_default().contains(key));
        assert_eq!(found[0].evidence[0].location, aa_core::Location::Bytes { offset: 8, length: 20 });
    }

    #[test]
    fn prefix_inside_a_longer_word_is_not_a_token() {
        assert!(run("XAKIAIOSFODNN7EXAMPLEX and sk_live_short").is_empty());
    }

    #[test]
    fn private_key_marker_is_found() {
        let found = run("x\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----BEGIN PUBLIC KEY-----");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "content.private-key");
        assert_eq!(found[0].params["kind"], "RSA PRIVATE KEY");
    }

    #[test]
    fn short_values_are_fully_masked() {
        assert_eq!(redact("abcdefgh"), "********");
        assert_eq!(redact("abcdefghij"), "abcd****ij");
    }
}
