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

/// Base64 characters that must follow a marker for it to count as a key. The shortest real key
/// (an Ed25519 key in PKCS#8) encodes to 64 characters.
const KEY_BODY_MIN: usize = 60;

/// True when base64 data follows a key marker: line breaks (real, or written as `\n` in a
/// string literal) and PEM header lines may come in between.
fn key_material_follows(rest: &[u8]) -> bool {
    let window = &rest[..rest.len().min(4096)];
    let mut run = 0usize;
    let mut index = 0;
    while index < window.len() {
        let byte = window[index];
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' => run += 1,
            b'\r' | b'\n' | b' ' | b'\t' => {}
            // `\n` or `\r` spelled out, as keys embedded in source code and JSON are.
            b'\\' if matches!(window.get(index + 1), Some(b'n' | b'r')) => index += 1,
            // A header line such as `Proc-Type: 4,ENCRYPTED` sits between marker and data.
            b':' | b',' | b'-' if run < KEY_BODY_MIN && !window[index..].starts_with(b"-----") => run = 0,
            _ => break,
        }
        if run >= KEY_BODY_MIN {
            return true;
        }
        index += 1;
    }
    false
}

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
        // A program that reads or writes key files holds the marker as a plain string. Only a
        // marker with encoded data after it is a key; whether that key is usable is not checked.
        let found = if key_material_follows(&bytes[hit.end()..]) {
            Finding::new(Section::Secrets, "content", "content.private-key", Confidence::Heuristic, Severity::High).reference("CWE-321")
        } else {
            Finding::new(Section::Secrets, "content", "content.private-key-marker", Confidence::Heuristic, Severity::Info)
        };
        out.finding(found.param("kind", kind).evidence(Evidence::bytes(file, hit.start() as u64, hit.len() as u64, marker)));
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
        let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nVJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDu";
        let found = run(&format!("x\n-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----BEGIN PUBLIC KEY-----"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "content.private-key");
        assert_eq!(found[0].severity, Severity::High);
        assert_eq!(found[0].params["kind"], "RSA PRIVATE KEY");
        // Written into source code as one string, and with PEM headers before the data.
        let escaped = body.replace('\n', "\\n");
        assert_eq!(run(&format!("key = \"-----BEGIN PRIVATE KEY-----\\n{escaped}\"; "))[0].rule, "content.private-key");
        let headed = format!("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{body}");
        assert_eq!(run(&headed)[0].rule, "content.private-key");
    }

    #[test]
    fn marker_without_key_material_is_only_a_marker() {
        // What a program that parses key files contains: the markers, one after the other.
        let found = run("-----BEGIN OPENSSH PRIVATE KEY-----\0-----END OPENSSH PRIVATE KEY-----\0openssh-key-v1");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule, "content.private-key-marker");
        assert_eq!(found[0].severity, Severity::Info);
        assert_eq!(run("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")[0].rule, "content.private-key-marker");
    }

    #[test]
    fn short_values_are_fully_masked() {
        assert_eq!(redact("abcdefgh"), "********");
        assert_eq!(redact("abcdefghij"), "abcd****ij");
    }
}
