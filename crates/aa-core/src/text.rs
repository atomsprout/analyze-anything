//! Credential redaction shared by readers that publish structured input text.

use regex::Regex;
use std::sync::LazyLock;

static REDACTORS: LazyLock<Result<Vec<(Regex, &'static str)>, regex::Error>> = LazyLock::new(|| {
    [
        (r"\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{36,255}|xox[abprs]-[A-Za-z0-9-]{10,200}|[sr]k_live_[0-9A-Za-z]{20,200}|SK[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,255})\b", "[redacted]"),
        (r"(?s)-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----.*", "[redacted private key material]"),
        (r"(?i)\b(Bearer|Basic)\s+[a-z0-9+/_.=-]+", "$1 [redacted]"),
        (r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@", "$1[redacted]@"),
        (r#"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*|\s+)("[^"]*"|'[^']*'|[^\s&]+)"#, "$1$2[redacted]"),
    ].into_iter().map(|(pattern, replacement)| Regex::new(pattern).map(|pattern| (pattern, replacement))).collect()
});

/// Redacts recognizable token forms, URL userinfo and credential assignments.
/// This does not identify every possible secret. A pattern initialization error fails closed.
pub fn redact_sensitive_text(text: &str) -> Result<String, &'static str> {
    let rules = REDACTORS.as_ref().map_err(|_| "credential redaction patterns could not be initialized")?;
    let mut text = text.to_string();
    for (pattern, replacement) in rules {
        text = pattern.replace_all(&text, *replacement).into_owned();
    }
    Ok(text)
}

/// A conservative name match for structured fields whose values must be hidden in full.
pub fn is_sensitive_field_name(name: &str) -> bool {
    let normalized: String = name.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect();
    ["password", "passwd", "pwd", "token", "secret", "apikey", "authorization"].iter().any(|suffix| normalized.ends_with(suffix))
}

/// Hides the whole value of a recognizable credential field, including spaces and newlines.
pub fn redact_named_value(name: &str, value: &str) -> Result<String, &'static str> {
    if is_sensitive_field_name(name) { Ok("[redacted]".into()) } else { redact_sensitive_text(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizable_credentials_are_removed_and_declarations_remain_data() {
        let token = format!("ghp_{}", "a".repeat(36));
        let key = format!("sk-proj-{}", "b".repeat(32));
        let input = format!(
            "{token} {key} https://user:fixture-password@example.invalid/?token=fixture-token&ok=1 --password 'fixture argument' Bearer fixture-bearer"
        );
        let output = redact_sensitive_text(&input).expect("built-in patterns compile");
        for value in [&token, &key, "fixture-password", "fixture-token", "fixture argument", "fixture-bearer"] {
            assert!(!output.contains(value), "{output}");
        }
        assert!(output.contains("example.invalid"));
        assert!(output.contains("&ok=1"));
        assert_eq!(redact_sensitive_text(r"%SystemRoot%\file.exe").expect("plain data"), r"%SystemRoot%\file.exe");
        assert_eq!(
            redact_sensitive_text("-----BEGIN PRIVATE KEY-----\nfixture material\nrest").expect("key marker"),
            "[redacted private key material]"
        );
    }

    #[test]
    fn named_credentials_hide_the_entire_value() {
        for name in ["Password", "service-password", "ACCESS_TOKEN", "ClientSecret", "api.key", "Authorization"] {
            assert_eq!(redact_named_value(name, "fixture secret with spaces\nand a second line").expect("named redaction"), "[redacted]");
        }
        assert_eq!(redact_named_value("TokensEnabled", "true").expect("ordinary value"), "true");
    }
}
