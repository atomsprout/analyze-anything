//! Shortcut declarations are data: no shell object or URL is activated by this reader.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

const MAX_TEXT: usize = 1024 * 1024;
const MAX_FIELDS: usize = 256;

use aa_core::text::redact_sensitive_text as redact;

fn decode(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.len() > MAX_TEXT {
        return Err("shortcut text exceeds the 1 MiB limit");
    }
    if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]).or_else(|| bytes.strip_prefix(&[0xfe, 0xff])) {
        if body.len() % 2 != 0 {
            return Err("truncated UTF-16 shortcut text");
        }
        let little = bytes.starts_with(&[0xff, 0xfe]);
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|b| if little { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
            .collect();
        String::from_utf16(&units).map_err(|_| "invalid UTF-16 shortcut text")
    } else {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        std::str::from_utf8(bytes).map(str::to_string).map_err(|_| "unknown shortcut text encoding; no host code page is assumed")
    }
}

#[derive(Debug)]
struct UrlShortcut {
    fields: Vec<(String, String)>,
    ignored: usize,
    duplicate_keys: bool,
}

fn parse_url(bytes: &[u8]) -> Result<UrlShortcut, &'static str> {
    let text = decode(bytes)?;
    let mut shortcut = UrlShortcut { fields: Vec::new(), ignored: 0, duplicate_keys: false };
    let mut inside = false;
    let mut seen = std::collections::BTreeSet::new();
    let mut has_target = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            inside = line.eq_ignore_ascii_case("[InternetShortcut]");
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            shortcut.ignored += 1;
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if !inside || !matches!(key.as_str(), "url" | "iconfile" | "iconindex" | "workingdirectory" | "hotkey" | "showcommand") {
            shortcut.ignored += 1;
            continue;
        }
        if shortcut.fields.len() >= MAX_FIELDS {
            return Err("shortcut has more than 256 supported fields");
        }
        shortcut.duplicate_keys |= !seen.insert(key.clone());
        has_target |= key == "url" && !value.trim().is_empty();
        shortcut.fields.push((key, redact(value.trim())?));
    }
    if !has_target {
        return Err("the InternetShortcut section has no nonempty URL declaration");
    }
    Ok(shortcut)
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("url") {
        return;
    }
    let shortcut = match parse_url(bytes) {
        Ok(shortcut) => shortcut,
        Err(reason) => {
            out.limitation("windows.shortcut-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    out.kind(file, "internet-shortcut");
    out.fact(file, "windows.internet-shortcut", json!({"fields": shortcut.fields, "ignored_fields": shortcut.ignored, "duplicate_keys": shortcut.duplicate_keys, "target_resolved": false}));
    let mut finding = Finding::new(Section::Capabilities, "windows", "windows.internet-shortcut", Confidence::Verified, Severity::Info)
        .param("fields", shortcut.fields.len());
    for (key, value) in shortcut.fields.iter().take(12) {
        finding = finding.evidence(Evidence::field(file, format!("InternetShortcut/{key}"), value.as_str()));
    }
    out.finding(finding);
    out.limitation("windows.shortcut-target-unresolved", Some(file), None);
    if shortcut.ignored > 0 || shortcut.duplicate_keys {
        out.limitation(
            "windows.shortcut-partial",
            Some(file),
            Some(format!("{} fields or lines not interpreted; duplicate supported keys: {}", shortcut.ignored, shortcut.duplicate_keys)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_declarations_keep_duplicates_and_never_expand_environment_references() {
        let parsed = parse_url(b"[InternetShortcut]\nURL=https://example.invalid/a\nURL=file:///%SystemRoot%/file\nIconFile=\\\\server\\share\\icon.ico\nCustom=unknown\n").expect("URL declarations");
        assert!(parsed.duplicate_keys);
        assert_eq!(parsed.ignored, 1);
        assert_eq!(parsed.fields[1].1, "file:///%SystemRoot%/file");
        assert_eq!(parsed.fields[2].1, r"\\server\share\icon.ico");
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain("[InternetShortcut]\nURL=https://example.invalid/中文".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert!(parse_url(&utf16).expect("UTF-16 declaration").fields[0].1.ends_with("中文"));
    }

    #[test]
    fn known_credentials_are_redacted_before_facts_and_evidence() {
        let text = redact(
            "https://user:private-password@example.invalid/?token=private-token&ok=1 --password 'private argument' Bearer private-bearer",
        )
        .expect("redaction");
        for secret in ["private-password", "private-token", "private argument", "private-bearer"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("example.invalid"));
    }

    #[test]
    fn malformed_encoding_missing_targets_and_large_field_counts_are_limits() {
        for bytes in [b"".as_slice(), b"URL=x", b"[InternetShortcut]\nURL=", &[0xff, 0xfe, 0x41], &[0x80]] {
            assert!(parse_url(bytes).is_err());
        }
        assert!(parse_url(&vec![b'a'; MAX_TEXT + 1]).is_err());
        let fields = format!("[InternetShortcut]\n{}", "URL=https://example.invalid/\n".repeat(MAX_FIELDS + 1));
        assert!(parse_url(fields.as_bytes()).is_err());
    }
}
