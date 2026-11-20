//! Reads REG declarations only. No registry handle, importer or environment is used.

use std::collections::BTreeMap;

use aa_core::plugin::Output;
use aa_core::text::{is_sensitive_field_name, redact_named_value, redact_sensitive_text};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::{Value, json};

use crate::installer::{self, RegistryWrite, Tag};

const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_LINE: usize = 128 * 1024;
// A selected key is repeated in every value record; bound that output amplification as well.
const MAX_KEY: usize = 4096;
const MAX_ISSUES: usize = 64;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Serialize)]
struct Entry {
    operation: &'static str,
    key: String,
    name: Option<String>,
    value_type: Option<u32>,
    value: Option<Value>,
    line: usize,
    tags: Vec<&'static str>,
}

#[derive(Debug, Default)]
struct Registry {
    version: &'static str,
    entries: Vec<Entry>,
    issues: Vec<(usize, &'static str)>,
    issue_count: usize,
    truncated: bool,
}

impl Registry {
    fn issue(&mut self, line: usize, reason: &'static str) {
        self.issue_count += 1;
        if self.issues.len() < MAX_ISSUES {
            self.issues.push((line, reason));
        }
    }
}

fn quoted(text: &str) -> Result<(String, &str)> {
    let body = text.strip_prefix('"').ok_or("expected a quoted registry string")?;
    let mut value = String::new();
    let mut escaped = false;
    for (index, ch) in body.char_indices() {
        if escaped {
            if !matches!(ch, '\\' | '"') {
                return Err("unsupported escape in registry string");
            }
            value.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Ok((value, &body[index + 1..]));
        } else {
            value.push(ch);
        }
    }
    Err("unterminated registry string")
}

fn hex_bytes(text: &str) -> Result<Vec<u8>> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|part| {
            let part = part.trim();
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid registry hex byte");
            }
            u8::from_str_radix(part, 16).map_err(|_| "invalid registry hex byte")
        })
        .collect()
}

fn encoded_string(bytes: &[u8], legacy: bool) -> Result<String> {
    if legacy {
        if !bytes.is_ascii() {
            return Err("non-ASCII REGEDIT4 data has no established code page");
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| "invalid legacy registry string")
    } else {
        if !bytes.len().is_multiple_of(2) {
            return Err("odd UTF-16 registry value length");
        }
        let units: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        String::from_utf16(&units).map_err(|_| "invalid UTF-16 registry value")
    }
}

fn value(text: &str, legacy: bool) -> Result<(u32, Value, bool)> {
    if text.starts_with('"') {
        let (value, rest) = quoted(text)?;
        if !rest.trim().is_empty() {
            return Err("trailing text after a registry string");
        }
        return Ok((1, Value::String(value), false));
    }
    let (kind, body) = text.split_once(':').ok_or("unsupported registry value syntax")?;
    if kind.eq_ignore_ascii_case("dword") {
        if body.len() != 8 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("DWORD declaration does not contain eight hexadecimal digits");
        }
        return Ok((4, json!(u32::from_str_radix(body, 16).map_err(|_| "invalid DWORD")?), false));
    }
    let lower = kind.to_ascii_lowercase();
    let kind = if lower == "hex" {
        3
    } else {
        let digits = lower.strip_prefix("hex(").and_then(|s| s.strip_suffix(')')).ok_or("unsupported registry value syntax")?;
        if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid registry value type");
        }
        u32::from_str_radix(digits, 16).map_err(|_| "invalid registry value type")?
    };
    let bytes = hex_bytes(body)?;
    let value = match kind {
        1 | 2 | 6 => {
            let text = encoded_string(&bytes, legacy && kind != 6)?;
            let text = text.strip_suffix('\0').ok_or("registry string has no terminating NUL")?;
            if text.contains('\0') {
                return Err("registry string has embedded NUL characters");
            }
            Value::String(text.to_string())
        }
        7 => {
            let text = encoded_string(&bytes, legacy)?;
            let body = if text == "\0" { "" } else { text.strip_suffix("\0\0").ok_or("multi-string has no double NUL terminator")? };
            if !body.is_empty() && body.split('\0').any(str::is_empty) {
                return Err("multi-string has data after an empty-string terminator");
            }
            json!(if body.is_empty() { Vec::new() } else { body.split('\0').map(str::to_string).collect::<Vec<_>>() })
        }
        4 | 5 if bytes.len() == 4 => {
            let b: [u8; 4] = bytes.as_slice().try_into().map_err(|_| "invalid DWORD size")?;
            json!(if kind == 4 { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
        }
        11 if bytes.len() == 8 => {
            let b: [u8; 8] = bytes.as_slice().try_into().map_err(|_| "invalid QWORD size")?;
            json!(u64::from_le_bytes(b))
        }
        4 | 5 | 11 => return Err("registry integer has the wrong byte length"),
        _ => return Ok((kind, json!({"bytes": bytes.len(), "sha256": aa_core::sha256_hex(&bytes)}), true)),
    };
    Ok((kind, value, false))
}

fn sanitize(name: &str, value: Value) -> Result<Value> {
    if is_sensitive_field_name(name) {
        return Ok(Value::String("[redacted]".into()));
    }
    match value {
        Value::String(s) => Ok(Value::String(redact_named_value(name, &s)?)),
        Value::Array(values) => values.into_iter().map(|v| sanitize(name, v)).collect::<Result<Vec<_>>>().map(Value::Array),
        other => Ok(other),
    }
}

fn key_parts(key: &str) -> Result<(&str, &str)> {
    if key.len() > MAX_KEY {
        return Err("registry key path exceeds the 4 KiB reader limit");
    }
    let (root, path) = key.split_once('\\').unwrap_or((key, ""));
    if !["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS", "HKEY_CURRENT_CONFIG"]
        .iter()
        .any(|r| root.eq_ignore_ascii_case(r))
    {
        return Err("unsupported registry root name");
    }
    if key.contains(['[', ']']) || path.split('\\').any(|p| p.is_empty()) && !path.is_empty() {
        return Err("invalid registry key path");
    }
    Ok((root, path))
}

fn parse(bytes: &[u8]) -> Result<Registry> {
    let text = crate::text::decode(bytes, MAX_BYTES)?;
    let mut lines = text.lines().enumerate();
    let (_, header) = lines.next().ok_or("empty registry text")?;
    let legacy = match header.trim() {
        "Windows Registry Editor Version 5.00" => false,
        "REGEDIT4" if text.is_ascii() => true,
        "REGEDIT4" => return Err("non-ASCII REGEDIT4 text has no established code page"),
        _ => return Err("registry export has no supported version header"),
    };
    let mut result = Registry { version: if legacy { "REGEDIT4" } else { "Windows Registry Editor Version 5.00" }, ..Registry::default() };
    let mut current: Option<(String, bool)> = None;
    while let Some((index, physical)) = lines.next() {
        let line_number = index + 1;
        let mut line = physical.trim().to_string();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if result.entries.len() >= MAX_ENTRIES {
            result.truncated = true;
            break;
        }
        if line.len() > MAX_LINE {
            current = None;
            result.issue(line_number, "registry declaration exceeds the line limit");
            continue;
        }
        if line.starts_with('[') {
            current = None;
            let Some(body) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
                result.issue(line_number, "invalid registry key section");
                continue;
            };
            let deleted = body.starts_with('-');
            let key = if deleted { &body[1..] } else { body };
            if let Err(reason) = key_parts(key) {
                result.issue(line_number, reason);
                continue;
            }
            current = Some((key.to_string(), deleted));
            result.entries.push(Entry {
                operation: if deleted { "delete_key" } else { "create_key" },
                key: redact_sensitive_text(key)?,
                name: None,
                value_type: None,
                value: None,
                line: line_number,
                tags: Vec::new(),
            });
            continue;
        }
        // Only hexadecimal value declarations have a supported continuation form.
        let continued = line.ends_with('\\');
        let mut incomplete = false;
        if continued {
            let assignment = if let Some(rest) = line.strip_prefix('@') { Some(rest) } else { quoted(&line).ok().map(|(_, rest)| rest) };
            let body = assignment.and_then(|rest| rest.trim_start().strip_prefix('=')).map(|body| body.trim_start().to_ascii_lowercase());
            if !body.is_some_and(|body| body.starts_with("hex:") || body.starts_with("hex(")) {
                result.issue(line_number, "continuation outside a hex declaration is unsupported");
                continue;
            }
            while line.ends_with('\\') && line.len() <= MAX_LINE {
                line.pop();
                match lines.next() {
                    Some((_, next)) => line.push_str(next.trim()),
                    None => {
                        result.issue(line_number, "truncated registry continuation");
                        incomplete = true;
                        break;
                    }
                }
            }
        }
        if incomplete {
            continue;
        }
        if line.len() > MAX_LINE {
            result.issue(line_number, "registry declaration exceeds the line limit");
            continue;
        }
        let Some((key, false)) = current.as_ref() else {
            result.issue(line_number, "value declaration is outside a supported non-deletion key section");
            continue;
        };
        let parsed = (|| {
            let (name, rest) = if let Some(rest) = line.strip_prefix('@') { (String::new(), rest) } else { quoted(&line)? };
            let body = rest.trim_start().strip_prefix('=').ok_or("registry value has no equals sign")?.trim();
            let (operation, kind, val, opaque) = if body == "-" {
                ("delete_value", None, None, false)
            } else {
                let (kind, val, opaque) = value(body, legacy)?;
                ("set_value", Some(kind), Some(sanitize(&name, val)?), opaque)
            };
            let (root, path) = key_parts(key)?;
            let tags = if operation == "set_value" {
                installer::classify_registry(&RegistryWrite {
                    root: root.to_string(),
                    key: path.to_string(),
                    name: name.clone(),
                    value: val.as_ref().map(|v| v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())),
                    source: format!("line {line_number}"),
                })
            } else {
                Vec::new()
            };
            Ok::<_, &'static str>((
                Entry {
                    operation,
                    key: redact_sensitive_text(key)?,
                    name: Some(redact_sensitive_text(&name)?),
                    value_type: kind,
                    value: val,
                    line: line_number,
                    tags: tags.into_iter().map(Tag::name).collect(),
                },
                opaque,
            ))
        })();
        match parsed {
            Ok((entry, opaque)) => {
                result.entries.push(entry);
                if opaque {
                    result.issue(line_number, "binary or unknown registry value payload is represented by length and digest only");
                }
            }
            Err(reason) => result.issue(line_number, reason),
        }
    }
    Ok(result)
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("reg") {
        return;
    }
    let registry = match parse(bytes) {
        Ok(registry) => registry,
        Err(reason) => {
            out.limitation("windows.registry-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    out.kind(file, "registry-export");
    out.fact(file, "windows.registry", json!({"version": registry.version, "entries": registry.entries, "issues": registry.issues, "issue_count": registry.issue_count, "truncated": registry.truncated, "applied": false}));
    let mut finding = Finding::new(Section::Capabilities, "windows", "windows.registry", Confidence::Verified, Severity::Info)
        .param("count", registry.entries.len())
        .evidence(Evidence::field(file, "line 1: version header", registry.version));
    for entry in registry.entries.iter().take(12) {
        finding = finding.evidence(Evidence::field(file, format!("line {}", entry.line), json!(entry)));
    }
    out.finding(finding);
    let mut tagged: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
    for entry in &registry.entries {
        for tag in &entry.tags {
            tagged.entry(tag).or_default().push(entry);
        }
    }
    for (tag, entries) in tagged {
        let severity = match tag {
            "driver" | "security_setting" | "root_certificate" => Severity::Medium,
            "autostart" | "service" | "firewall" => Severity::Low,
            _ => Severity::Info,
        };
        let mut finding = Finding::new(
            Section::Capabilities,
            "windows",
            &format!("windows.registry-{}", tag.replace('_', "-")),
            Confidence::Heuristic,
            severity,
        )
        .param("count", entries.len());
        for entry in entries.iter().take(12) {
            finding = finding.evidence(Evidence::field(file, format!("line {}", entry.line), json!(entry)));
        }
        out.finding(finding);
    }
    if registry.issue_count > 0 || registry.truncated {
        out.limitation(
            "windows.registry-partial",
            Some(file),
            Some(format!(
                "{}; entry limit reached: {}; first issues: {}",
                aa_core::counted(registry.issue_count as u64, "declarations were unread or opaque"),
                registry.truncated,
                registry.issues.iter().map(|(line, reason)| format!("line {line}: {reason}")).collect::<Vec<_>>().join("; ")
            )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(body: &str) -> Vec<u8> {
        format!("Windows Registry Editor Version 5.00\n{body}").into_bytes()
    }

    #[test]
    fn writes_deletions_duplicates_and_categories_are_declarations_in_source_order() {
        let parsed = parse(&document(
            r#"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"Fixture"="%SystemRoot%\\fixture.exe --flag"
"Fixture"="other.exe"
"Old"=-
[-HKEY_CURRENT_USER\Software\Fixture\Old]
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Fixture]
"Type"=dword:00000001
[HKEY_CLASSES_ROOT\fixture]
"URL Protocol"=""
@="Fixture Protocol"
"Password"="fixture password with spaces"
"AccessToken"=hex(1):66,00,69,00,78,00,74,00,75,00,72,00,65,00,00,00
"#,
        ))
        .expect("REG declarations");
        assert_eq!(parsed.issue_count, 0);
        assert_eq!(parsed.entries[1].value, Some(json!(r"%SystemRoot%\fixture.exe --flag")));
        assert_eq!(parsed.entries[1].tags, ["autostart"]);
        assert_eq!(parsed.entries[2].name, parsed.entries[1].name);
        assert_eq!(parsed.entries[3].operation, "delete_value");
        assert_eq!(parsed.entries[4].operation, "delete_key");
        assert_eq!(parsed.entries[6].tags, ["driver"]);
        assert_eq!(parsed.entries[8].tags, ["protocol_handler"]);
        assert_eq!(parsed.entries[9].name.as_deref(), Some(""));
        let serialized = serde_json::to_string(&parsed.entries).expect("entries JSON");
        assert!(!serialized.contains("fixture password"));
        assert_eq!(parsed.entries.last().expect("token").value, Some(json!("[redacted]")));
    }

    #[test]
    fn typed_values_and_hex_continuations_are_read_without_expanding_them() {
        let body = "[HKEY_CURRENT_USER\\Software\\Fixture]\n\"expand\"=hex(2):25,00,58,00,25,00,00,00\n\"list\"=hex(7):61,00,00,00,62,00,00,00,00,00\n\"large\"=hex(b):ff,ff,ff,ff,ff,ff,ff,ff\n\"big\"=hex(5):00,00,00,02\n\"little\"=hex(4):02,00,00,00\n\"blob\" = hex:01,02,\\\n 03,04\n";
        let parsed = parse(&document(body)).expect("typed registry values");
        assert_eq!(parsed.entries[1].value, Some(json!("%X%")));
        assert_eq!(parsed.entries[2].value, Some(json!(["a", "b"])));
        assert_eq!(parsed.entries[3].value, Some(json!(u64::MAX)));
        assert_eq!(parsed.entries[4].value, Some(json!(2)));
        assert_eq!(parsed.entries[5].value, Some(json!(2)));
        assert_eq!(parsed.entries[6].value.as_ref().expect("opaque payload")["bytes"], 4);
        assert_eq!(parsed.issue_count, 1);
        assert!(parsed.issues[0].1.contains("digest only"));
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(String::from_utf8(document(body)).expect("UTF-8 test text").encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(
            serde_json::to_vec(&parsed.entries).expect("entries"),
            serde_json::to_vec(&parse(&utf16).expect("UTF-16 export").entries).expect("entries")
        );
    }

    #[test]
    fn invalid_sections_cannot_attach_values_to_the_previous_key_and_limits_are_explicit() {
        let parsed = parse(&document("[HKEY_CURRENT_USER\\Software\\Fixture]\n[BAD\\key]\n\"orphan\"=\"x\"\n")).expect("partial document");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.issue_count, 2);
        for value in ["dword:fffffffff", "hex(7):61,00", "hex(2):00", "hex(b):01", "hex:0g", "hex:01,", "hex:01,\\"] {
            let parsed = parse(&document(&format!("[HKEY_CURRENT_USER\\Software\\Fixture]\n\"x\"={value}"))).expect("partial value");
            assert_eq!(parsed.entries.len(), 1, "{value}");
            assert_eq!(parsed.issue_count, 1, "{value}");
        }
        assert!(parse(b"REGEDIT4\n\xff").is_err());
        assert!(parse(&vec![b'a'; MAX_BYTES + 1]).is_err());
        let long_key =
            parse(&document(&format!("[HKEY_CURRENT_USER\\{}]\n{}", "x".repeat(MAX_KEY), "\"value\"=\"x\"\n".repeat(MAX_ENTRIES))))
                .expect("oversized key is a limitation");
        assert!(long_key.entries.is_empty(), "an oversized key must not amplify every following value record");
        assert_eq!(long_key.issue_count, MAX_ENTRIES + 1);
        assert_eq!(long_key.issues.len(), MAX_ISSUES);
        let oversized =
            parse(&document(&format!("[HKEY_CURRENT_USER\\Software\\Fixture]\n\"x\"=\"{}\"", "x".repeat(MAX_LINE)))).expect("line limit");
        assert_eq!(oversized.entries.len(), 1);
        assert_eq!(oversized.issue_count, 1);
        let many = parse(&document(&format!("[HKEY_CURRENT_USER\\Software\\Fixture]\n{}", "\"x\"=dword:00000001\n".repeat(MAX_ENTRIES))))
            .expect("entry limit");
        assert_eq!(many.entries.len(), MAX_ENTRIES);
        assert!(many.truncated);
        let legacy = parse(b"REGEDIT4\n[HKEY_CURRENT_USER\\Software\\Fixture]\n\"x\"=hex(2):25,58,25,00\n").expect("ASCII REGEDIT4");
        assert_eq!(legacy.entries[1].value, Some(json!("%X%")));
    }
}
