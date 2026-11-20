//! Reads INF declarations without selecting a host platform or invoking SetupAPI.

use std::collections::BTreeMap;

use aa_core::plugin::Output;
use aa_core::text::{redact_named_value, redact_sensitive_text};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::json;

const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
const MAX_SECTIONS: usize = 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_FIELDS: usize = 128;
const MAX_FIELD: usize = 4096;
const MAX_ISSUES: usize = 64;
const MAX_PROJECTED_BYTES: usize = 4 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Debug, Serialize)]
struct Entry {
    line: usize,
    end_line: usize,
    key: Option<String>,
    fields: Vec<String>,
    // A separate projection, never a replacement for the literal declaration.
    neutral_fields: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct InfSection {
    name: String,
    line: usize,
    entries: Vec<Entry>,
}

#[derive(Debug, Default)]
struct Inf {
    sections: Vec<InfSection>,
    issues: Vec<(usize, &'static str)>,
    issue_count: usize,
    truncated: bool,
    entries: usize,
}

impl Inf {
    fn issue(&mut self, line: usize, reason: &'static str) {
        self.issue_count += 1;
        if self.issues.len() < MAX_ISSUES {
            self.issues.push((line, reason));
        }
    }
}

// INF quotes do not use backslash escapes. A semicolon inside a percent token is data.
fn uncomment(line: &str, section_boundary: bool) -> Result<(&str, bool)> {
    if section_boundary && line.trim_start_matches([' ', '\t']).starts_with('[') {
        if let Some(end) = line.find(']') {
            let tail = line[end + 1..].trim_matches([' ', '\t']);
            if tail.is_empty() || tail.starts_with(';') {
                return Ok((&line[..=end], false));
            }
        }
        return Err("malformed section header");
    }
    let mut quoted = false;
    let mut token = false;
    let mut end = line.len();
    for (index, ch) in line.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '%' if !quoted => token = !token,
            ';' if !quoted && !token => {
                end = index;
                break;
            }
            _ => {}
        }
    }
    if quoted {
        return Err("a physical line has unclosed quotation marks");
    }
    let text = line[..end].trim_end_matches([' ', '\t']);
    Ok((text, text.ends_with('\\')))
}

// Keep whitespace inside quotes, discard it only at the outer edges of each field.
fn fields(text: &str, delimiter: char) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut value = String::new();
    let mut pending_space = String::new();
    let mut quoted = false;
    let mut token = false;
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if quoted && chars.peek() == Some(&'"') {
                value.push_str(&pending_space);
                pending_space.clear();
                value.push('"');
                chars.next();
            } else {
                if !quoted {
                    value.push_str(&pending_space);
                    pending_space.clear();
                }
                quoted = !quoted;
            }
        } else if ch == delimiter && !quoted && !token {
            result.push(std::mem::take(&mut value));
            pending_space.clear();
            if result.len() >= MAX_FIELDS {
                return Err("entry exceeds the field count budget");
            }
        } else if matches!(ch, ' ' | '\t') && !quoted {
            if !value.is_empty() {
                pending_space.push(ch);
            }
        } else {
            if ch == '%' && !quoted {
                token = !token;
            }
            value.push_str(&pending_space);
            pending_space.clear();
            value.push(ch);
        }
        if value.len() + pending_space.len() > MAX_FIELD {
            return Err("field exceeds the decoded UTF-8 byte budget");
        }
    }
    if quoted {
        return Err("unclosed quotation marks");
    }
    result.push(value);
    Ok(result)
}

fn entry(text: &str, line: usize, end_line: usize) -> Result<Entry> {
    let mut quoted = false;
    let mut token = false;
    let equal = text.char_indices().find_map(|(index, ch)| {
        match ch {
            '"' => quoted = !quoted,
            '%' if !quoted => token = !token,
            '=' if !quoted && !token => return Some(index),
            _ => {}
        }
        None
    });
    let (key, body) = if let Some(index) = equal {
        let mut key = fields(&text[..index], ',')?;
        if key.len() != 1 || key[0].is_empty() {
            return Err("entry has an empty or multi-field key");
        }
        (key.pop(), &text[index + 1..])
    } else {
        (None, text)
    };
    Ok(Entry { line, end_line, key, fields: fields(body, ',')?, neutral_fields: None })
}

fn parse(bytes: &[u8]) -> Result<Inf> {
    let text = crate::text::decode(bytes, MAX_BYTES)?;
    // Non-BOM bytes above ASCII could instead be an ANSI code page. Do not guess UTF-8.
    if !bytes.starts_with(&[0xff, 0xfe]) && !bytes.starts_with(&[0xfe, 0xff]) && !bytes.starts_with(&[0xef, 0xbb, 0xbf]) && !text.is_ascii()
    {
        return Err("non-ASCII INF requires a Unicode BOM; no ANSI code page is assumed");
    }
    let mut inf = Inf::default();
    let mut logical = String::new();
    let mut start = 0;
    let mut inside = false;
    let mut discarding = false;
    let mut continuing = false;
    for (index, physical) in text.lines().enumerate() {
        let line = index + 1;
        if !continuing && !discarding {
            start = line;
        }
        let (part, continued) = match uncomment(physical, !continuing && !discarding) {
            Ok(value) => value,
            Err(reason) => {
                inf.issue(start, reason);
                logical.clear();
                discarding = false;
                continuing = false;
                // A malformed section header must not lend the previous section's context.
                if physical.trim_start().starts_with('[') {
                    inside = false;
                }
                continue;
            }
        };
        if discarding || logical.len().saturating_add(part.len()) > MAX_LINE {
            if !discarding {
                inf.issue(start, "logical line exceeds the byte budget");
                inf.truncated = true;
            }
            logical.clear();
            discarding = continued;
            continuing = false;
            if physical.trim_start().starts_with('[') {
                inside = false;
            }
            continue;
        }
        logical.push_str(if continued {
            part[..part.len() - 1].trim_start_matches([' ', '\t'])
        } else {
            part.trim_start_matches([' ', '\t'])
        });
        if continued {
            continuing = true;
            continue;
        }
        continuing = false;
        let current = std::mem::take(&mut logical);
        let current = current.trim_matches([' ', '\t']);
        if current.is_empty() {
            continue;
        }
        if current.starts_with('[') {
            inside = false;
            let Some(name) = current.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
                inf.issue(start, "malformed section header");
                continue;
            };
            if name.is_empty() || name.len() > 1024 || name.chars().count() > 255 || name.contains(['[', ']', '\0']) {
                inf.issue(start, "empty, oversized or malformed section name");
                continue;
            }
            if inf.sections.len() >= MAX_SECTIONS {
                inf.issue(start, "section count exceeds the budget");
                inf.truncated = true;
                break;
            }
            inf.sections.push(InfSection { name: name.into(), line: start, entries: Vec::new() });
            inside = true;
            continue;
        }
        if !inside {
            inf.issue(start, "entry outside a readable section");
            continue;
        }
        if inf.entries >= MAX_ENTRIES {
            inf.issue(start, "entry count exceeds the budget");
            inf.truncated = true;
            break;
        }
        match entry(current, start, line) {
            Ok(entry) => {
                inf.sections.last_mut().expect("readable section exists").entries.push(entry);
                inf.entries += 1;
            }
            Err(reason) => {
                inf.truncated |= reason.contains("budget");
                inf.issue(start, reason);
            }
        }
    }
    if continuing || discarding {
        inf.issue(start, "unfinished line continuation");
    }
    if !inf.sections.iter().any(|s| s.name.eq_ignore_ascii_case("version")) {
        return Err("no readable Version section; legacy or non-INF syntax is unsupported");
    }
    project_neutral_strings(&mut inf);
    Ok(inf)
}

// Only unique, literal, undecorated string definitions are eligible. This projection is
// disabled with localized sections or an incomplete parse; it never selects the host locale.
fn expand(text: &str, strings: &BTreeMap<String, String>) -> Option<String> {
    let mut result = String::new();
    let mut rest = text;
    while let Some(index) = rest.find('%') {
        result.push_str(&rest[..index]);
        rest = &rest[index + 1..];
        if let Some(next) = rest.strip_prefix('%') {
            result.push('%');
            rest = next;
        } else {
            let end = rest.find('%')?;
            result.push_str(strings.get(&rest[..end].to_ascii_lowercase())?);
            rest = &rest[end + 1..];
        }
        if result.len() > MAX_FIELD {
            return None;
        }
    }
    result.push_str(rest);
    (result.len() <= MAX_FIELD).then_some(result)
}

fn project_neutral_strings(inf: &mut Inf) {
    if inf.issue_count > 0 || inf.sections.iter().any(|s| !s.name.is_ascii() || s.name.to_ascii_lowercase().starts_with("strings.")) {
        return;
    }
    let mut definitions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for section in &inf.sections {
        if section.name.eq_ignore_ascii_case("strings") {
            for entry in &section.entries {
                if let Some(key) = &entry.key {
                    if !key.is_ascii() {
                        // A non-ASCII key could alias an ASCII key under Windows casing.
                        return;
                    }
                    definitions.entry(key.to_ascii_lowercase()).or_default().extend(entry.fields.clone());
                }
            }
        }
    }
    let strings: BTreeMap<String, String> = definitions
        .into_iter()
        .filter_map(|(key, values)| {
            (values.len() == 1 && !values[0].contains('%') && !aa_core::text::is_sensitive_field_name(&key))
                .then(|| (key, values[0].clone()))
        })
        .collect();
    let mut projected_bytes = 0usize;
    let mut exhausted = false;
    for section in &mut inf.sections {
        if section.name.eq_ignore_ascii_case("strings") {
            continue;
        }
        for entry in &mut section.entries {
            entry.neutral_fields = entry.fields.iter().map(|value| expand(value, &strings)).collect();
            if let Some(fields) = &entry.neutral_fields {
                projected_bytes = projected_bytes.saturating_add(fields.iter().map(String::len).sum::<usize>());
                if projected_bytes > MAX_PROJECTED_BYTES {
                    exhausted = true;
                    break;
                }
            }
        }
        if exhausted {
            break;
        }
    }
    if exhausted {
        for section in &mut inf.sections {
            for entry in &mut section.entries {
                entry.neutral_fields = None;
            }
        }
        inf.issue(0, "neutral string projection exceeds the total byte budget");
    }
}

fn redact(inf: &mut Inf) -> Result<()> {
    for section in &mut inf.sections {
        let sensitive_section = aa_core::text::is_sensitive_field_name(&section.name);
        section.name = redact_sensitive_text(&section.name)?;
        for entry in &mut section.entries {
            let name = entry.key.as_deref().unwrap_or("");
            // Registry rows have no key; their third field is the value name.
            let registry_name = if entry.key.is_none() && entry.fields.first().is_some_and(|s| s.to_ascii_uppercase().starts_with("HK")) {
                entry.fields.get(2).map(String::as_str).unwrap_or("")
            } else {
                ""
            };
            let sensitive = sensitive_section
                || aa_core::text::is_sensitive_field_name(name)
                || aa_core::text::is_sensitive_field_name(registry_name)
                || (entry.key.is_none()
                    && entry.neutral_fields.as_ref().is_some_and(|fields| {
                        fields.first().is_some_and(|s| s.to_ascii_uppercase().starts_with("HK"))
                            && fields.get(2).is_some_and(|s| aa_core::text::is_sensitive_field_name(s))
                    }));
            for value in entry.fields.iter_mut().chain(entry.neutral_fields.iter_mut().flatten()) {
                *value = if sensitive { "[redacted]".into() } else { redact_named_value(name, value)? };
            }
            entry.key = entry.key.as_deref().map(redact_sensitive_text).transpose()?;
        }
    }
    Ok(())
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("inf") {
        return;
    }
    let mut inf = match parse(bytes) {
        Ok(inf) => inf,
        Err(reason) => {
            out.limitation("windows.inf-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    if let Err(reason) = redact(&mut inf) {
        out.limitation("windows.inf-unreadable", Some(file), Some(reason.into()));
        return;
    }
    out.kind(file, "windows-inf");
    let mut finding = Finding::new(Section::Structure, "windows", "windows.inf", Confidence::Verified, Severity::Info)
        .param("sections", inf.sections.len())
        .param("entries", inf.entries);
    let mut evidence_count = 0;
    for section in &inf.sections {
        if section.name.eq_ignore_ascii_case("version") {
            for entry in &section.entries {
                if evidence_count < 16 {
                    finding = finding.evidence(Evidence::field(
                        file,
                        format!("line {}/[{}]/{}", entry.line, section.name, entry.key.as_deref().unwrap_or("(list)")),
                        entry.fields.join(", "),
                    ));
                    evidence_count += 1;
                }
            }
        }
    }
    if evidence_count == 0 {
        let version = inf.sections.iter().find(|s| s.name.eq_ignore_ascii_case("version")).expect("parse requires a Version section");
        finding = finding.evidence(Evidence::field(file, format!("line {}/INF section", version.line), version.name.as_str()));
    }
    out.finding(finding);
    out.fact(
        file,
        "windows.inf",
        json!({
            "sections": inf.sections,
            "entry_count": inf.entries,
            "issues": inf.issues,
            "issue_count": inf.issue_count,
            "truncated": inf.truncated,
            "neutral_projection": "unique-literal-undecorated-strings-no-locale-selection",
            "platform_selected": false,
            "installed": false,
            "catalog_verified": false,
        }),
    );
    out.limitation("windows.inf-semantics-unresolved", Some(file), None);
    if inf.issue_count > 0 {
        out.limitation(
            "windows.inf-partial",
            Some(file),
            Some(aa_core::counted(inf.issue_count as u64, "declarations were unread or unsupported")),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar_keeps_decorations_empty_fields_comments_quotes_and_continuations() {
        let inf = parse(
            br#"[Version]
Signature="$Windows NT$"
DriverVer=06/16/2007,1.0.0.0
[Install.NTamd64.10.0]
CopyFiles="dir\"\ ; trailing comment
 ,file.sys
[Registry]
HKR,,Value,,"A;B, ""quoted"" value" ; comment
[Version]
Class=Sample
"#,
        )
        .expect("bounded INF declarations");
        assert_eq!(inf.issue_count, 0, "{:?}", inf.issues);
        assert_eq!(inf.sections.len(), 4, "duplicate sections remain in source order");
        assert_eq!(inf.sections[1].name, "Install.NTamd64.10.0");
        let entry = &inf.sections[1].entries[0];
        assert_eq!(entry.fields, ["dir\\", "file.sys"]);
        assert_eq!((entry.line, entry.end_line), (5, 6));
        assert_eq!(inf.sections[2].entries[0].fields, ["HKR", "", "Value", "", "A;B, \"quoted\" value"]);
    }

    #[test]
    fn neutral_projection_is_separate_bounded_and_does_not_expand_directories_or_host_state() {
        let inf = parse(b"[Version]\nProvider=%Provider%\n[Service]\nServiceBinary=%13%\\%Driver%.sys\nOther=%%SystemRoot%%\\a\n[Strings]\nProvider=Example\nDriver=Sample\n").expect("INF strings");
        assert_eq!(inf.sections[0].entries[0].fields, ["%Provider%"]);
        assert_eq!(inf.sections[0].entries[0].neutral_fields.as_deref(), Some(["Example".to_string()].as_slice()));
        assert!(inf.sections[1].entries[0].neutral_fields.is_none());
        assert_eq!(inf.sections[1].entries[1].neutral_fields.as_deref(), Some([r"%SystemRoot%\a".to_string()].as_slice()));
        for suffix in ["[Strings.0409]\nProvider=Localized\n", "[Strings]\nprovider=Duplicate\n", "[Strings]\nProvider=%Nested%\n"] {
            let inf = parse(format!("[Version]\nProvider=%Provider%\n[Strings]\nProvider=Example\n{suffix}").as_bytes())
                .expect("ambiguous strings retained");
            assert!(inf.sections[0].entries[0].neutral_fields.is_none());
        }
        assert!(expand("%s%%s%", &BTreeMap::from([("s".into(), "a".repeat(MAX_FIELD))])).is_none());
    }

    #[test]
    fn malformed_sections_do_not_inherit_context_and_partial_parse_disables_projection() {
        let inf = parse(b"[Version]\nClass=Sample\n[broken\nProvider=wrong-context\n[Good]\nKey=value\n").expect("partial INF");
        assert_eq!(inf.issue_count, 2);
        assert_eq!(inf.entries, 2);
        assert!(inf.sections[0].entries[0].neutral_fields.is_none());
        assert!(parse(b"[Other]\nKey=value\n").is_err());
        assert!(parse(&[0xff, 0xfe, 0x41]).is_err());
        assert!(parse("[Version]\nProvider=中文\n".as_bytes()).is_err());
        let unicode: Vec<u8> =
            [0xff, 0xfe].into_iter().chain("[Version]\nProvider=中文\n".encode_utf16().flat_map(u16::to_le_bytes)).collect();
        assert_eq!(parse(&unicode).expect("marked Unicode INF").sections[0].entries[0].fields, ["中文"]);
        let continued = parse(b"[Version]\n\\\nKey=value\n").expect("empty continuation prefix retains source start");
        assert_eq!((continued.sections[0].entries[0].line, continued.sections[0].entries[0].end_line), (2, 3));
        assert_eq!(parse(b"[Version]\n\\").expect("unfinished empty continuation").issue_count, 1);
    }

    #[test]
    fn every_resource_budget_is_explicit_and_bounded() {
        assert!(parse(&vec![b'a'; MAX_BYTES + 1]).is_err());
        let lines = format!("[Version]\n{}\n[Good]\nKey=kept\n", "x".repeat(MAX_LINE + 1));
        let inf = parse(lines.as_bytes()).expect("line budget");
        assert!(inf.truncated);
        assert_eq!(inf.entries, 1);
        assert_eq!(inf.sections[1].entries[0].fields, ["kept"]);
        assert!(fields(&"x".repeat(MAX_FIELD + 1), ',').is_err());
        assert!(fields(&"x,".repeat(MAX_FIELDS), ',').is_err());
        let sections = format!("[Version]\n{}", "[Next]\n".repeat(MAX_SECTIONS));
        let inf = parse(sections.as_bytes()).expect("section budget");
        assert!(inf.truncated);
        assert_eq!(inf.sections.len(), MAX_SECTIONS);
        let entries = format!("[Version]\n{}", "Key=value\n".repeat(MAX_ENTRIES + 1));
        let inf = parse(entries.as_bytes()).expect("entry budget");
        assert!(inf.truncated);
        assert_eq!(inf.entries, MAX_ENTRIES);
        let errors = format!("[Version]\n{}", "bad=\"quote\n".repeat(MAX_ISSUES + 10));
        let inf = parse(errors.as_bytes()).expect("issue budget");
        assert_eq!(inf.issue_count, MAX_ISSUES + 10);
        assert_eq!(inf.issues.len(), MAX_ISSUES);
        let projected = format!("[Version]\n{}[Strings]\nX={}\n", "Key=%X%\n".repeat(1100), "a".repeat(MAX_FIELD));
        let inf = parse(projected.as_bytes()).expect("projection amplification budget");
        assert_eq!(inf.issue_count, 1);
        assert!(inf.sections.iter().flat_map(|s| &s.entries).all(|e| e.neutral_fields.is_none()));
    }

    #[test]
    fn redaction_covers_literal_and_projected_values_before_serialization() {
        let mut inf = parse(b"[Version]\nProvider=%Name%\nOther=%ApiToken%\n[Strings]\nName=https://user:private@example.invalid/\nApiToken=private token with spaces\nValueName=Password\n[Reg]\nHKR,,Password,,private-registry-secret\nHKR,,%ValueName%,,private-projected-secret\n").expect("INF data");
        redact(&mut inf).expect("bounded redaction");
        let json = serde_json::to_string(&inf.sections).expect("serializable declarations");
        for secret in ["private", "private token with spaces", "private-registry-secret"] {
            assert!(!json.contains(secret), "{json}");
        }
    }
}
