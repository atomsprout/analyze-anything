//! Reads literal command segments of Windows batch files without expansion or execution.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

const MAX_BYTES: usize = 512 * 1024;
const MAX_COMMANDS: usize = 256;

#[derive(Default)]
struct Batch {
    commands: Vec<Value>,
    issues: Vec<Value>,
    issues_omitted: usize,
    argument_bytes: usize,
}

impl Batch {
    fn issue(&mut self, line: usize, offset: usize, reason: &'static str) {
        if self.issues.len() < 64 {
            self.issues.push(json!({"line":line,"utf8_offset":offset,"reason":reason}));
        } else {
            self.issues_omitted += 1;
        }
    }
}

fn comment(line: &str) -> bool {
    line.starts_with(':') || line.split_ascii_whitespace().next().is_some_and(|head| head.eq_ignore_ascii_case("rem"))
}

fn literal_tokens(segment: &str) -> Result<Vec<(usize, &str)>, &'static str> {
    let mut tokens = Vec::new();
    let mut quoted = false;
    let mut start = None;
    for (offset, ch) in segment.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        }
        if !quoted && ch.is_ascii_whitespace() {
            if let Some(at) = start.take() {
                tokens.push((at, &segment[at..offset]));
            }
        } else if start.is_none() {
            start = Some(offset);
        }
        if tokens.len() > 64 {
            return Err("batch argument count budget");
        }
    }
    if quoted {
        return Err("batch quoting is incomplete");
    }
    if let Some(at) = start {
        tokens.push((at, &segment[at..]));
    }
    Ok(tokens)
}

fn unquote(value: &str) -> Option<&str> {
    let value = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(value);
    (!value.is_empty() && value.len() <= 2048 && !value.contains('"') && !value.chars().any(char::is_control)).then_some(value)
}

fn argument_kind(value: &str) -> Option<&'static str> {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Some("url")
    } else if [".\\", "./", "..\\", "../", "\\\\"].iter().any(|prefix| value.starts_with(prefix))
        || value.as_bytes().get(1..3).is_some_and(|s| s == b":\\" || s == b":/")
    {
        Some("path")
    } else {
        None
    }
}

fn describe(report: &mut Batch, segment: &str, line: usize, offset: usize, preceding_operator: Option<&str>) {
    if segment.is_empty() || comment(segment) {
        return;
    }
    if report.commands.len() == MAX_COMMANDS {
        report.issue(line, offset, "batch command record budget");
        return;
    }
    let tokens = match literal_tokens(segment) {
        Ok(tokens) => tokens,
        Err(reason) => {
            report.issue(line, offset, reason);
            return;
        }
    };
    let Some((_, raw_name)) = tokens.first() else { return };
    let Some(name) =
        unquote(raw_name).filter(|name| name.len() <= 512 && !name.starts_with(['/', '-', '=']) && !name.contains([';', ',', '=', '@']))
    else {
        report.issue(line, offset, "batch command name outside literal profile");
        return;
    };
    let mut lower = name.to_ascii_lowercase();
    if lower == "echo." || lower == "echo:" || lower == "echo/" {
        lower = "echo".into();
    }
    if matches!(lower.as_str(), "if" | "for" | "else" | "call" | "goto" | "start" | "cmd" | "cmd.exe") {
        report.issue(line, offset, "batch control flow or nested command dispatch is unresolved");
        return;
    }
    let declaration = match lower.as_str() {
        "curl" | "curl.exe" => Some("network-request"),
        "sc" | "sc.exe" => Some("service-tool"),
        "schtasks" | "schtasks.exe" => Some("scheduled-task-tool"),
        "reg" | "reg.exe" => Some("registry-tool"),
        "runas" | "runas.exe" => Some("alternate-user-tool"),
        _ => None,
    };
    let Some(shown_name) = aa_core::text::redact_sensitive_text(name).ok() else {
        report.issue(line, offset, "batch command name redaction failed");
        return;
    };
    let mut arguments = Vec::new();
    let mut sensitive = false;
    // Echo output and variable assignments are not command arguments for this inventory.
    if !matches!(lower.as_str(), "echo" | "set") {
        for (at, raw) in tokens.into_iter().skip(1) {
            let Some(value) = unquote(raw) else { continue };
            if sensitive {
                sensitive = false;
                continue;
            }
            if aa_core::text::is_sensitive_field_name(value.split(['=', ':']).next().unwrap_or_default()) {
                sensitive = true;
                continue;
            }
            if let Some(kind) = argument_kind(value)
                && let Ok(value) = aa_core::text::redact_sensitive_text(value)
            {
                if arguments.len() >= 16 || report.argument_bytes + value.len() > 256 * 1024 {
                    report.issue(line, offset + at, "batch literal argument output budget");
                    break;
                }
                report.argument_bytes += value.len();
                arguments.push(json!({"kind":kind,"value":value,"utf8_offset":offset+at}));
            }
        }
    }
    report.commands.push(json!({"name":shown_name,"line":line,"utf8_offset":offset,
        "utf8_length":segment.len(),"preceding_operator":preceding_operator,"declaration":declaration,"literal_arguments":arguments}));
}

fn scan(text: &str) -> Batch {
    let mut report = Batch::default();
    let mut offset = 0;
    let mut group_depth = 0usize;
    let mut continuation = false;
    for (index, physical) in text.split_inclusive('\n').enumerate() {
        let line = index + 1;
        let line_offset = offset;
        offset += physical.len();
        let body = physical.trim_end_matches(['\r', '\n']);
        let stripped = body.trim_start();
        let bare = stripped.strip_prefix('@').unwrap_or(stripped).trim_start();
        if bare.is_empty() && !continuation {
            continue;
        }
        let continuing = body.as_bytes().iter().rev().take_while(|&&b| b == b'^').count() % 2 == 1;
        if comment(bare) && group_depth == 0 && !continuation && !continuing {
            if bare.contains(['&', '|', '<', '>']) {
                report.issue(line, line_offset, "batch comment or label with shell operators is unresolved");
            }
            continue;
        }
        let mut quoted = false;
        let mut escaped = false;
        let mut separators = Vec::new();
        let mut structural = group_depth > 0;
        let mut redirect = false;
        for (at, ch) in body.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '"' {
                quoted = !quoted;
            } else if !quoted {
                match ch {
                    '^' => escaped = true,
                    '(' => {
                        group_depth += 1;
                        structural = true;
                    }
                    ')' => {
                        group_depth = group_depth.saturating_sub(1);
                        structural = true;
                    }
                    '<' | '>' => redirect = true,
                    '&' | '|' if separators.len() < 128 => separators.push(at),
                    '&' | '|' => structural = true,
                    _ => {}
                }
            }
        }
        if continuation || continuing || structural || quoted || redirect || body.contains(['%', '!', '^']) {
            report.issue(line, line_offset, "batch expansion, escape, grouping, redirection or continued line is unresolved");
            continuation = continuing;
            continue;
        }
        let mut start = 0;
        let mut previous = None;
        for stop in separators.into_iter().chain(std::iter::once(body.len())) {
            if stop < start {
                continue;
            }
            let raw = &body[start..stop];
            let clean = raw.trim_start();
            let clean = clean.strip_prefix('@').unwrap_or(clean).trim();
            if comment(clean) && stop < body.len() {
                report.issue(line, line_offset + start, "batch comment or label with shell operators is unresolved");
                break;
            }
            describe(&mut report, clean, line, line_offset + start + raw.find(clean).unwrap_or(0), previous);
            previous = match body.as_bytes().get(stop..stop + 2) {
                Some(b"&&") => Some("&&"),
                Some(b"||") => Some("||"),
                _ if body.as_bytes().get(stop) == Some(&b'&') => Some("&"),
                _ if body.as_bytes().get(stop) == Some(&b'|') => Some("|"),
                _ => None,
            };
            start = stop + if matches!(previous, Some("&&" | "||")) { 2 } else { 1 };
        }
    }
    report
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !matches!(file.extension().as_deref(), Some("bat" | "cmd")) {
        return;
    }
    let text = match crate::text::decode(bytes, MAX_BYTES) {
        Ok(text) => text,
        Err(reason) => {
            out.limitation("windows.batch-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    let digest = aa_core::sha256_hex(bytes);
    if file.digests.as_ref().is_none_or(|d| d.sha256 != digest) {
        out.limitation("windows.batch-unreadable", Some(file), Some("script bytes differ from the captured digest".into()));
        return;
    }
    let report = scan(&text);
    if !report.issues.is_empty() {
        out.limitation("windows.batch-incomplete", Some(file), None);
    }
    if !report.commands.is_empty() {
        out.finding(
            Finding::new(Section::Structure, "windows", "windows.batch-commands", Confidence::Verified, Severity::Info)
                .param("count", report.commands.len())
                .evidence(Evidence::field(
                    file,
                    "Batch literal command segments",
                    json!(report.commands.iter().take(8).collect::<Vec<_>>()),
                )),
        );
    }
    out.kind(file, "batch-script");
    out.limitation("windows.batch-scope", Some(file), None);
    out.fact(
        file,
        "windows.batch",
        json!({"source_sha256":digest,"profile":"batch-literal-segments-v1","offset_basis":"decoded-UTF8",
        "commands":report.commands,"issues":report.issues,"issues_omitted":report.issues_omitted,"evaluated":false}),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(report: &Batch) -> Vec<&str> {
        report.commands.iter().map(|c| c["name"].as_str().expect("literal command name")).collect()
    }

    #[test]
    fn treats_quotes_operators_comments_and_unsupported_lines_as_distinct_forms() {
        let text = concat!(
            "@echo off\r\n",
            "REM curl https://example.test/ignored\r\n",
            ":: ignored label comment\r\n",
            "echo \"curl https://example.test/ignored & dir\" && dir \"C:\\Report Folder\" | findstr summary\r\n",
            "if exist marker (\r\n",
            "  echo grouped\r\n",
            ")\r\n",
            "echo escaped ^& dir\r\n",
            "echo continued ^\r\n",
            "dir possibly-an-argument\r\n",
            "%script_name%\r\n",
            "echo !variable!\r\n",
            "echo quoted > file.txt\r\n",
            "echo after\r\n",
        );
        let report = scan(text);
        assert_eq!(names(&report), ["echo", "echo", "dir", "findstr", "echo"]);
        assert_eq!(report.commands[2]["preceding_operator"], "&&");
        assert_eq!(report.commands[3]["preceding_operator"], "|");
        assert_eq!(report.commands[2]["literal_arguments"][0]["value"], r"C:\Report Folder");
        assert!(report.commands[1]["literal_arguments"].as_array().expect("echo arguments").is_empty());
        assert_eq!(report.issues.len(), 9);
        for row in &report.commands {
            let offset = row["utf8_offset"].as_u64().expect("syntax offset") as usize;
            assert!(text[offset..].starts_with(row["name"].as_str().expect("command")));
        }
    }

    #[test]
    fn producer_script_retains_literals_around_unresolved_caret_continuations() {
        let bytes = include_bytes!("../tests/data/upstream-makeaosponwinx86.cmd");
        assert_eq!(aa_core::sha256_hex(bytes), "a30cf5d2de5f7a9bdbf21cc8235ab8d506c9dffeadba629916457cc041ced635");
        let script = crate::text::decode(bytes, MAX_BYTES).expect("licensed producer script");
        let report = scan(&script);
        assert_eq!(names(&report), ["mkdir", "cd", "ninja"]);
        assert_eq!(report.issues.len(), 9);
        assert_eq!(report.commands[0]["line"], 1);
        assert_eq!(report.commands[2]["line"], 17);
    }
}
