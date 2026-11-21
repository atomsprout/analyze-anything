//! A bounded PowerShell syntax inventory. The parser never evaluates a script.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use std::ops::ControlFlow;
use tree_sitter::{Node, ParseOptions, Parser};

const MAX_BYTES: usize = 512 * 1024;
const MAX_NODES: usize = 50_000;
const MAX_COMMANDS: usize = 256;
const MAX_VALUE: usize = 2048;

#[derive(Default)]
struct Script {
    commands: Vec<Value>,
    administrator: Vec<Value>,
    issues: Vec<Value>,
    issues_omitted: usize,
    published_bytes: usize,
}

fn position(node: Node<'_>) -> Value {
    let point = node.start_position();
    json!({"line":point.row+1,"byte_column":point.column+1,"utf8_offset":node.start_byte(),"utf8_length":node.byte_range().len()})
}

impl Script {
    fn issue(&mut self, node: Node<'_>, reason: &'static str) {
        if self.issues.len() < 64 {
            self.issues.push(json!({"position":position(node),"reason":reason}));
        } else {
            self.issues_omitted += 1;
        }
    }

    fn administrator(&mut self, node: Node<'_>, kind: &'static str) {
        if self.administrator.len() < 128 {
            self.administrator.push(json!({"kind":kind,"position":position(node)}));
        } else {
            self.issue(node, "administrator record count budget");
        }
    }
}

fn literal(value: &str, quoted: bool) -> Option<&str> {
    if value.len() > MAX_VALUE || value.chars().any(char::is_control) {
        return None;
    }
    if quoted {
        if let Some(value) = value.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            return (!value.contains('\'')).then_some(value);
        }
        if let Some(value) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            return (!value.contains(['"', '$', '`', '“', '”'])).then_some(value);
        }
    }
    if !value.is_empty()
        && value.is_ascii()
        && !value.bytes().any(|b| b.is_ascii_whitespace())
        && !value.contains(['$', '`', '\'', '"', '(', ')', '{', '}', '[', ']', '|', '&', ';', '@', '*', '?', '<', '>', ',', '#'])
    {
        Some(value)
    } else {
        None
    }
}

fn publish(value: &str) -> Option<String> {
    aa_core::text::redact_sensitive_text(value).ok()
}

fn classify(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "invoke-webrequest" | "invoke-restmethod" | "start-bitstransfer" => Some("network-request"),
        "new-service" | "set-service" | "start-service" | "stop-service" | "remove-service" => Some("service"),
        "register-scheduledtask" | "set-scheduledtask" | "unregister-scheduledtask" => Some("scheduled-task"),
        "set-executionpolicy" | "set-mppreference" | "add-mppreference" | "remove-mppreference" => Some("security-configuration"),
        _ => None,
    }
}

fn argument_role(value: &str) -> Option<&'static str> {
    // Only literal URI and path forms are published. Argument meanings depend on command binding.
    let begins = |prefix: &str| value.get(..prefix.len()).is_some_and(|s| s.eq_ignore_ascii_case(prefix));
    if begins("http://") || begins("https://") {
        Some("url")
    } else if [".\\", "./", "..\\", "../", "\\\\"].iter().any(|prefix| value.starts_with(prefix))
        || value.as_bytes().get(1..3).is_some_and(|s| s == b":\\" || s == b":/")
    {
        Some("path")
    } else {
        None
    }
}

fn literal_argument(node: Node<'_>) -> bool {
    if matches!(node.kind(), "generic_token" | "string_literal") {
        return true;
    }
    // The grammar wraps a quoted argument in a singleton array and unary expression.
    // Require both wrappers to be singletons before reading the original slice.
    node.kind() == "array_literal_expression"
        && node.child_count() == 1
        && node.child(0).is_some_and(|unary| {
            unary.kind() == "unary_expression" && unary.child_count() == 1 && unary.child(0).is_some_and(|n| n.kind() == "string_literal")
        })
}

fn command(report: &mut Script, node: Node<'_>, text: &str, encoded_budget: &mut Option<crate::encoded_powershell::Budget>) {
    if report.commands.len() == MAX_COMMANDS {
        report.issue(node, "command record count budget");
        return;
    }
    let Some(name_node) = node.child_by_field_name("command_name") else {
        report.issue(node, "command name unavailable");
        return;
    };
    let get_text = |n: Node<'_>| text.get(n.byte_range()).unwrap_or_default();
    let invocation = node.child(0).filter(|n| n.kind() == "command_invokation_operator");
    let operator = invocation.map_or("direct", |n| match get_text(n) {
        "&" => "call",
        "." => "dot-source",
        _ => "unknown",
    });
    let raw_name = get_text(name_node);
    let Some(name) = literal(raw_name, invocation.is_some()).filter(|s| !s.is_empty()) else {
        report.issue(name_node, "dynamic or unsupported command name");
        return;
    };
    let Some(shown) = publish(name) else {
        report.issue(name_node, "command name redaction failed");
        return;
    };
    let mut arguments = Vec::new();
    let mut elevation = false;
    if let Some(elements) = node.child_by_field_name("command_elements") {
        let mut cursor = elements.walk();
        let mut sensitive = false;
        let mut verb = false;
        for (index, arg) in elements.named_children(&mut cursor).filter(|arg| arg.kind() != "command_argument_sep").enumerate() {
            if index == 64 {
                report.issue(arg, "command argument work budget");
                break;
            }
            let raw = get_text(arg);
            if arg.kind() == "command_parameter" {
                verb = raw.eq_ignore_ascii_case("-Verb");
                sensitive = aa_core::text::is_sensitive_field_name(raw.split_once(':').map_or(raw, |(key, _)| key));
                continue;
            }
            if arguments.len() == 16 {
                report.issue(arg, "literal argument count budget");
                break;
            }
            if !literal_argument(arg) {
                if arg.kind() != "comment" {
                    report.issue(arg, "dynamic or unsupported command argument");
                }
                verb = false;
                sensitive = false;
                continue;
            }
            if !sensitive {
                if let Some(value) = literal(raw, true) {
                    elevation |= name.eq_ignore_ascii_case("Start-Process") && verb && value.eq_ignore_ascii_case("RunAs");
                    if let Some(role) = argument_role(value)
                        && let Some(value) = publish(value)
                    {
                        if report.published_bytes + value.len() <= 256 * 1024 {
                            report.published_bytes += value.len();
                            arguments.push(json!({"kind":role,"value":value,"position":position(arg)}));
                        } else {
                            report.issue(arg, "literal argument output budget");
                            break;
                        }
                    }
                } else {
                    report.issue(arg, "dynamic or unsupported literal argument");
                }
            }
            sensitive = false;
            verb = false;
        }
    }
    if elevation {
        report.administrator(node, "start-process-runas");
    }
    let mut record = json!({"name":shown,"operator":operator,"position":position(node),
        "declaration":classify(name),"literal_arguments":arguments});
    if matches!(operator, "direct" | "call")
        && crate::encoded_powershell::host(name)
        && let Some(elements) = node.child_by_field_name("command_elements")
    {
        let mut cursor = elements.walk();
        let mut operands = Vec::new();
        for arg in elements.named_children(&mut cursor) {
            let raw = get_text(arg);
            if arg.kind() == "comment" || (arg.kind() == "command_argument_sep" && raw.trim().is_empty()) {
                continue;
            }
            if operands.len() == 64 {
                report.issue(arg, "EncodedCommand argument work budget");
                operands.clear();
                break;
            }
            let value =
                (literal_argument(arg) || arg.kind() == "command_parameter").then(|| crate::encoded_powershell::literal(raw)).flatten();
            operands.push(crate::encoded_powershell::Operand { value, offset: arg.start_byte(), length: arg.byte_range().len() });
        }
        if let Some(budget) = encoded_budget {
            if let Some(result) = crate::encoded_powershell::inspect(&operands, budget) {
                if result["status"] == "unresolved" || result["syntax"]["status"] != "parsed" {
                    report.issue(node, "EncodedCommand representation or decoded syntax unresolved");
                }
                record["encoded_command"] = result;
            }
        } else if operands.iter().any(|arg| arg.value.is_some_and(|v| v.eq_ignore_ascii_case("-EncodedCommand"))) {
            report.issue(node, "nested EncodedCommand exceeds depth limit");
        }
    }
    report.commands.push(record);
}

fn read(text: &str) -> Result<Script, &'static str> {
    read_with_encoded(text, Some(crate::encoded_powershell::Budget::default()))
}

pub(super) fn inspect_decoded(text: &str) -> Value {
    match read_with_encoded(text, None) {
        Ok(report) => json!({"status":"parsed","offset_basis":"decoded-command-UTF8","commands":report.commands,
            "administrator":report.administrator,"issues":report.issues,"issues_omitted":report.issues_omitted}),
        Err(reason) => json!({"status":"unresolved","reason":reason}),
    }
}

fn read_with_encoded(text: &str, mut encoded_budget: Option<crate::encoded_powershell::Budget>) -> Result<Script, &'static str> {
    let mut parser = Parser::new();
    parser.set_language(&tree_sitter_powershell::LANGUAGE.into()).map_err(|_| "PowerShell grammar is incompatible")?;
    // Bound parser work by callback count rather than a host-dependent time limit.
    let mut callbacks = 0usize;
    let mut progress = |_: &tree_sitter::ParseState| {
        callbacks += 1;
        if callbacks > 20_000 { ControlFlow::Break(()) } else { ControlFlow::Continue(()) }
    };
    let tree = parser
        .parse_with_options(
            &mut |offset, _| text.as_bytes().get(offset..).unwrap_or_default(),
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        )
        .ok_or("PowerShell parser work budget")?;
    let mut report = Script::default();
    if tree.root_node().has_error() {
        return Err("PowerShell grammar reported an error or unsupported syntax");
    }
    let mut cursor = tree.walk();
    let mut visited = 0;
    let mut depth = 0;
    loop {
        let node = cursor.node();
        visited += 1;
        if visited > MAX_NODES || depth > 256 {
            report.issue(node, "PowerShell syntax traversal budget");
            break;
        }
        if node.kind() == "command" {
            command(&mut report, node, text, &mut encoded_budget);
        } else if node.kind() == "comment" {
            let raw = text.get(node.byte_range()).unwrap_or_default();
            let mut parts = raw.split_ascii_whitespace();
            let prefix = text.get(..node.start_byte()).and_then(|s| s.rsplit(['\n', '\r']).next()).unwrap_or_default();
            if prefix.trim().is_empty()
                && parts.next().is_some_and(|s| s.eq_ignore_ascii_case("#requires"))
                && parts.next().is_some_and(|s| s.eq_ignore_ascii_case("-RunAsAdministrator"))
                && parts.next().is_none()
            {
                report.administrator(node, "requires-directive");
            }
        }
        if cursor.goto_first_child() {
            depth += 1;
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return Ok(report);
            }
            depth -= 1;
        }
    }
    Ok(report)
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !matches!(file.extension().as_deref(), Some("ps1" | "psm1")) {
        return;
    }
    let result = crate::text::decode(bytes, MAX_BYTES).and_then(|text| read(&text));
    let report = match result {
        Ok(report) => report,
        Err(reason) => {
            out.limitation("windows.powershell-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    let digest = aa_core::sha256_hex(bytes);
    if file.digests.as_ref().is_none_or(|digests| digests.sha256 != digest) {
        out.limitation("windows.powershell-unreadable", Some(file), Some("script bytes differ from the captured digest".into()));
        return;
    }
    if !report.issues.is_empty() {
        out.limitation("windows.powershell-incomplete", Some(file), None);
    }
    if !report.commands.is_empty() {
        out.finding(
            Finding::new(Section::Structure, "windows", "windows.powershell-commands", Confidence::Verified, Severity::Info)
                .param("count", report.commands.len())
                .evidence(Evidence::field(file, "PowerShell command syntax", json!(report.commands.iter().take(8).collect::<Vec<_>>()))),
        );
    }
    if !report.administrator.is_empty() {
        out.finding(
            Finding::new(Section::Capabilities, "windows", "windows.powershell-administrator", Confidence::Verified, Severity::Info)
                .evidence(Evidence::field(
                    file,
                    "PowerShell administrator declarations",
                    json!(report.administrator.iter().take(8).collect::<Vec<_>>()),
                )),
        );
    }
    out.kind(file, "powershell-script");
    crate::encoded_powershell::finding(file, &report.commands, out);
    out.limitation("windows.powershell-scope", Some(file), None);
    out.fact(file, "windows.powershell", json!({"source_sha256":digest,"profile":"powershell-syntax-v1","offset_basis":"decoded-UTF8",
        "commands":report.commands,"administrator":report.administrator,"issues":report.issues,"issues_omitted":report.issues_omitted,"evaluated":false}));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_commands_and_positions_match_native_powershell_ast() {
        let cases: Vec<Value> = serde_json::from_str(include_str!("../tests/data/powershell-ast.ref.json")).expect("native snapshot");
        for case in cases {
            let report = read(case["source"].as_str().expect("fixture script")).expect("supported fixture syntax");
            let commands = case["commands"].as_array().expect("native commands");
            let expected: Vec<_> = commands.iter().filter(|c| c["name"].is_string()).collect();
            assert_eq!(report.commands.len(), expected.len(), "{}", case["case"]);
            for (parsed, native) in report.commands.iter().zip(expected) {
                assert_eq!(parsed["name"], native["name"], "{}", case["case"]);
                assert_eq!(parsed["position"]["line"], native["line"]);
                assert_eq!(parsed["position"]["byte_column"], native["column"]);
                assert_eq!(parsed["operator"], if native["operator"] == "Ampersand" { "call" } else { "direct" });
            }
            assert_eq!(json!(!report.administrator.is_empty()), case["requires_administrator"]);
            if case["case"] == "dynamic" {
                assert!(report.issues.iter().any(|issue| issue["reason"] == "dynamic or unsupported command name"));
            }
        }
    }

    #[test]
    fn captures_simple_url_path_and_runnable_syntax_without_conflating_strings() {
        let text = r#"Invoke-WebRequest -Uri 'https://example.test/test' -OutFile 'C:\Reports\document.txt'
Start-Process notepad.exe -Verb RunAs
Write-Output 'Start-Process -Verb RunAs'
Write-Output 'https://example.test/?token=synthetic-test-value'
"#;
        let result = read(text).expect("simple command syntax");
        assert_eq!(result.commands.len(), 4, "{:?}", result.commands);
        assert_eq!(result.commands[0]["declaration"], "network-request");
        assert_eq!(result.commands[0]["literal_arguments"][0]["kind"], "url", "{:?}", result.commands);
        assert_eq!(result.commands[0]["literal_arguments"][1]["kind"], "path");
        assert_eq!(result.administrator.len(), 1, "{:?}", result.administrator);
        assert_eq!(result.administrator[0]["kind"], "start-process-runas");
        assert!(!json!(result.commands).to_string().contains("synthetic-test-value"));
    }

    #[test]
    fn malformed_syntax_and_record_limits_leave_explicit_coverage_boundaries() {
        assert!(read("Write-Output 'unterminated").is_err());
        assert!(crate::text::decode(&vec![b'a'; MAX_BYTES + 1], MAX_BYTES).is_err());
        let repeated = "Write-Output 'sample'\n".repeat(MAX_COMMANDS + 80);
        let report = read(&repeated).expect("bounded valid script");
        assert_eq!(report.commands.len(), MAX_COMMANDS);
        assert_eq!(report.issues.len(), 64);
        assert_eq!(report.issues_omitted, 16);
        assert!(report.issues.iter().all(|row| row["reason"] == "command record count budget"));
    }
}
