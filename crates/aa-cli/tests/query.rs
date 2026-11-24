//! Finished-report commands stay available without the optional AI/network feature.
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("query test folder");
    let report = aa_engine::analyze_bytes(
        &aa_engine::Registry::standard(),
        "source-that-does-not-exist.txt",
        b"https://example.invalid/evidence".to_vec(),
        &aa_engine::Options::default(),
        &mut aa_engine::NoProgress,
    );
    let path = dir.path().join("report.json");
    std::fs::write(&path, aa_core::canonical_json(&report)).expect("saved report");
    (dir, path)
}

#[test]
fn offline_cli_queries_need_only_the_finished_report_and_do_not_rewrite_it() {
    let (dir, path) = fixture();
    let before = std::fs::read(&path).expect("report bytes");
    let result = Command::new(env!("CARGO_BIN_EXE_analyze-anything"))
        .arg("query")
        .arg(&path)
        .args(["files", "--args", "{\"limit\":1}"])
        .output()
        .expect("query CLI");
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let answer: Value = serde_json::from_slice(&result.stdout).expect("query JSON");
    assert_eq!(answer["matching"], 1);
    assert_eq!(answer["files"][0]["path"], "source-that-does-not-exist.txt");
    assert!(answer["next_offset"].is_null());
    assert_eq!(std::fs::read(&path).expect("unchanged report"), before);
    assert_eq!(std::fs::read_dir(dir.path()).expect("output contents").count(), 1);
    let schemas = Command::new(env!("CARGO_BIN_EXE_analyze-anything")).args(["query", "--list-tools"]).output().expect("query schemas");
    assert!(schemas.status.success(), "{}", String::from_utf8_lossy(&schemas.stderr));
    assert_eq!(serde_json::from_slice::<Value>(&schemas.stdout).expect("schemas").as_array().expect("tools").len(), 7);
}

#[test]
fn offline_stdio_mcp_exposes_queries_without_an_analysis_capability() {
    let (_dir, path) = fixture();
    let mut child = Command::new(env!("CARGO_BIN_EXE_analyze-anything"))
        .arg("mcp")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("MCP CLI");
    let mut stdin = child.stdin.take().expect("MCP input");
    for message in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_coverage","arguments":{}}}),
    ] {
        writeln!(stdin, "{message}").expect("write MCP request");
    }
    drop(stdin);
    let result = child.wait_with_output().expect("MCP exit");
    assert!(result.status.success());
    let replies: Vec<Value> =
        String::from_utf8(result.stdout).expect("MCP UTF-8").lines().map(|line| serde_json::from_str(line).expect("MCP JSON")).collect();
    assert_eq!(replies.len(), 3);
    let tools = replies[1]["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 7);
    assert!(tools.iter().all(|tool| tool["annotations"]["readOnlyHint"] == true));
    assert!(!tools.iter().any(|tool| tool["name"] == "analyze_input"));
    assert!(replies[2]["result"]["content"][0]["text"].as_str().expect("coverage").contains("selected_artifacts"));
}

#[test]
fn cli_reports_unsupported_layout_before_deserializing_its_body() {
    let (dir, path) = fixture();
    std::fs::write(&path, b"{\"schema_version\":1}").expect("unsupported layout");
    let result = Command::new(env!("CARGO_BIN_EXE_analyze-anything")).arg("query").arg(path).arg("coverage").output().expect("query CLI");
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("layout 1 is unsupported"));
    assert_eq!(std::fs::read_dir(dir.path()).expect("no exports").count(), 1);
}
