//! Exercise the shipped executable and its real child, without executing an input artifact.

use std::path::Path;
use std::process::{Command, Output};

fn analyze(input: &Path, out: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_analyze-anything"));
    command.arg(input).arg("-o").arg(out).args(["--format", "json"]);
    #[cfg(feature = "ai")]
    command.arg("--no-ai");
    command.args(extra).output().expect("CLI supervisor process")
}

#[test]
fn supervised_cli_matches_the_engine_and_preserves_custom_rules() {
    let dir = tempfile::tempdir().expect("private test folder");
    let input = dir.path().join("中文 ' sample.txt");
    std::fs::write(&input, "hello https://example.com/marker").expect("input fixture");
    let out = dir.path().join("report");
    let result = analyze(&input, &out, &[]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let saved: aa_core::Report =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).expect("report file")).expect("report JSON");
    let direct = aa_engine::analyze(&input, &aa_engine::Options::default(), &mut aa_engine::NoProgress).expect("direct reference");
    assert_eq!(aa_core::canonical_json(&saved), aa_core::canonical_json(&direct));
    let rules = dir.path().join("test.yar");
    std::fs::write(&rules, "rule cli_marker { strings: $marker = \"example.com/marker\" condition: $marker }").expect("rule fixture");
    let result = analyze(&input, &out, &["--rules", rules.to_str().expect("UTF-8 rule path")]);
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let saved: aa_core::Report =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).expect("report file")).expect("report JSON");
    assert!(saved.findings.iter().any(|f| f.params.values().any(|v| v.as_str().is_some_and(|s| s.contains("cli_marker")))));
    let failed_threshold = analyze(&input, &out, &["--rules", rules.to_str().expect("rule path"), "--fail-on", "low"]);
    assert_eq!(failed_threshold.status.code(), Some(3), "finding threshold stays in the supervising CLI");
}

#[test]
fn worker_startup_failure_does_not_fabricate_a_report() {
    let dir = tempfile::tempdir().expect("private test folder");
    let input = dir.path().join("input.txt");
    std::fs::write(&input, "plain text").expect("input fixture");
    let out = dir.path().join("report");
    let result = analyze(&input, &out, &["--rules", "a-rule-file-that-does-not-exist.yar"]);
    assert_eq!(result.status.code(), Some(1));
    assert!(!out.join("report.json").exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot read"));
}

#[test]
fn run_deadline_returns_only_a_real_partial_report_or_an_explicit_failure() {
    let dir = tempfile::tempdir().expect("private test folder");
    let input = dir.path().join("input.bin");
    std::fs::write(&input, vec![0x41; 4 * 1024 * 1024]).expect("bounded input fixture");
    let out = dir.path().join("report");
    let result = analyze(&input, &out, &["--run-timeout", "0"]);
    let report_path = out.join("report.json");
    if report_path.exists() {
        let report: aa_core::Report = serde_json::from_slice(&std::fs::read(report_path).expect("report file")).expect("valid report");
        assert_eq!(result.status.code(), Some(2), "{}", String::from_utf8_lossy(&result.stderr));
        assert!(report.coverage.truncated || report.coverage.content_lost > 0);
        assert!(report.limitations.iter().any(|l| l.code == "cancelled"));
    } else {
        assert_eq!(result.status.code(), Some(1));
    }
    assert!(String::from_utf8_lossy(&result.stderr).contains("whole analysis timeout reached"));
}
