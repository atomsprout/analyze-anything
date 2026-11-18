use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use aa_core::{InputKind, Report};
use aa_engine::{Limits, NoProgress, Options, analyze};

fn run(path: &Path, options: &Options) -> Report {
    analyze(path, options, &mut NoProgress).expect("the input is readable")
}

/// Bytes that no type detector recognises and that use every value equally.
fn noise(length: usize) -> Vec<u8> {
    // A fixed linear congruential generator: the same bytes on every run.
    let mut state = 0x2545_f491u32;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((state >> 24) as u8);
    }
    bytes[..4].copy_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    bytes
}

fn folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("b.txt"), "hello\n").expect("write");
    std::fs::write(dir.path().join("a.bin"), noise(16 * 1024)).expect("write");
    std::fs::write(dir.path().join("sub/empty"), b"").expect("write");
    // The first bytes of a Windows executable, under a picture's name.
    let mut exe = b"MZ".to_vec();
    exe.resize(256, 0);
    std::fs::write(dir.path().join("sub/photo.jpg"), exe).expect("write");
    dir
}

#[test]
fn single_file_has_known_digests() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("abc.txt");
    std::fs::write(&path, "abc").expect("write");
    let report = run(&path, &Options::default());

    assert_eq!(report.input.kind, InputKind::File);
    assert_eq!(report.input.name, "abc.txt");
    let artifact = &report.artifacts[0];
    let digests = artifact.digests.as_ref().expect("digests");
    // Published test vectors for the string "abc".
    assert_eq!(digests.md5, "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(digests.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(digests.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(report.input.sha256.as_deref(), Some(digests.sha256.as_str()));
    assert_eq!(artifact.size, 3);
    assert_eq!(artifact.detected.as_ref().expect("type").mime, "text/plain");
    assert!(report.findings.is_empty());
    assert!(!report.coverage.truncated);
}

#[test]
fn folder_is_listed_in_sorted_order_with_findings() {
    let dir = folder();
    let report = run(dir.path(), &Options::default());

    let paths: Vec<&str> = report.artifacts.iter().map(|a| a.path.as_str()).collect();
    assert_eq!(paths, ["a.bin", "b.txt", "sub/empty", "sub/photo.jpg"]);
    assert_eq!(report.coverage.artifacts_total, 4);
    assert_eq!(report.coverage.artifacts_analyzed, 4);
    assert_eq!(report.input.sha256, None);

    let empty = &report.artifacts[2];
    assert_eq!(empty.entropy, None, "an empty file has no entropy, not zero");
    assert_eq!(empty.detected.as_ref().expect("type").mime, "application/x-empty");

    let rules: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["content.executable-disguised", "content.high-entropy"]);
    assert_eq!(report.findings[0].evidence[0].artifact, "sub/photo.jpg");
    assert_eq!(report.findings[1].evidence[0].artifact, "a.bin");
    assert!(report.findings.iter().all(|f| f.id.len() == 64));
}

#[test]
fn same_input_gives_byte_identical_report() {
    let dir = folder();
    let first = serde_json::to_string(&run(dir.path(), &Options::default())).expect("json");
    let second = serde_json::to_string(&run(dir.path(), &Options::default())).expect("json");
    assert_eq!(first, second);
    assert!(!first.contains(dir.path().to_string_lossy().as_ref()), "the report must not hold the location on disk");
}

#[test]
fn file_limit_is_reported_not_silent() {
    let dir = folder();
    let options = Options { limits: Limits { max_files: 2, ..Limits::default() }, ..Options::default() };
    let report = run(dir.path(), &options);
    assert_eq!(report.artifacts.len(), 2);
    assert!(report.coverage.truncated);
    assert!(report.limitations.iter().any(|l| l.code == "limit_reached"));
}

#[test]
fn byte_limit_stops_the_run_and_says_so() {
    let dir = folder();
    let options = Options { limits: Limits { max_total_bytes: 1, ..Limits::default() }, ..Options::default() };
    let report = run(dir.path(), &options);
    assert_eq!(report.artifacts.len(), 1, "the first file is read, then the limit applies");
    assert!(report.coverage.truncated);
    assert!(report.limitations.iter().any(|l| l.code == "limit_reached"));
}

#[test]
fn cancelled_run_returns_what_was_done() {
    let dir = folder();
    let options = Options { cancel: Some(Arc::new(AtomicBool::new(true))), ..Options::default() };
    let report = run(dir.path(), &options);
    assert!(report.artifacts.is_empty());
    assert!(report.coverage.truncated);
    assert_eq!(report.limitations[0].code, "cancelled");
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_not_followed() {
    let dir = folder();
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link")).expect("symlink");
    let report = run(dir.path(), &Options::default());
    assert!(report.artifacts.iter().all(|a| a.path != "link"));
    assert!(report.limitations.iter().any(|l| l.code == "symlink_skipped" && l.artifact.as_deref() == Some("link")));
}

#[test]
fn missing_input_is_an_error() {
    assert!(analyze(Path::new("/no/such/input"), &Options::default(), &mut NoProgress).is_err());
}
