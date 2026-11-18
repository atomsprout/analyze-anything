use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, InputKind, Report};
use aa_engine::{Limits, NoProgress, Options, Registry, analyze, analyze_with};

fn run(path: &Path, options: &Options) -> Report {
    analyze(path, options, &mut NoProgress).expect("the input is readable")
}

fn limits(change: impl FnOnce(&mut Limits)) -> Options {
    let mut limits = Limits::default();
    change(&mut limits);
    Options { limits, ..Options::default() }
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

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        writer.start_file(*name, options).expect("start entry");
        writer.write_all(data).expect("write entry");
    }
    writer.finish().expect("finish zip").into_inner()
}

fn tar_gz_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()));
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, *data).expect("append");
    }
    builder.into_inner().expect("finish tar").finish().expect("finish gzip")
}

fn folder() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("b.txt"), "hello https://example.com/x\n").expect("write");
    std::fs::write(dir.path().join("a.bin"), noise(16 * 1024)).expect("write");
    std::fs::write(dir.path().join("sub/empty"), b"").expect("write");
    // The first bytes of a Windows executable, under a picture's name.
    let mut exe = b"MZ".to_vec();
    exe.resize(256, 0);
    std::fs::write(dir.path().join("sub/photo.jpg"), exe).expect("write");
    dir
}

fn write_input(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("write");
    (dir, path)
}

fn paths(report: &Report) -> Vec<&str> {
    report.artifacts.iter().map(|a| a.path.as_str()).collect()
}

fn codes(report: &Report) -> Vec<&str> {
    report.limitations.iter().map(|l| l.code.as_str()).collect()
}

#[test]
fn single_file_has_known_digests() {
    let (_dir, path) = write_input("abc.txt", b"abc");
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
    assert_eq!(artifact.mime(), "text/plain");
    assert!(report.findings.is_empty());
    assert!(!report.coverage.truncated);
}

#[test]
fn folder_is_listed_in_sorted_order_with_findings() {
    let dir = folder();
    let report = run(dir.path(), &Options::default());

    assert_eq!(paths(&report), ["a.bin", "b.txt", "sub/empty", "sub/photo.jpg"]);
    assert_eq!(report.coverage.artifacts_total, 4);
    assert_eq!(report.coverage.artifacts_analyzed, 4);
    assert_eq!(report.input.sha256, None);

    let empty = &report.artifacts[2];
    assert_eq!(empty.entropy, None, "an empty file has no entropy, not zero");
    assert_eq!(empty.mime(), "application/x-empty");

    let rules: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["content.hosts", "content.executable-disguised", "content.high-entropy"]);
    assert!(report.findings.iter().all(|f| f.id.len() == 64));
    assert_eq!(report.summary["content.hosts"]["hosts"][0]["host"], "example.com");
}

#[test]
fn every_rule_and_code_in_a_report_has_text() {
    let dir = folder();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/hostname", dir.path().join("link")).expect("symlink");
    let report = run(dir.path(), &limits(|l| l.max_files = 3));
    for id in report.findings.iter().map(|f| &f.rule).chain(report.limitations.iter().map(|l| &l.code)) {
        let text = report.rules.get(id).unwrap_or_else(|| panic!("no text for {id}"));
        assert!(!text.title_zh.is_empty() && !text.title_en.is_empty() && !text.text_zh.is_empty() && !text.text_en.is_empty());
    }
    assert!(!report.limitations.is_empty());
}

#[test]
fn same_input_gives_byte_identical_report() {
    let dir = folder();
    std::fs::write(dir.path().join("c.zip"), zip_of(&[("x/y.txt", b"y"), ("z.bin", &noise(8192))])).expect("write");
    let first = serde_json::to_string(&run(dir.path(), &Options::default())).expect("json");
    let second = serde_json::to_string(&run(dir.path(), &Options::default())).expect("json");
    assert_eq!(first, second);
    assert!(!first.contains(dir.path().to_string_lossy().as_ref()), "the report must not hold the location on disk");
    assert!(!first.contains("analyze-anything-"), "the report must not hold temporary paths");
}

#[test]
fn zip_is_unpacked_into_children() {
    let (_dir, path) =
        write_input("pack.zip", &zip_of(&[("docs/readme.txt", b"see https://inner.example.org/"), ("data.bin", b"\x00\x01")]));
    let report = run(&path, &Options::default());

    assert_eq!(paths(&report), ["pack.zip", "pack.zip/data.bin", "pack.zip/docs/readme.txt"]);
    assert_eq!(report.artifacts[0].kind.as_deref(), Some("zip"));
    assert_eq!(report.artifacts[0].unpacked_by.as_deref(), Some("zip"));
    assert_eq!(report.artifacts[2].parent.as_deref(), Some("pack.zip"));
    assert_eq!(report.artifacts[2].size, 30);
    assert_eq!(report.coverage.containers_unpacked, 1);
    assert_eq!(report.summary["content.hosts"]["hosts"][0]["host"], "inner.example.org");
    assert!(report.limitations.is_empty());
}

#[test]
fn nested_containers_are_opened_all_the_way_down() {
    let inner = zip_of(&[("deep.txt", b"deep")]);
    let middle = tar_gz_of(&[("inner.zip", &inner), ("note.txt", b"n")]);
    let (_dir, path) = write_input("outer.zip", &zip_of(&[("middle.tar.gz", &middle)]));
    let report = run(&path, &Options::default());

    assert_eq!(
        paths(&report),
        [
            "outer.zip",
            "outer.zip/middle.tar.gz",
            "outer.zip/middle.tar.gz/middle.tar",
            "outer.zip/middle.tar.gz/middle.tar/inner.zip",
            "outer.zip/middle.tar.gz/middle.tar/inner.zip/deep.txt",
            "outer.zip/middle.tar.gz/middle.tar/note.txt",
        ]
    );
    assert_eq!(report.coverage.containers_unpacked, 4);
    assert!(!report.coverage.truncated);
}

#[test]
fn depth_limit_stops_unpacking_and_says_so() {
    let inner = zip_of(&[("deep.txt", b"deep")]);
    let (_dir, path) = write_input("outer.zip", &zip_of(&[("inner.zip", &inner)]));
    let report = run(&path, &limits(|l| l.max_depth = 1));

    assert_eq!(paths(&report), ["outer.zip", "outer.zip/inner.zip"]);
    assert_eq!(report.artifacts[1].kind.as_deref(), Some("zip"), "the format is still recognised");
    assert_eq!(report.artifacts[1].unpacked_by, None);
    assert_eq!(codes(&report), ["depth_limit"]);
    assert!(report.coverage.truncated);
}

#[test]
fn compression_bomb_is_cut_off_by_the_budget() {
    // 64 MiB of zeros compresses to a few kilobytes.
    let zeros = vec![0u8; 64 * 1024 * 1024];
    let (_dir, path) = write_input("bomb.zip", &zip_of(&[("a", &zeros), ("b", &zeros), ("small.txt", b"ok")]));

    let report = run(&path, &limits(|l| l.max_unpacked_bytes = 1024 * 1024));
    assert_eq!(paths(&report), ["bomb.zip"], "nothing beyond the total budget is kept");
    assert!(report.coverage.truncated);
    assert_eq!(codes(&report), ["limit_reached"]);

    let report = run(&path, &limits(|l| l.max_entry_bytes = 1024 * 1024));
    assert_eq!(paths(&report), ["bomb.zip", "bomb.zip/small.txt"], "oversized entries are skipped, the rest is kept");
    assert_eq!(codes(&report), ["limit_reached", "limit_reached"]);
    assert!(report.coverage.truncated);
}

#[test]
fn entry_names_cannot_escape_the_container() {
    let (_dir, path) = write_input("evil.zip", &zip_of(&[("../../outside.txt", b"x"), ("/abs/path.txt", b"y"), ("ok\\win.txt", b"z")]));
    let report = run(&path, &Options::default());

    assert_eq!(paths(&report), ["evil.zip", "evil.zip/abs/path.txt", "evil.zip/ok/win.txt"]);
    assert_eq!(codes(&report), ["unsafe_path"]);
    assert_eq!(report.limitations[0].detail.as_deref(), Some("../../outside.txt"));
}

#[test]
fn duplicate_entry_names_are_both_kept() {
    let (_dir, path) = write_input("dup.tar.gz", &tar_gz_of(&[("a.txt", b"first"), ("a.txt", b"second")]));
    let report = run(&path, &Options::default());
    assert_eq!(paths(&report), ["dup.tar.gz", "dup.tar.gz/dup.tar", "dup.tar.gz/dup.tar/a.txt", "dup.tar.gz/dup.tar/a.txt (2)"]);
    assert_eq!(report.artifacts[2].size, 5);
    assert_eq!(report.artifacts[3].size, 6);
}

#[test]
fn damaged_archive_is_reported_not_fatal() {
    let mut bytes = zip_of(&[("a.txt", b"hello")]);
    bytes.truncate(bytes.len() - 10);
    let (_dir, path) = write_input("broken.zip", &bytes);
    let report = run(&path, &Options::default());
    assert_eq!(paths(&report), ["broken.zip"]);
    assert_eq!(report.artifacts[0].kind.as_deref(), Some("zip"));
    assert_eq!(codes(&report), ["unpack_failed"]);
}

#[test]
fn file_limit_is_reported_not_silent() {
    let dir = folder();
    let report = run(dir.path(), &limits(|l| l.max_files = 2));
    assert_eq!(report.artifacts.len(), 2);
    assert!(report.coverage.truncated);
    assert!(codes(&report).contains(&"limit_reached"));
}

#[test]
fn file_limit_counts_unpacked_files_too() {
    let (_dir, path) = write_input("many.zip", &zip_of(&[("1", b"a"), ("2", b"b"), ("3", b"c"), ("4", b"d")]));
    let report = run(&path, &limits(|l| l.max_files = 3));
    assert_eq!(paths(&report), ["many.zip", "many.zip/1", "many.zip/2"]);
    assert_eq!(codes(&report), ["limit_reached"]);
}

#[test]
fn byte_limit_stops_the_run_and_says_so() {
    let dir = folder();
    let report = run(dir.path(), &limits(|l| l.max_total_bytes = 1));
    assert_eq!(report.artifacts.len(), 1, "the first file is read, then the limit applies");
    assert!(report.coverage.truncated);
    assert_eq!(codes(&report), ["limit_reached"]);
}

#[test]
fn cancelled_run_returns_what_was_done() {
    let dir = folder();
    let options = Options { cancel: Some(Arc::new(AtomicBool::new(true))), ..Options::default() };
    let report = run(dir.path(), &options);
    assert!(report.artifacts.is_empty());
    assert!(report.coverage.truncated);
    assert_eq!(codes(&report), ["cancelled"]);
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

struct Panics;

impl Analyzer for Panics {
    fn id(&self) -> &'static str {
        "panics"
    }

    fn rules(&self) -> &'static [Rule] {
        &[]
    }

    fn analyze_file(&self, _tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        out.kind(file, "must-not-be-kept");
        if file.path == "b.txt" {
            panic!("boom");
        }
    }

    fn analyze_tree(&self, _tree: &dyn Tree, _out: &mut Output) {
        panic!("tree boom");
    }
}

#[test]
fn a_failing_analyzer_does_not_stop_the_run() {
    let dir = folder();
    let mut registry = Registry::standard();
    registry.analyzers.insert(0, Box::new(Panics));
    // The panic message would otherwise be printed by the default hook.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let report = analyze_with(&registry, dir.path(), &Options::default(), &mut NoProgress).expect("readable");
    std::panic::set_hook(hook);

    assert_eq!(codes(&report), ["analyzer_failed", "analyzer_failed"]);
    assert_eq!(report.limitations[0].detail.as_deref(), Some("panics: tree boom"));
    assert_eq!(report.limitations[1].artifact.as_deref(), Some("b.txt"));
    assert_eq!(report.limitations[1].detail.as_deref(), Some("panics: boom"));
    let b = report.artifacts.iter().find(|a| a.path == "b.txt").expect("b.txt");
    assert_eq!(b.kind, None, "output of a failed call is discarded whole");
    assert!(report.findings.iter().any(|f| f.rule == "content.hosts"), "other analyzers still ran");
}
