use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, InputKind, Report};
use aa_engine::{Event, Limits, NoProgress, Options, ProgressSink, Registry, analyze, analyze_session, analyze_with, sweep_stale};

fn run(path: &Path, options: &Options) -> Report {
    analyze(path, options, &mut NoProgress).expect("the input is readable")
}

fn limits(change: impl FnOnce(&mut Limits)) -> Options {
    let mut limits = Limits::default();
    change(&mut limits);
    Options { limits, ..Options::default() }
}

const ROOT_INF: &[u8] = br#"[Version]
Signature="$Windows NT$"
[SourceDisksFiles]
a.sys=1,\amd64,5
[SourceDisksNames]
1=Media,,,\dist
"#;

fn root_options(inf: &str, root: &str) -> Options {
    Options { windows_source_roots: vec![aa_engine::WindowsSourceRoot { inf: inf.into(), root: root.into() }], ..Options::default() }
}

#[test]
fn explicit_windows_distribution_roots_map_only_supplied_bytes_and_preserve_default_behavior() {
    let dir = tempfile::tempdir().expect("input folder");
    std::fs::create_dir_all(dir.path().join("meta")).expect("INF directory");
    std::fs::create_dir_all(dir.path().join("dist/amd64")).expect("source directory");
    std::fs::write(dir.path().join("meta/driver.inf"), ROOT_INF).expect("source INF");
    std::fs::write(dir.path().join("dist/amd64/a.sys"), b"bytes").expect("unexecuted payload");
    let plain = run(dir.path(), &Options::default());
    assert!(plain.artifacts.iter().all(|a| !a.facts.contains_key("windows.source-files")));
    let options = root_options("meta/DRIVER.inf", ".");
    let report = run(dir.path(), &options);
    let mapping = &report.artifacts.iter().find(|a| a.path == "meta/driver.inf").expect("INF").facts["windows.source-files"];
    assert_eq!(mapping["basis"], "caller-declared-logical-distribution-root");
    assert_eq!(mapping["records"][0]["target"], "dist/amd64/a.sys");
    assert_eq!(mapping["records"][0]["size_agreement"], true);
    assert!(report.findings.iter().any(|f| f.rule == "windows.inf-source-files" && !f.evidence.is_empty()));
    assert_eq!(serde_json::to_vec(&report).expect("report JSON"), serde_json::to_vec(&run(dir.path(), &options)).expect("repeat JSON"));
    assert_eq!(std::fs::read(dir.path().join("dist/amd64/a.sys")).expect("input unchanged"), b"bytes");
    let invalid = run(dir.path(), &root_options("meta/driver.inf", "C:/private-marker"));
    assert!(invalid.limitations.iter().any(|l| l.code == "engine.windows-source-roots-invalid"));
    assert!(!serde_json::to_string(&invalid).expect("invalid settings report").contains("private-marker"));
    let invalid_size = String::from_utf8(ROOT_INF.to_vec()).expect("ASCII fixture").replace(",5", ",unknown-size");
    std::fs::write(dir.path().join("meta/driver.inf"), invalid_size).expect("unsupported size declaration");
    let report = run(dir.path(), &options);
    let source = report.artifacts.iter().find(|a| a.path == "meta/driver.inf").expect("INF");
    assert_eq!(source.facts["windows.source-files"]["records"][0]["size_check"], "unsupported-size-declaration");
    assert!(report.findings.iter().any(|f| f.rule == "windows.inf-source-files"), "path association is separate from size interpretation");
    assert!(report.limitations.iter().any(|l| l.code == "windows.source-files-unresolved"));
}

#[test]
fn windows_distribution_roots_respect_archive_namespaces_missing_paths_and_directory_aliases() {
    let dir = tempfile::tempdir().expect("input folder");
    let zip = zip_of(&[("meta/driver.inf", ROOT_INF), ("dist/amd64/a.sys", b"bytes")]);
    let path = dir.path().join("pkg.zip");
    std::fs::write(&path, zip).expect("archive");
    let report = run(&path, &root_options("pkg.zip/meta/driver.inf", "pkg.zip"));
    let source = report.artifacts.iter().find(|a| a.path.ends_with("/driver.inf")).expect("INF child");
    assert_eq!(source.facts["windows.source-files"]["records"][0]["target"], "pkg.zip/dist/amd64/a.sys");
    let wrong = run(&path, &root_options("pkg.zip/meta/driver.inf", "."));
    assert!(!wrong.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
    let inner = zip_of(&[("meta/driver.inf", ROOT_INF), ("dist/amd64/a.sys", b"bytes")]);
    let nested = dir.path().join("nested.zip");
    std::fs::write(&nested, zip_of(&[("inner.zip", &inner)])).expect("nested container");
    let nested_report = run(&nested, &root_options("nested.zip/inner.zip/meta/driver.inf", "nested.zip/inner.zip"));
    assert!(nested_report.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
    let crossed = run(&nested, &root_options("nested.zip/inner.zip/meta/driver.inf", "nested.zip"));
    assert!(!crossed.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
    for extra in ["Meta/other.bin", "Dist/other.bin"] {
        let zip = zip_of(&[("meta/driver.inf", ROOT_INF), ("dist/amd64/a.sys", b"bytes"), (extra, b"alias")]);
        std::fs::write(&path, zip).expect("case-sensitive archive names");
        let aliases = run(&path, &root_options("pkg.zip/meta/driver.inf", "pkg.zip"));
        assert!(!aliases.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
        assert!(aliases.limitations.iter().any(|l| l.code == "windows.source-files-unresolved"));
    }
    let zip = zip_of(&[("meta/driver.inf", ROOT_INF), ("dist/amd64/other.bin", b"directory present")]);
    std::fs::write(&path, zip).expect("missing source archive");
    let missing = run(&path, &root_options("pkg.zip/meta/driver.inf", "pkg.zip"));
    let source = missing.artifacts.iter().find(|a| a.path.ends_with("/driver.inf")).expect("INF child");
    assert_eq!(source.facts["windows.source-files"]["records"][0]["status"], "not-supplied-at-candidate-path");
    assert!(!missing.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
}

#[test]
fn partial_input_listing_cannot_establish_a_missing_declared_source() {
    let dir = tempfile::tempdir().expect("input folder");
    std::fs::write(dir.path().join("driver.inf"), ROOT_INF).expect("INF");
    std::fs::write(dir.path().join("z.bin"), b"not a source").expect("second input");
    let mut options = root_options("driver.inf", ".");
    options.limits.max_files = 1;
    let report = run(dir.path(), &options);
    assert!(!report.findings.iter().any(|f| f.rule == "windows.inf-source-files"));
    let source = report.artifacts.iter().find(|a| a.path == "driver.inf").expect("first input");
    let records = source.facts["windows.source-files"]["records"].as_array().expect("unresolved mappings");
    assert!(records.iter().all(|r| r["status"] == "unresolved"));
    assert!(records.iter().any(|r| r["reason"] == "input-listing-completeness-not-established"));
}

#[test]
fn windows_source_mapping_bounds_candidate_attempts_and_output_independently() {
    for (count, subdirectory) in [(300, "".to_string()), (200, std::iter::repeat_n("a".repeat(126), 32).collect::<Vec<_>>().join("\\"))] {
        let dir = tempfile::tempdir().expect("bounded fixture");
        let mut text = String::from("[Version]\nSignature=\"$Windows NT$\"\n[SourceDisksFiles]\n");
        for index in 0..count {
            text.push_str(&format!("a{index}.sys=1,{subdirectory}\n"));
        }
        text.push_str("[SourceDisksNames]\n");
        for _ in 0..16 {
            text.push_str("1=Media\n");
        }
        std::fs::write(dir.path().join("driver.inf"), text).expect("declarations");
        let report = run(dir.path(), &root_options("driver.inf", "."));
        let source = report.artifacts.iter().find(|a| a.path == "driver.inf").expect("INF");
        let mapping = &source.facts["windows.source-files"];
        assert_eq!(mapping["truncated"], true);
        let records = mapping["records"].as_array().expect("bounded mapping records");
        assert!(records.len() <= 4096);
        assert!(records.iter().map(|r| serde_json::to_vec(r).expect("mapping JSON").len()).sum::<usize>() <= 4 * 1024 * 1024);
        assert!(report.limitations.iter().any(|l| l.code == "windows.source-files-limit"));
    }
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

fn relative_shortcut(path: &str) -> Vec<u8> {
    let mut bytes = vec![0; 76];
    bytes[..20].copy_from_slice(&[0x4c, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
    bytes[20..24].copy_from_slice(&0x88u32.to_le_bytes());
    let units: Vec<_> = path.encode_utf16().collect();
    bytes.extend((units.len() as u16).to_le_bytes());
    bytes.extend(units.into_iter().flat_map(u16::to_le_bytes));
    bytes.extend([0; 4]);
    bytes
}

#[test]
fn supplied_shortcut_references_are_scoped_deterministic_and_do_not_add_host_files() {
    let link = relative_shortcut(r"..\bin\TOOL.exe");
    let pack = zip_of(&[("shortcuts/launch.lnk", &link), ("bin/tool.exe", b"supplied payload")]);
    let (_dir, path) = write_input("package.zip", &pack);
    let report = run(&path, &Options::default());
    let source = report.artifacts.iter().find(|a| a.path == "package.zip/shortcuts/launch.lnk").expect("shortcut");
    let reference = &source.facts["windows.input-references"]["references"][0];
    assert_eq!(reference["target"], "package.zip/bin/tool.exe");
    assert_eq!(reference["target_sha256"], aa_core::sha256_hex(b"supplied payload"));
    assert_eq!(report.artifacts.len(), 3);
    let finding = report.findings.iter().find(|f| f.rule == "windows.input-reference").expect("relationship finding");
    assert_eq!(finding.evidence.len(), 2);
    assert_eq!(finding.evidence[1].artifact, "package.zip/bin/tool.exe");
    assert!(report.limitations.iter().any(|l| l.code == "windows.shortcut-target-unresolved"));
    for id in report.findings.iter().map(|f| &f.rule).chain(report.limitations.iter().map(|l| &l.code)) {
        let rule = report.rules.get(id).expect("rule wording");
        assert!(!rule.text_en.is_empty() && !rule.text_zh.is_empty());
    }
    assert_eq!(
        serde_json::to_vec(&report).expect("first report"),
        serde_json::to_vec(&run(&path, &Options::default())).expect("second report")
    );
    assert_eq!(std::fs::read(&path).expect("unchanged archive"), pack);
}

#[test]
fn archive_collisions_and_normalized_names_cannot_create_false_unique_shortcut_targets() {
    let link = relative_shortcut("same.txt");
    let copied = relative_shortcut("same.txt (2)");
    let bytes = tar_gz_of(&[("launch.lnk", &link), ("copied.lnk", &copied), ("same.txt", b"one"), ("same.txt", b"two")]);
    let (_dir, path) = write_input("collision.tar.gz", &bytes);
    let report = run(&path, &Options::default());
    assert!(!report.findings.iter().any(|f| f.rule == "windows.input-reference"));
    let targets: Vec<_> = report.artifacts.iter().filter(|a| a.name().starts_with("same.txt")).collect();
    assert_eq!(targets.len(), 2);
    assert!(targets.iter().all(|a| a.facts["engine.entry-name"]["colliding"] == true));
    let source = report.artifacts.iter().find(|a| a.name() == "launch.lnk").expect("shortcut");
    assert_eq!(source.facts["windows.input-references"]["references"][0]["status"], "unresolved");

    let pack = zip_of(&[("launch.lnk", &link), ("./same.txt", b"one")]);
    let (_dir, path) = write_input("normalized.zip", &pack);
    let report = run(&path, &Options::default());
    assert!(!report.findings.iter().any(|f| f.rule == "windows.input-reference"));
    let target = report.artifacts.iter().find(|a| a.name() == "same.txt").expect("normalized entry preserved");
    assert_eq!(target.facts["engine.entry-name"]["normalized"], true);
}

#[test]
fn partial_input_or_container_listings_do_not_establish_unique_targets() {
    let dir = tempfile::tempdir().expect("listing fixture");
    let link = relative_shortcut("target.exe");
    std::fs::write(dir.path().join("a.lnk"), &link).expect("shortcut");
    std::fs::write(dir.path().join("target.exe"), b"payload").expect("target");
    std::fs::write(dir.path().join("zz-extra"), b"not listed").expect("additional input");
    let report = run(dir.path(), &limits(|limits| limits.max_files = 2));
    assert_eq!(report.artifacts.len(), 2);
    assert_eq!(report.summary["engine.input-listing"]["complete"], false);
    assert!(!report.findings.iter().any(|f| f.rule == "windows.input-reference"));
    let source = report.artifacts.iter().find(|a| a.name() == "a.lnk").expect("listed shortcut");
    assert_eq!(source.facts["windows.input-references"]["references"][0]["reason"], "input-listing-completeness-not-established");

    let bytes = zip_of(&[("a.lnk", &link), ("target.exe", b"payload"), ("zz-extra", b"not unpacked")]);
    let (_dir, path) = write_input("partial.zip", &bytes);
    let report = run(&path, &limits(|limits| limits.max_files = 3));
    assert_eq!(report.artifacts.len(), 3);
    assert_eq!(report.artifacts[0].facts["engine.container-listing"]["complete"], false);
    assert!(!report.findings.iter().any(|f| f.rule == "windows.input-reference"));
    let source = report.artifacts.iter().find(|a| a.name() == "a.lnk").expect("unpacked shortcut");
    assert_eq!(source.facts["windows.input-references"]["references"][0]["reason"], "container-listing-completeness-not-established");
}

#[test]
fn an_unrelated_broken_container_does_not_hide_a_complete_input_namespace() {
    let dir = tempfile::tempdir().expect("complete folder fixture");
    std::fs::write(dir.path().join("a.lnk"), relative_shortcut("target.exe")).expect("shortcut");
    std::fs::write(dir.path().join("target.exe"), b"payload").expect("target");
    std::fs::write(dir.path().join("broken.zip"), b"PK\x03\x04broken").expect("damaged container");
    let report = run(dir.path(), &Options::default());
    assert!(report.limitations.iter().any(|l| l.code == "unpack_failed"));
    assert_eq!(report.summary["engine.input-listing"]["complete"], true);
    assert!(report.findings.iter().any(|f| f.rule == "windows.input-reference"));
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
    let rules: Vec<&str> = report.findings.iter().map(|f| f.rule.as_str()).collect();
    assert_eq!(rules, ["overview.kind-file", "overview.attention-none", "structure.totals"]);
    assert!(!report.coverage.truncated);
}

#[test]
fn shortcut_credentials_do_not_leak_through_generic_content_facts() {
    let bytes = b"[InternetShortcut]\nURL=https://user:fixture-password@example.invalid/?token=fixture-token&ok=1\n";
    let (_dir, path) = write_input("private.url", bytes);
    let report = run(&path, &Options::default());
    let serialized = serde_json::to_string(&report).expect("complete report JSON");
    for secret in ["fixture-password", "fixture-token"] {
        assert!(!serialized.contains(secret), "credential leaked into report");
    }
    assert!(serialized.contains("example.invalid"));
    assert!(report.artifacts[0].facts.contains_key("windows.internet-shortcut"));
    assert!(report.artifacts[0].facts.contains_key("content.urls"));
    assert_eq!(std::fs::read(&path).expect("input remains readable"), bytes);
    assert_eq!(serialized, serde_json::to_string(&run(&path, &Options::default())).expect("second report"));
}

#[test]
fn registry_reports_preserve_declarations_and_redact_named_credentials() {
    let bytes = b"Windows Registry Editor Version 5.00\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n\"Fixture\"=\"%SystemRoot%\\\\fixture.exe\"\n\"Password\"=\"fixture secret with spaces\"\n\"Old\"=-\n";
    let (_dir, path) = write_input("fixture.reg", bytes);
    let report = run(&path, &Options::default());
    assert!(report.findings.iter().any(|f| f.rule == "overview.kind-registry-export"));
    assert!(report.findings.iter().any(|f| f.rule == "windows.registry-autostart"));
    let json = serde_json::to_string(&report).expect("registry report");
    assert!(!json.contains("fixture secret"));
    assert!(json.contains("%SystemRoot%"));
    assert!(json.contains("delete_value"));
    for code in report.findings.iter().map(|f| &f.rule).chain(report.limitations.iter().map(|l| &l.code)) {
        let rule = report.rules.get(code).expect("rule included in report");
        assert!(!rule.text_en.is_empty() && !rule.text_zh.is_empty());
    }
    assert_eq!(json, serde_json::to_string(&run(&path, &Options::default())).expect("repeat report"));
    assert_eq!(std::fs::read(&path).expect("input bytes"), bytes);
}

#[test]
fn task_xml_reports_are_deterministic_redacted_and_never_add_referenced_files() {
    let bytes = br#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Principals><Principal id="fixture"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals><Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers><Actions Context="fixture"><Exec><Command>\\server\share\outside.exe</Command><Arguments>--password 'fixture secret with spaces' https://user:fixture-password@example.invalid/?token=fixture-token</Arguments></Exec></Actions></Task>"#;
    let (_dir, path) = write_input("fixture.xml", bytes);
    let report = run(&path, &Options::default());
    assert_eq!(report.artifacts.len(), 1, "references do not become new inputs");
    assert!(report.findings.iter().any(|f| f.rule == "overview.kind-scheduled-task"));
    assert!(report.findings.iter().any(|f| f.rule == "windows.task-highest-available"));
    assert!(report.findings.iter().any(|f| f.rule == "windows.task-startup-trigger"));
    let serialized = serde_json::to_string(&report).expect("task report");
    for secret in ["fixture secret", "fixture-password", "fixture-token"] {
        assert!(!serialized.contains(secret));
    }
    for id in report.findings.iter().map(|f| &f.rule).chain(report.limitations.iter().map(|l| &l.code)) {
        let rule = report.rules.get(id).expect("translated rule in report");
        assert!(!rule.text_en.is_empty() && !rule.text_zh.is_empty());
    }
    assert_eq!(serialized, serde_json::to_string(&run(&path, &Options::default())).expect("second report"));
    assert_eq!(std::fs::read(&path).expect("original input bytes"), bytes);
}

#[test]
fn shell_link_reports_are_deterministic_and_have_translated_rules() {
    let bytes = include_bytes!("../../aa-windows/tests/data/native.lnk");
    let (_dir, path) = write_input("native.lnk", bytes);
    let report = run(&path, &Options::default());
    assert!(report.findings.iter().any(|f| f.rule == "overview.kind-shell-link"));
    assert!(report.findings.iter().any(|f| f.rule == "windows.shell-link" && !f.evidence.is_empty()));
    assert!(report.limitations.iter().any(|l| l.code == "windows.shortcut-target-unresolved"));
    for code in report.findings.iter().map(|f| f.rule.as_str()).chain(report.limitations.iter().map(|l| l.code.as_str())) {
        let rule = report.rules.get(code).expect("report includes rule wording");
        assert!(!rule.text_en.is_empty() && !rule.text_zh.is_empty());
    }
    assert_eq!(serde_json::to_vec(&report).expect("report"), serde_json::to_vec(&run(&path, &Options::default())).expect("second report"));
    assert_eq!(std::fs::read(&path).expect("unchanged input"), bytes);
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
    assert_eq!(
        rules,
        [
            "overview.kind-folder",
            "overview.attention",
            "structure.totals",
            "structure.by-type",
            "structure.largest",
            "content.hosts",
            "content.executable-disguised",
            "content.high-entropy"
        ]
    );
    assert_eq!(report.summary["structure.totals"]["files"], 4);
    assert_eq!(report.summary["structure.largest"][0]["path"], "a.bin");
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
    let totals = &report.summary["structure.totals"];
    assert_eq!(totals["max_depth"], 4);
    assert_eq!(totals["files"], 2, "only deep.txt and note.txt are content; the rest are containers");
    assert_eq!(totals["bytes"], 5);
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
    assert!(!report.summary.contains_key("structure.duplicates"), "same name, different content");
    assert!(codes(&report).contains(&"engine.entry-name-collision"));
    assert_eq!(report.coverage.content_lost, 0, "ambiguity does not mean either byte stream was lost");
}

#[test]
fn supervisors_refuse_scratch_storage_inside_the_input_before_creating_it() {
    let dir = tempfile::tempdir().expect("private fixture root");
    let input = dir.path().join("input");
    std::fs::create_dir(&input).expect("input directory");
    let scratch = input.join("new").join("scratch");
    assert!(aa_engine::validate_scratch_root(&input, &scratch).is_err());
    assert!(!input.join("new").exists(), "validation must not write inside the input");
    let missing = dir.path().join("missing");
    assert!(aa_engine::validate_scratch_root(&missing, &missing.join("scratch")).is_err());
    assert!(aa_engine::validate_scratch_root(&input, &dir.path().join("missing").join("..").join("input").join("scratch")).is_err());
    assert!(aa_engine::validate_scratch_root(&input, &dir.path().join("external")).is_ok());
    let file = input.join("file.txt");
    std::fs::write(&file, "ordinary bytes").expect("input file");
    assert!(aa_engine::validate_scratch_root(&file, &input.join("scratch")).is_ok());
}

#[test]
fn windows_archive_names_are_logical_even_when_spilled_to_disk() {
    let names = ["CON", "case.txt", "CASE.txt", "name.", "name:stream", "C:\\absolute", "same", "same"];
    let mut writer = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default()));
    for (index, name) in names.iter().enumerate() {
        let content = vec![b'A' + index as u8; 300 * 1024];
        let mut header = tar::Header::new_gnu();
        header.set_path("placeholder").expect("ordinary header name");
        // Construct names directly in the format, without asking the host to interpret them.
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        writer.append(&header, content.as_slice()).expect("archive entry");
    }
    let compressed = writer.into_inner().expect("tar finish").finish().expect("gzip finish");
    let (dir, path) = write_input("names.tar.gz", &compressed);
    let scratch = dir.path().join("scratch");
    std::fs::create_dir(&scratch).expect("scratch root");
    let options = Options { temp_root: Some(scratch.clone()), ..Options::default() };
    let session = analyze_session(&Registry::standard(), &path, &options, &mut NoProgress).expect("archive session");
    let expected = ["CON", "case.txt", "CASE.txt", "name.", "name:stream", "C:/absolute", "same", "same (2)"];
    for (index, name) in expected.iter().enumerate() {
        let logical = format!("names.tar.gz/names.tar/{name}");
        assert_eq!(session.read(&logical, 100, 3).expect("logical bytes"), [b'A' + index as u8; 3]);
    }
    let report = session.report();
    assert_eq!(report.coverage.content_lost, 0);
    assert_eq!(report.limitations.iter().filter(|l| l.code == "engine.entry-name-collision").count(), 2);
    let repeat = analyze(&path, &options, &mut NoProgress).expect("repeat analysis");
    assert_eq!(aa_core::canonical_json(report), aa_core::canonical_json(&repeat));
    for folder in std::fs::read_dir(&scratch).expect("scratch listing") {
        for file in std::fs::read_dir(folder.expect("scratch entry").path()).expect("spill listing") {
            let name = file.expect("spill file").file_name();
            let name = name.to_str().expect("internal ASCII names");
            assert!(name == ".lock" || name.bytes().all(|b| b.is_ascii_digit()), "{name}");
        }
    }
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
    assert!(report.findings.is_empty(), "nothing was read, so nothing is concluded");
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
    registry.analyzers.insert(0, Arc::new(Panics));
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

#[test]
fn identical_files_are_grouped() {
    let (_dir, path) = write_input("twins.zip", &zip_of(&[("a/one.bin", &noise(5000)), ("b/two.bin", &noise(5000)), ("c.txt", b"other")]));
    let report = run(&path, &Options::default());
    let duplicates = &report.summary["structure.duplicates"];
    assert_eq!(duplicates["total_groups"], 1);
    assert_eq!(duplicates["wasted_bytes"], 5000);
    assert_eq!(duplicates["groups"][0]["paths"], serde_json::json!(["twins.zip/a/one.bin", "twins.zip/b/two.bin"]));
}

/// Every archive format opens to the same two files, byte for byte, as the system tools packed.
#[test]
fn every_archive_format_unpacks_to_the_original_bytes() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../aa-unpack/tests/data");
    let samples = [
        ("sample.zip", "sample.zip", "zip"),
        ("sample.7z", "sample.7z", "7z"),
        ("sample.tar", "sample.tar", "tar"),
        ("sample.tar.gz", "sample.tar.gz/sample.tar", "gzip"),
        ("sample.tar.bz2", "sample.tar.bz2/sample.tar", "bzip2"),
        ("sample.tar.xz", "sample.tar.xz/sample.tar", "xz"),
        ("sample.tar.zst", "sample.tar.zst/sample.tar", "zstd"),
    ];
    for (file, root, kind) in samples {
        let report = run(&data.join(file), &Options::default());
        assert_eq!(report.artifacts[0].kind.as_deref(), Some(kind), "{file}");
        let sha256 = |path: String| {
            let artifact = report.artifacts.iter().find(|a| a.path == path).unwrap_or_else(|| panic!("{file}: no {path}"));
            artifact.digests.as_ref().expect("digests").sha256.clone()
        };
        // Digests of the two files as `sha256sum` reports them for the originals.
        assert_eq!(sha256(format!("{root}/a.txt")), "a013aeaf2dce832ec132dfbce6afcb4e1a6a6b72a50f76e4a6fe0885b2a7d4e7", "{file}");
        assert_eq!(sha256(format!("{root}/sub/b.bin")), "9a2ef41ddd562fadaa764d10516043d58caf9f5e0b14cd3ff5ac4ff30ab3be11", "{file}");
        assert!(report.limitations.is_empty(), "{file}: {:?}", report.limitations);
    }
}

#[test]
fn bytes_in_memory_give_the_same_report_as_the_file_on_disk() {
    let bytes = zip_of(&[("docs/readme.txt", b"see https://inner.example.org/"), ("data.bin", &noise(9000))]);
    let (_dir, path) = write_input("pack.zip", &bytes);
    let from_disk = run(&path, &Options::default());
    let from_memory = aa_engine::analyze_bytes(&Registry::standard(), "some/dir/pack.zip", bytes, &Options::default(), &mut NoProgress);
    assert_eq!(serde_json::to_string(&from_disk).expect("json"), serde_json::to_string(&from_memory).expect("json"));
}

struct PanickingUnpacker;

impl aa_core::plugin::Unpacker for PanickingUnpacker {
    fn id(&self) -> &'static str {
        "panicking"
    }

    fn unpack(&self, file: &Artifact, _bytes: &[u8], sink: &mut dyn aa_core::plugin::UnpackSink) -> aa_core::plugin::Unpack {
        if file.path != "b.txt" {
            return aa_core::plugin::Unpack::NotMine;
        }
        sink.add("kept.txt", &mut &b"kept"[..]).expect("add");
        panic!("decoder boom");
    }
}

#[test]
fn a_failing_unpacker_does_not_stop_the_run() {
    let dir = folder();
    let mut registry = Registry::standard();
    registry.unpackers.insert(0, Box::new(PanickingUnpacker));
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let report = analyze_with(&registry, dir.path(), &Options::default(), &mut NoProgress).expect("readable");
    std::panic::set_hook(hook);

    assert_eq!(codes(&report), ["unpack_failed"]);
    assert_eq!(report.limitations[0].detail.as_deref(), Some("the unpacker failed: decoder boom"));
    assert!(paths(&report).contains(&"b.txt/kept.txt"), "what was extracted before the failure is kept");
    assert_eq!(report.coverage.artifacts_total, 5);
}

struct Stalls;

impl Analyzer for Stalls {
    fn id(&self) -> &'static str {
        "stalls"
    }

    fn rules(&self) -> &'static [Rule] {
        &[]
    }

    fn analyze_file(&self, _tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.path == "b.txt" {
            // Longer than any test waits; the thread is left behind and ends with the process.
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
        out.fact(file, "stalls.seen", true);
    }
}

#[test]
fn a_stalled_analyzer_is_given_up_on_and_the_run_finishes() {
    let dir = folder();
    let mut registry = Registry::standard();
    registry.analyzers.insert(0, Arc::new(Stalls));
    let started = std::time::Instant::now();
    let report = analyze_with(&registry, dir.path(), &limits(|l| l.analyzer_seconds = 1), &mut NoProgress).expect("readable");
    assert!(started.elapsed() < std::time::Duration::from_secs(60), "the run must not wait for the stalled call");

    assert_eq!(codes(&report), ["analyzer_timeout"]);
    assert_eq!(report.limitations[0].artifact.as_deref(), Some("b.txt"));
    assert_eq!(report.limitations[0].detail.as_deref(), Some("stalls: no result after 1 seconds"));
    assert_eq!(report.coverage.content_lost, 1);
    let fact = |path: &str| report.artifacts.iter().find(|a| a.path == path).and_then(|a| a.facts.get("stalls.seen")).is_some();
    assert!(fact("a.bin") && fact("sub/photo.jpg"), "other files are unaffected");
    assert!(!fact("b.txt"));
    assert_eq!(report.summary["content.hosts"]["hosts"][0]["host"], "example.com", "the other analyzers still ran on the stalled file");
}

struct SlowUnpacker;

impl aa_core::plugin::Unpacker for SlowUnpacker {
    fn id(&self) -> &'static str {
        "slow"
    }

    fn unpack(&self, file: &Artifact, _bytes: &[u8], sink: &mut dyn aa_core::plugin::UnpackSink) -> aa_core::plugin::Unpack {
        if file.path != "b.txt" {
            return aa_core::plugin::Unpack::NotMine;
        }
        sink.add("first.txt", &mut &b"1"[..]).expect("add");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let second = sink.add("second.txt", &mut &b"2"[..]);
        assert_eq!(second, Err(aa_core::plugin::SinkError::LimitReached));
        aa_core::plugin::Unpack::Done { kind: "slow" }
    }
}

#[test]
fn unpacking_that_takes_too_long_is_cut_off() {
    let dir = folder();
    let mut registry = Registry::standard();
    registry.unpackers.insert(0, Box::new(SlowUnpacker));
    let report = analyze_with(&registry, dir.path(), &limits(|l| l.unpack_seconds = 1), &mut NoProgress).expect("readable");
    assert_eq!(codes(&report), ["unpack_timeout"]);
    assert!(paths(&report).contains(&"b.txt/first.txt") && !paths(&report).contains(&"b.txt/second.txt"));
    assert!(report.coverage.truncated);
}

struct Recorder(Vec<Event>);

impl ProgressSink for Recorder {
    fn event(&mut self, event: Event) {
        self.0.push(event);
    }
}

#[test]
fn a_session_gives_the_same_report_and_reads_any_range_of_any_file() {
    let big = noise(700 * 1024);
    let archive = zip_of(&[("small.txt", b"hello from inside"), ("big.bin", &big)]);
    let (_dir, path) = write_input("a.zip", &archive);
    let session = analyze_session(&Registry::standard(), &path, &Options::default(), &mut NoProgress).expect("readable");
    assert_eq!(session.report(), &run(&path, &Options::default()), "a session must not change the report");

    // The input itself, a child kept in memory, and a child spilled to disk.
    assert_eq!(session.read("a.zip", 0, 4).expect("read"), b"PK\x03\x04");
    assert_eq!(session.read("a.zip/small.txt", 6, 4).expect("read"), b"from");
    assert_eq!(session.read("a.zip/big.bin", 1000, 5000).expect("read"), big[1000..6000]);
    // The end of a file cuts a read short; past the end there is nothing; no file is an error.
    assert_eq!(session.read("a.zip/small.txt", 11, 100).expect("read"), b"inside");
    assert!(session.read("a.zip/small.txt", 17, 10).expect("read").is_empty());
    assert!(session.read("a.zip/small.txt", u64::MAX, u64::MAX).expect("read").is_empty());
    assert_eq!(session.read("a.zip/missing", 0, 1).expect_err("no such file").kind(), std::io::ErrorKind::NotFound);
    assert_eq!(session.read("a.zip/big.bin", 0, u64::MAX).expect("read").len(), big.len(), "smaller than the cap");
}

#[test]
fn what_a_session_unpacked_is_removed_when_it_ends() {
    let archive = zip_of(&[("big.bin", &noise(700 * 1024))]);
    let (_dir, path) = write_input("a.zip", &archive);
    let root = tempfile::tempdir().expect("temp dir");
    let options = Options { temp_root: Some(root.path().to_path_buf()), ..Options::default() };
    let count = || std::fs::read_dir(root.path()).expect("list").count();

    let session = analyze_session(&Registry::standard(), &path, &options, &mut NoProgress).expect("readable");
    assert_eq!(count(), 1, "the large child is kept in the chosen folder");
    assert_eq!(sweep_stale(Some(root.path())), 0, "a folder in use is left alone");
    assert_eq!(session.read("a.zip/big.bin", 0, 8).expect("still readable").len(), 8);
    drop(session);
    assert_eq!(count(), 0);
}

#[test]
fn folders_left_by_a_killed_run_are_swept() {
    let root = tempfile::tempdir().expect("temp dir");
    // What a killed run leaves: its folder, a lock file nobody holds, and unpacked files.
    let left = root.path().join("analyze-anything-killed");
    std::fs::create_dir(&left).expect("mkdir");
    std::fs::write(left.join(".lock"), b"").expect("write");
    std::fs::write(left.join("00000001"), b"unpacked").expect("write");
    // Things that are not ours, or not yet abandoned.
    std::fs::create_dir(root.path().join("someone-elses-folder")).expect("mkdir");
    std::fs::write(root.path().join("analyze-anything-a-file"), b"").expect("write");
    std::fs::create_dir(root.path().join("analyze-anything-starting")).expect("mkdir");

    assert_eq!(sweep_stale(Some(root.path())), 1);
    let mut names: Vec<String> =
        std::fs::read_dir(root.path()).expect("list").flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["analyze-anything-a-file", "analyze-anything-starting", "someone-elses-folder"]);
}

#[test]
fn progress_names_every_file_in_both_passes_and_survives_json() {
    let dir = folder();
    let mut recorder = Recorder(Vec::new());
    let report = analyze(dir.path(), &Options::default(), &mut recorder).expect("readable");
    let total = report.artifacts.len() as u64;

    let mut analyzed: Vec<&str> = Vec::new();
    for event in &recorder.0 {
        if let Event::Analyzed { index, total: of, path } = event {
            analyzed.push(path);
            assert_eq!((*index, *of), (analyzed.len() as u64, total));
        }
    }
    analyzed.sort_unstable();
    assert_eq!(analyzed, paths(&report), "each artifact is reported once");
    let relating = recorder.0.iter().filter(|e| matches!(e, Event::Relating { .. })).count();
    assert_eq!(relating, Registry::standard().analyzers.len());
    assert_eq!(recorder.0.last(), Some(&Event::Finished));

    // Every event can cross a process boundary and come back unchanged.
    for event in &recorder.0 {
        let json = serde_json::to_string(event).expect("to json");
        assert_eq!(&serde_json::from_str::<Event>(&json).expect("from json"), event, "{json}");
    }
    assert_eq!(serde_json::to_string(&Event::Listed { files: 3 }).expect("json"), r#"{"event":"listed","files":3}"#);
}

#[test]
fn a_bundle_given_as_a_folder_is_called_a_bundle_and_finds_its_program_by_its_own_name() {
    // An app whose Info.plist names no executable: the system then goes by the bundle's name.
    let dir = tempfile::tempdir().expect("temp dir");
    let app = dir.path().join("Mini.app");
    std::fs::create_dir_all(app.join("Contents/MacOS")).expect("folders");
    let plist = |executable: &str| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\
             <key>CFBundleIdentifier</key><string>com.example.mini</string>{executable}</dict></plist>\n"
        )
    };
    std::fs::write(app.join("Contents/MacOS/Mini"), b"#!/bin/sh\n").expect("program");
    for named in ["", "<key>CFBundleExecutable</key><string></string>"] {
        std::fs::write(app.join("Contents/Info.plist"), plist(named)).expect("plist");
        let report = run(&app, &Options::default());
        let kind = report.findings.iter().find(|f| f.rule.starts_with("overview.kind")).expect("says what it is");
        assert_eq!((kind.rule.as_str(), kind.params["name"].as_str()), ("overview.kind-bundle", Some("Mini.app")));
        assert!(!report.findings.iter().any(|f| f.rule == "apple.executable-missing"), "the program is there, under the bundle's name");
    }

    // A folder that is not named like a bundle stays a folder, whatever it holds.
    let plain = dir.path().join("Mini");
    std::fs::rename(&app, &plain).expect("renamed");
    let report = run(&plain, &Options::default());
    assert!(report.findings.iter().any(|f| f.rule == "overview.kind-folder"));
}
