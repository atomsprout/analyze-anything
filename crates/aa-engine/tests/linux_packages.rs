#[path = "../../aa-linux/tests/support/mod.rs"]
mod support;

use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn deb_control_and_actions_are_attributed_to_control_contents_only() {
    let bytes = support::deb(support::CONTROL, b"Package: impostor\nVersion: 999\nArchitecture: fake\n");
    let report = analyze_bytes(&Registry::standard(), "sample.deb", bytes.clone(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("root");
    assert_eq!(root.facts["deb.control"]["name"], "aa-fixture");
    assert!(
        report.summary["composition.components"]["components"]
            .as_array()
            .expect("components")
            .iter()
            .any(|row| row["ecosystem"] == "deb" && row["name"] == "aa-fixture")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule == "deb.install-script" && finding.evidence[0].artifact.ends_with("control.tar/postinst"))
    );
    assert!(report.findings.iter().any(|finding| finding.rule == "deb.dependencies"));
    assert!(report.limitations.iter().any(|limit| limit.code == "deb.script-semantics"));
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-deb"));
    let again = analyze_bytes(&Registry::standard(), "sample.deb", bytes, &Options::default(), &mut NoProgress);
    assert_eq!(report, again);
}

#[test]
fn deb_ambiguous_control_identity_is_a_gap_and_cannot_become_a_finding() {
    let control = b"Package: a\nPACKAGE: b\nVersion: 1\nArchitecture: all\n";
    let report = analyze_bytes(&Registry::standard(), "sample.deb", support::deb(control, b"data"), &Options::default(), &mut NoProgress);
    assert!(!report.findings.iter().any(|finding| finding.rule == "deb.identity"));
    assert!(report.limitations.iter().any(|limit| limit.code == "deb.control-unread"));
}

#[test]
fn rpm_gzip_cpio_payload_reaches_existing_content_analysis_with_source_evidence() {
    let bytes = support::rpm("gzip", Vec::new());
    let report = analyze_bytes(&Registry::standard(), "sample.rpm", bytes.clone(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("root");
    assert_eq!(root.facts["rpm.package"]["name"], "aa-fixture");
    assert!(
        report.summary["composition.components"]["components"]
            .as_array()
            .expect("components")
            .iter()
            .any(|row| row["ecosystem"] == "rpm" && row["name"] == "aa-fixture")
    );
    let member = report.artifacts.iter().find(|file| file.path.ends_with("usr/share/fixture/data.txt")).expect("CPIO payload");
    assert!(member.parent.as_deref().is_some_and(|path| path.ends_with("[payload].cpio")));
    assert_eq!(member.digests.as_ref().expect("member digests").sha256, aa_core::sha256_hex(b"https://example.invalid/cpio\n"));
    for rule in ["rpm.identity", "rpm.dependencies", "rpm.install-scripts", "cpio.contents", "overview.kind-rpm"] {
        assert!(report.findings.iter().any(|finding| finding.rule == rule), "{rule}");
    }
    assert!(report.limitations.iter().any(|limit| limit.code == "rpm.integrity-unverified"));
    let again = analyze_bytes(&Registry::standard(), "sample.rpm", bytes, &Options::default(), &mut NoProgress);
    assert_eq!(report, again);
}

#[test]
fn linux_payload_budgets_propagate_to_coverage() {
    let mut options = Options::default();
    options.limits.max_entry_bytes = 32;
    for (name, bytes) in [("sample.deb", support::deb(support::CONTROL, b"data")), ("sample.rpm", support::rpm("gzip", Vec::new()))] {
        let report = analyze_bytes(&Registry::standard(), name, bytes, &options, &mut NoProgress);
        assert!(report.coverage.truncated);
        assert!(report.artifacts.iter().all(|file| !file.path.ends_with("data.txt")));
    }
}

#[test]
fn published_deb_and_rpm_read_real_compression_and_preserve_link_declarations() {
    let deb = include_bytes!("../../aa-linux/tests/data/node-isarray_2.0.5-1_all.deb");
    assert_eq!(aa_core::sha256_hex(deb), "41b6b84a05e30d35b2ac224c5f4600b2a4e976d19f7d0bfdf0565dd729962d84");
    let report = analyze_bytes(&Registry::standard(), "sample.deb", deb.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("Debian root");
    assert_eq!(root.facts["deb.control"]["name"], "node-isarray");
    assert!(report.artifacts.iter().any(|file| file.path.ends_with("usr/share/nodejs/isarray/index.js")));
    assert_eq!(report.artifacts.iter().filter(|file| file.facts.contains_key("deb.archive-entries")).count(), 2);
    let rpm = include_bytes!("../../aa-linux/tests/data/xxhash-libs-0.8.4-2.fc43.x86_64.rpm");
    assert_eq!(aa_core::sha256_hex(rpm), "8ebf402b124f6fc75f39155254b5a116fccfda53e4a3fbd52210f6f66f7b7c8e");
    let report = analyze_bytes(&Registry::standard(), "sample.rpm", rpm.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("RPM root");
    assert_eq!(root.facts["rpm.package"]["name"], "xxhash-libs");
    let library = report.artifacts.iter().find(|file| file.path.ends_with("usr/lib64/libxxhash.so.0.8.4")).expect("native library");
    assert_eq!(library.kind.as_deref(), Some("elf"));
    let cpio = report.artifacts.iter().find(|file| file.facts.contains_key("cpio.directory")).expect("CPIO directory");
    assert!(
        cpio.facts["cpio.directory"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .any(|row| row["path"] == "./usr/lib64/libxxhash.so.0" && row["link_target"] == "libxxhash.so.0.8.4")
    );
    assert!(report.limitations.iter().any(|limit| limit.code == "cpio.special-file"));
    assert!(!report.artifacts.iter().any(|file| file.path.ends_with("usr/lib64/libxxhash.so.0")));
}

#[test]
fn colliding_control_files_and_payload_script_names_do_not_create_false_declarations() {
    let control = support::tar(&[("control", support::CONTROL), ("./control", support::CONTROL)]);
    let data = support::tar(&[("postinst", b"a payload file, not a maintainer script")]);
    let bytes = support::ar(&[("debian-binary", b"2.0\n"), ("control.tar", &control), ("data.tar", &data)]);
    let report = analyze_bytes(&Registry::standard(), "sample.deb", bytes, &Options::default(), &mut NoProgress);
    assert!(!report.findings.iter().any(|finding| matches!(finding.rule.as_str(), "deb.identity" | "deb.install-script")));
    assert!(report.limitations.iter().any(|limit| limit.code == "deb.control-unread"));
}
