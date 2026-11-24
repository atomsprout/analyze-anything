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

#[test]
fn native_built_script_packages_preserve_scalar_interpreters_and_script_evidence() {
    for (name, bytes, rule) in [
        ("native-script.deb", &include_bytes!("../../aa-linux/tests/data/native-script.deb")[..], "deb.install-script"),
        ("native-script.rpm", &include_bytes!("../../aa-linux/tests/data/native-script.rpm")[..], "rpm.install-scripts"),
    ] {
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        assert!(report.findings.iter().any(|finding| finding.rule == rule));
        assert!(!report.limitations.iter().any(|limit| limit.code == "unpack_failed"));
        if name.ends_with("rpm") {
            let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("RPM root");
            let interpreter = root.facts["rpm.package"]["tags"]
                .as_array()
                .expect("tags")
                .iter()
                .find(|row| row["tag"] == 1086)
                .expect("native post interpreter");
            assert_eq!(interpreter["type"], 6);
            assert_eq!(interpreter["value"], "/bin/sh");
        }
    }
}

#[test]
fn package_metadata_redacts_named_credentials_and_script_assignments() {
    let mut control = support::CONTROL.to_vec();
    control.extend(b"X-Api-Key: fixture-control-credential\n");
    let report = analyze_bytes(&Registry::standard(), "sample.deb", support::deb(&control, b"data"), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("Debian root");
    assert!(!root.facts["deb.control"].to_string().contains("fixture-control-credential"));
    assert!(root.facts["deb.control"].to_string().contains("[redacted]"));
    let rpm = support::rpm("none", vec![(1079, 6, b"token=fixture-script-credential\0".to_vec(), 1)]);
    let report = analyze_bytes(&Registry::standard(), "sample.rpm", rpm, &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("RPM root");
    assert!(!root.facts["rpm.package"].to_string().contains("fixture-script-credential"));
    assert!(root.facts["rpm.package"].to_string().contains("[redacted]"));
}

#[test]
fn deb_installer_text_is_bounded_redacted_and_distinguishes_triggers_from_scripts() {
    let oversized = vec![b'x'; 256 * 1024 + 1];
    let control = support::tar(&[
        ("control", support::CONTROL),
        ("postinst", b"#!/bin/sh\ntoken=fixture-install-secret\n"),
        ("preinst", &oversized),
        ("triggers", b"interest-noawait /usr/share/fixture\n"),
    ]);
    let data = support::tar(&[("data", b"data")]);
    let bytes = support::ar(&[("debian-binary", b"2.0\n"), ("control.tar", &control), ("data.tar", &data)]);
    let report = analyze_bytes(&Registry::standard(), "sample.deb", bytes, &Options::default(), &mut NoProgress);
    let postinst = report.artifacts.iter().find(|file| file.path.ends_with("control.tar/postinst")).expect("script");
    assert!(postinst.facts["deb.installation-declaration"]["text"].as_str().expect("text").contains("token=[redacted]"));
    assert!(!serde_json::to_string(&postinst.facts).expect("serialize script facts").contains("fixture-install-secret"));
    assert!(report.findings.iter().any(|finding| finding.rule == "deb.triggers"));
    assert!(
        report
            .limitations
            .iter()
            .any(|limit| limit.code == "deb.action-unread" && limit.artifact.as_deref().is_some_and(|path| path.ends_with("preinst")))
    );
}

#[test]
fn pinned_linux_packages_match_recorded_native_values_and_every_regular_file_digest() {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/spikes/linux-packages-native.json")).expect("native records");
    for (name, bytes) in [
        ("native-script.deb", &include_bytes!("../../aa-linux/tests/data/native-script.deb")[..]),
        ("native-script.rpm", &include_bytes!("../../aa-linux/tests/data/native-script.rpm")[..]),
        ("node-isarray_2.0.5-1_all.deb", &include_bytes!("../../aa-linux/tests/data/node-isarray_2.0.5-1_all.deb")[..]),
        ("xxhash-libs-0.8.4-2.fc43.x86_64.rpm", &include_bytes!("../../aa-linux/tests/data/xxhash-libs-0.8.4-2.fc43.x86_64.rpm")[..]),
    ] {
        let digest = aa_core::sha256_hex(bytes);
        let recorded = reference["records"]
            .as_array()
            .expect("records")
            .iter()
            .find(|record| record["pinned_fixture"] == true && record["sha256"] == digest)
            .expect("hash-bound native record");
        assert!(recorded["checks"].as_array().expect("checks").iter().all(|check| check["matches"] == true));
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("package root");
        let native = &recorded["native"];
        let check_member = |container: &aa_core::Artifact, entry: &serde_json::Value| {
            if let Some(hash) = entry["sha256"].as_str() {
                let name = entry["path"].as_str().expect("entry name").trim_start_matches('/').trim_start_matches("./");
                let path = format!("{}/{name}", container.path);
                let artifact = report.artifacts.iter().find(|file| file.path == path).expect("captured native member");
                assert_eq!(artifact.digests.as_ref().expect("member digest").sha256, hash, "{path}");
            }
        };
        if name.ends_with("deb") {
            for key in ["name", "version", "architecture"] {
                assert_eq!(root.facts["deb.control"][key], native[key]);
            }
            for archive in native["archives"].as_array().expect("native TARs") {
                let member = archive["member"].as_str().expect("archive name");
                let prefix = format!("{}/{member}", root.path);
                let tar = report
                    .artifacts
                    .iter()
                    .find(|file| {
                        file.facts.contains_key("deb.archive-entries") && (file.path == prefix || file.parent.as_deref() == Some(&prefix))
                    })
                    .expect("captured TAR metadata");
                assert_eq!(
                    tar.facts["deb.archive-entries"]["entries"].as_array().expect("entries").len(),
                    archive["entries"].as_array().expect("native entries").len()
                );
                for entry in archive["entries"].as_array().expect("native entries") {
                    check_member(tar, entry);
                }
            }
        } else {
            for key in ["name", "version", "release", "architecture"] {
                assert_eq!(root.facts["rpm.package"][key], native[key]);
            }
            for tag in native["tags"].as_array().expect("native tags") {
                let row = root.facts["rpm.package"]["tags"]
                    .as_array()
                    .expect("tags")
                    .iter()
                    .find(|row| row["tag"] == tag["tag"])
                    .expect("captured tag");
                assert_eq!(row["value"], tag["value"]);
            }
            let cpio = report.artifacts.iter().find(|file| file.facts.contains_key("cpio.directory")).expect("captured CPIO");
            assert_eq!(
                cpio.facts["cpio.directory"]["entries"].as_array().expect("entries").len(),
                native["entries"].as_array().expect("native entries").len()
            );
            for entry in native["entries"].as_array().expect("native entries") {
                check_member(cpio, entry);
            }
        }
    }
}
