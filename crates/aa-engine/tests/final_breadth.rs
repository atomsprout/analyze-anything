use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn native_final_batch_samples_reach_identity_composition_and_deterministic_reports() {
    let samples: &[(&str, &[u8], &str, &str, &str)] = &[
        (
            "xxhash.apk",
            include_bytes!("../../aa-linux/tests/data/libxxhash-0.8.3-r0.apk"),
            "alpine-apk",
            "alpine-apk.package",
            "overview.kind-alpine-apk",
        ),
        (
            "fixture.flatpak",
            include_bytes!("../../aa-linux/tests/data/native-inert.flatpak"),
            "flatpak",
            "flatpak.bundle",
            "overview.kind-flatpak",
        ),
        (
            "fixture.oci.tar",
            include_bytes!("../../aa-linux/tests/data/native-image.oci.tar"),
            "oci-image",
            "image.package",
            "overview.kind-container-image",
        ),
        (
            "fixture.docker.tar",
            include_bytes!("../../aa-linux/tests/data/native-image.docker.tar"),
            "docker-image",
            "image.package",
            "overview.kind-container-image",
        ),
    ];
    for (name, bytes, kind, fact, overview) in samples {
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("input root");
        assert_eq!(root.kind.as_deref(), Some(*kind), "{name}");
        assert!(root.facts.contains_key(*fact), "{name}");
        assert!(report.findings.iter().any(|finding| finding.rule == *overview), "{name}");
        if *kind == "alpine-apk" {
            let components = report.summary["composition.components"]["components"].as_array().expect("captured component list");
            assert!(components.iter().any(|row| row["ecosystem"] == "apk" && row["name"] == "libxxhash" && row["version"] == "0.8.3-r0"));
        } else if *kind == "flatpak" {
            assert_eq!(root.facts[*fact]["capture_complete"], true);
            let components = report.summary["composition.components"]["components"].as_array().expect("Flatpak component list");
            assert!(components.iter().any(|row| row["ecosystem"] == "flatpak" && row["version"].is_null() && row["purl"].is_null()));
        } else {
            assert_eq!(root.facts[*fact]["merged_filesystem"], false);
            assert!(report.artifacts.iter().any(|file| file.facts.contains_key("image.layer-entries")));
        }
        let again = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        assert_eq!(report, again, "{name}");
    }
}

#[test]
fn native_lz4_checksums_and_decoded_child_reach_the_engine_without_authentication_claims() {
    let bytes = include_bytes!("../../aa-unpack/tests/data/native-all-checksums.txt.lz4");
    let report = analyze_bytes(&Registry::standard(), "fixture.txt.lz4", bytes.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("frame");
    assert_eq!(root.kind.as_deref(), Some("lz4"));
    assert_eq!(root.facts["lz4.frame"]["complete_decoding"], true);
    assert_eq!(root.facts["lz4.frame"]["authenticated"], false);
    let child = report.artifacts.iter().find(|file| file.parent.as_deref() == Some(&root.path)).expect("decoded child");
    let source = b"Analyze Anything native LZ4 fixture. Project-authored Apache-2.0 data.\n".repeat(3000);
    assert_eq!(child.digests.as_ref().expect("decoded digest").sha256, aa_core::sha256_hex(&source));
    let again = analyze_bytes(&Registry::standard(), "fixture.txt.lz4", bytes.to_vec(), &Options::default(), &mut NoProgress);
    assert_eq!(report, again);
}
