use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn real_arch_package_identity_components_payload_and_report_are_consistent() {
    let bytes = include_bytes!("../../aa-linux/tests/data/libutf8proc-2.12.0-1-x86_64.pkg.tar.zst");
    assert_eq!(aa_core::sha256_hex(bytes), "297205aba0d093921dbfbc70b9ecf7359838f0c3418b6265af960aed12bfd072");
    let report = analyze_bytes(&Registry::standard(), "libutf8proc.pkg.tar.zst", bytes.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("package root");
    assert_eq!(root.kind.as_deref(), Some("arch-package"));
    assert_eq!(root.facts["arch.package"]["name"], "libutf8proc");
    assert_eq!(root.facts["arch.package"]["version"], "2.12.0-1");
    assert!(report.artifacts.iter().any(|file| file.kind.as_deref() == Some("elf")));
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-arch"));
    assert!(
        report.summary["composition.components"]["components"]
            .as_array()
            .expect("components")
            .iter()
            .any(|component| component["ecosystem"] == "alpm" && component["name"] == "libutf8proc")
    );
    let again = analyze_bytes(&Registry::standard(), "libutf8proc.pkg.tar.zst", bytes.to_vec(), &Options::default(), &mut NoProgress);
    assert_eq!(report, again);
}

#[test]
fn real_static_library_members_reach_elf_analysis_without_linking() {
    let bytes = include_bytes!("../../aa-linux/tests/data/upstream-libxxhash-0.8.1.a");
    let report = analyze_bytes(&Registry::standard(), "libxxhash.a", bytes.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("archive root");
    assert_eq!(root.kind.as_deref(), Some("ar"));
    assert_eq!(root.unpacked_by.as_deref(), Some("ar"));
    assert!(root.facts.contains_key("ar.directory"));
    assert!(report.artifacts.iter().any(|file| file.parent.as_deref() == Some(&root.path) && file.kind.as_deref() == Some("elf")));
    assert!(report.findings.iter().any(|finding| finding.rule == "ar.contents"));
}
