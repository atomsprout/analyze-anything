//! Executable containers feed the ordinary static pipeline; no input is run.

use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn sdk_bundle_members_reach_existing_dotnet_and_configuration_readers() {
    let registry = Registry::standard();
    let bytes = include_bytes!("../../aa-unpack/tests/data/sdk-dotnet-bundle.exe");
    let report = analyze_bytes(&registry, "app.exe", bytes.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("host");
    assert_eq!(root.unpacked_by.as_deref(), Some("dotnet-bundle"));
    assert_eq!(root.facts["dotnet-bundle.manifest"]["entries"].as_array().expect("directory").len(), 3);
    let assembly = report.artifacts.iter().find(|file| file.path == "app.exe/BundleFixture.dll").expect("embedded assembly");
    assert!(assembly.facts.contains_key("windows.dotnet"));
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-dotnet-bundle"));
    assert!(report.findings.iter().any(|finding| finding.rule == "dotnet-bundle.contents"));
    let again = analyze_bytes(&registry, "app.exe", bytes.to_vec(), &Options::default(), &mut NoProgress);
    assert_eq!(report, again);
    let mut options = Options::default();
    options.limits.max_entry_bytes = 64;
    let limited = analyze_bytes(&registry, "app.exe", bytes.to_vec(), &options, &mut NoProgress);
    assert!(limited.coverage.truncated);
    assert!(!limited.limitations.is_empty());
    assert!(limited.artifacts.iter().all(|file| file.parent.is_none()));
}

#[test]
fn native_carchive_exposes_data_and_preserves_container_provenance() {
    let bytes = include_bytes!("../../aa-unpack/tests/data/native-carchive.pkg");
    let report = analyze_bytes(&Registry::standard(), "archive.pkg", bytes.to_vec(), &Options::default(), &mut NoProgress);
    let root = report.artifacts.iter().find(|file| file.parent.is_none()).expect("archive");
    assert_eq!(root.unpacked_by.as_deref(), Some("pyinstaller"));
    let data = report.artifacts.iter().find(|file| file.path == "archive.pkg/data.txt").expect("native member");
    assert_eq!(data.parent.as_deref(), Some("archive.pkg"));
    assert_eq!(
        data.digests.as_ref().expect("member digest").sha256,
        aa_core::sha256_hex(include_bytes!("../../../tools/fixtures/executable-bundles/data.txt"))
    );
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-pyinstaller"));
    assert!(report.findings.iter().any(|finding| finding.rule == "pyinstaller.contents"));
}
