use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn licensed_language_packages_reach_semantic_readers_through_shared_containers() {
    for (name, bytes, key, expected_name) in [
        (
            "sampleproject.whl",
            include_bytes!("../../aa-packages/tests/data/wheel/sampleproject-4.0.0-py3-none-any.whl").as_slice(),
            "wheel.package",
            Some("sampleproject"),
        ),
        ("isarray.tgz", include_bytes!("../../aa-packages/tests/data/npm/isarray-2.0.5.tgz").as_slice(), "npm.package", Some("isarray")),
        ("slf4j-api.jar", include_bytes!("../../aa-packages/tests/data/java/slf4j-api-2.0.16.jar").as_slice(), "java.jar", None),
    ] {
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        let package = report.artifacts.iter().find(|file| file.facts.contains_key(key)).expect("registered package semantic reader");
        if let Some(name) = expected_name {
            assert_eq!(package.facts[key]["name"], name);
        }
        assert!(package.facts[key]["inventory"]["total"].as_u64().is_some_and(|count| count > 0));
        assert!(
            report
                .findings
                .iter()
                .filter(|finding| matches!(finding.analyzer.as_str(), "wheel" | "npm" | "java"))
                .all(|finding| !finding.evidence.is_empty())
        );
        assert_eq!(
            report,
            analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress),
            "{name} must remain deterministic"
        );
    }
}
