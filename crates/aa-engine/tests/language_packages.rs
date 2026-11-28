use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

#[test]
fn licensed_language_packages_reach_semantic_readers_through_shared_containers() {
    for (name, bytes, key, expected_name, expected_purl, overview) in [
        (
            "sampleproject.whl",
            include_bytes!("../../aa-packages/tests/data/wheel/sampleproject-4.0.0-py3-none-any.whl").as_slice(),
            "wheel.package",
            Some("sampleproject"),
            "pkg:pypi/sampleproject@4.0.0",
            "overview.kind-wheel",
        ),
        (
            "isarray.tgz",
            include_bytes!("../../aa-packages/tests/data/npm/isarray-2.0.5.tgz").as_slice(),
            "npm.package",
            Some("isarray"),
            "pkg:npm/isarray@2.0.5",
            "overview.kind-npm",
        ),
        (
            "slf4j-api.jar",
            include_bytes!("../../aa-packages/tests/data/java/slf4j-api-2.0.16.jar").as_slice(),
            "java.jar",
            None,
            "pkg:maven/org.slf4j/slf4j-api@2.0.16",
            "overview.kind-jar",
        ),
    ] {
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        let package = report.artifacts.iter().find(|file| file.facts.contains_key(key)).expect("registered package semantic reader");
        if let Some(name) = expected_name {
            assert_eq!(package.facts[key]["name"], name);
        }
        assert!(package.facts[key]["inventory"]["total"].as_u64().is_some_and(|count| count > 0));
        let components = report.summary["composition.components"]["components"].as_array().expect("captured package components");
        let component = components.iter().find(|row| row["purl"] == expected_purl).expect("metadata identity reaches component inventory");
        let source = component["source"].as_str().expect("original metadata source");
        assert!(report.artifacts.iter().any(|file| file.path == source));
        assert!(source.ends_with(if key == "wheel.package" {
            "/METADATA"
        } else if key == "npm.package" {
            "/package/package.json"
        } else {
            "/pom.properties"
        }));
        assert_eq!(component["declared_range"], serde_json::Value::Null);
        assert!(report.findings.iter().any(|finding| finding.rule == overview));
        let bom = aa_export::cyclonedx::cyclonedx(&report);
        let exported = bom["components"]
            .as_array()
            .expect("CycloneDX components")
            .iter()
            .find(|row| row["purl"] == expected_purl)
            .expect("captured identity exported");
        assert!(
            exported["properties"]
                .as_array()
                .expect("source properties")
                .iter()
                .any(|row| row["name"] == "aa:source" && row["value"] == source)
        );
        assert!(bom.get("dependencies").is_none(), "literal unresolved declarations must not become resolved SBOM edges");
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
