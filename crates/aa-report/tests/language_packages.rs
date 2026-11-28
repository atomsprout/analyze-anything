use std::io::{Cursor, Write};

use aa_engine::{NoProgress, Options, Registry, analyze_bytes};
use aa_report::{Format, Lang, render};

fn zip(rows: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in rows {
        writer.start_file(*name, zip::write::SimpleFileOptions::default()).expect("fixture ZIP member");
        writer.write_all(bytes).expect("fixture ZIP data");
    }
    writer.finish().expect("finalized ZIP").into_inner()
}

fn npm() -> Vec<u8> {
    let bytes = br#"{"name":"@Example/pkg","version":"1.0.0+build","dependencies":{"literal-dep":"^1.2"},"scripts":{"install":"echo literal-only"}}"#;
    let mut writer = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    writer.append_data(&mut header, "package/package.json", Cursor::new(bytes)).expect("npm source metadata");
    writer.into_inner().expect("finalized npm TAR")
}

#[test]
fn literal_dependencies_reach_all_report_views_without_resolved_targets() {
    let wheel = zip(&[
        ("example-1.dist-info/WHEEL", b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
        (
            "example-1.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: Example__Pkg.Name\nVersion: 1.0+LOCAL\nRequires-Dist: literal-dep>=1; python_version < '4'\n",
        ),
    ]);
    let jar = zip(&[("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nImplementation-Title: Literal display title\r\nImplementation-Version: 1.0\r\nClass-Path: relative.jar https://example.invalid/never-opened.jar\r\n\r\n")]);
    for (name, bytes, expected, purl) in [
        ("example.whl", wheel, "literal-dep>=1", Some("pkg:pypi/example-pkg-name@1.0%2Blocal")),
        ("example.tar", npm(), "literal-dep@^1.2", Some("pkg:npm/%40Example/pkg@1.0.0%2Bbuild")),
        ("example.jar", jar, "relative.jar", None),
    ] {
        let report = analyze_bytes(&Registry::standard(), name, bytes, &Options::default(), &mut NoProgress);
        let relationships = aa_report::relationships::collect(&report);
        let row = relationships.rows.iter().find(|row| row.declaration.contains(expected)).expect("literal source relationship");
        assert_eq!(row.status, "declared-unresolved");
        assert!(row.target.is_none());
        assert!(row.target_sha256.is_none());
        assert!(report.artifacts.iter().any(|file| file.path == row.source));
        let components = report.summary["composition.components"]["components"].as_array().expect("captured declared component");
        assert_eq!(components.len(), 1, "a dependency name never becomes a captured component");
        if let Some(purl) = purl {
            assert_eq!(components[0]["purl"], purl);
        } else {
            assert!(components[0]["purl"].is_null(), "a JAR display title is not a registry coordinate");
        }
        for lang in [Lang::En, Lang::Zh] {
            for format in [Format::Text, Format::Markdown, Format::Html] {
                let rendered = String::from_utf8(render(&report, format, lang).expect("language package report")).expect("UTF-8 report");
                assert!(rendered.contains("declared-unresolved"));
                assert!(rendered.contains("literal-dep") || rendered.contains("relative.jar"));
            }
        }
    }
}

#[test]
fn only_validated_maven_rows_produce_coordinates_and_war_ear_are_unqualified() {
    let bytes = zip(&[
        ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\nImplementation-Title: A display name\r\nImplementation-Version: 7\r\n\r\n"),
        ("META-INF/maven/org.Example/one/pom.properties", b"groupId=org.Example\nartifactId=one\nversion=1.0+build\n"),
        ("META-INF/maven/org.Example/two/pom.properties", b"groupId=org.Example\nartifactId=two\nversion=2.0\n"),
        ("META-INF/maven/org.Example/wrong/pom.properties", b"groupId=other.group\nartifactId=wrong\nversion=3\n"),
    ]);
    let report = analyze_bytes(&Registry::standard(), "captured.jar", bytes.clone(), &Options::default(), &mut NoProgress);
    let components = report.summary["composition.components"]["components"].as_array().expect("validated coordinates");
    assert_eq!(components.len(), 2);
    assert!(components.iter().any(|row| row["purl"] == "pkg:maven/org.Example/one@1.0%2Bbuild"));
    assert!(components.iter().any(|row| row["purl"] == "pkg:maven/org.Example/two@2.0"));
    for name in ["unqualified.war", "unqualified.ear"] {
        let report = analyze_bytes(&Registry::standard(), name, bytes.clone(), &Options::default(), &mut NoProgress);
        assert!(!report.artifacts.iter().any(|file| file.facts.contains_key("java.jar")));
        assert!(!report.summary.contains_key("composition.components"));
        assert!(report.limitations.iter().any(|gap| gap.code == "java.variant-unread"));
    }
}

#[test]
fn licensed_real_language_packages_render_identity_and_evidence_in_both_languages() {
    for (name, bytes, identity) in [
        (
            "sampleproject.whl",
            include_bytes!("../../aa-packages/tests/data/wheel/sampleproject-4.0.0-py3-none-any.whl").as_slice(),
            "sampleproject",
        ),
        ("isarray.tgz", include_bytes!("../../aa-packages/tests/data/npm/isarray-2.0.5.tgz").as_slice(), "isarray"),
        ("slf4j-api.jar", include_bytes!("../../aa-packages/tests/data/java/slf4j-api-2.0.16.jar").as_slice(), "slf4j-api"),
    ] {
        let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        assert!(report.findings.iter().all(|finding| !finding.evidence.is_empty()), "{name} findings require source evidence");
        for lang in [Lang::En, Lang::Zh] {
            for format in [Format::Text, Format::Markdown, Format::Html] {
                let output = render(&report, format, lang).expect("real language package report");
                assert_eq!(output, render(&report, format, lang).expect("deterministic report"));
                assert!(String::from_utf8(output).expect("UTF-8 report").contains(identity));
            }
        }
    }
}
