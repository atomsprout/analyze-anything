//! Tests that run the whole analyzer over packages built in memory or cut from real ones.

/// Every fact key the analyzer writes.
pub const FACT_KEYS: &[&str] = &[
    "android.manifest",
    "android.permissions",
    "android.deep_links",
    "android.network_security_config",
    "android.google_services",
    "android.resources",
    "android.signing",
    "android.zip",
    "android.dex",
    "android.code",
    "android.sdks",
    "android.native_libs",
    "android.build",
    "android.apk_set",
    "android.packages",
];

use std::collections::BTreeMap;
use std::sync::Arc;

use aa_core::plugin::{Analyzer, Bytes, Output, Tree};
use aa_core::{Artifact, Digests, Finding, Section, Severity};
use serde_json::Value as Json;
use sha2::Digest;

use crate::{Android, zipraw};

const FULL: &[u8] = include_bytes!("../tests/data/full.apk");
const EXPECTED: &str = include_str!("../tests/data/expected.tsv");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// An artifact tree held in memory.
#[derive(Default)]
struct MemTree {
    artifacts: Vec<Artifact>,
    data: BTreeMap<String, Arc<Vec<u8>>>,
}

impl Tree for MemTree {
    fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    fn read(&self, path: &str) -> std::io::Result<Bytes> {
        match self.data.get(path) {
            Some(data) => Ok(Bytes::new(data.clone())),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, path.to_string())),
        }
    }
}

impl MemTree {
    fn add(&mut self, path: &str, parent: Option<&str>, data: Vec<u8>) {
        if self.data.contains_key(path) {
            return; // the engine keeps the first entry of a name
        }
        self.artifacts.push(Artifact {
            path: path.to_string(),
            parent: parent.map(str::to_string),
            size: data.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: hex::encode(sha2::Sha256::digest(&data)) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        });
        self.data.insert(path.to_string(), Arc::new(data));
    }

    /// Adds a ZIP file and, as the ZIP unpacker would, its entries (recursively for nested APKs).
    fn add_zip(&mut self, path: &str, parent: Option<&str>, data: Vec<u8>) {
        self.add(path, parent, data.clone());
        let Some(archive) = zipraw::parse(&data) else { return };
        if let Some(artifact) = self.artifacts.iter_mut().find(|a| a.path == path) {
            artifact.kind = Some("zip".into());
            artifact.unpacked_by = Some("zip".into());
        }
        for entry in &archive.entries {
            if entry.name.ends_with('/') {
                continue;
            }
            let Ok(content) = zipraw::read_entry(&data, entry, 64 * 1024 * 1024) else { continue };
            let child = format!("{path}/{}", entry.name);
            if entry.name.ends_with(".apk") {
                self.add_zip(&child, Some(path), content);
            } else {
                self.add(&child, Some(path), content);
            }
        }
    }

    fn finish(mut self) -> Self {
        self.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
        self
    }

    fn apk(name: &str, data: Vec<u8>) -> Self {
        let mut tree = MemTree::default();
        tree.add_zip(name, None, data);
        tree.finish()
    }
}

fn analyze(tree: &MemTree) -> Output {
    let mut out = Output::default();
    Android.analyze_tree(tree, &mut out);
    out
}

fn fact<'a>(out: &'a Output, key: &str) -> &'a Json {
    out.facts.iter().find(|f| f.key == key).map(|f| &f.value).unwrap_or_else(|| panic!("no fact {key}"))
}

fn rule<'a>(out: &'a Output, id: &str) -> Vec<&'a Finding> {
    out.findings.iter().filter(|f| f.rule == id).collect()
}

fn has(out: &Output, id: &str) -> bool {
    !rule(out, id).is_empty()
}

fn rules_of(out: &Output) -> Vec<&str> {
    let mut ids: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
    ids.sort();
    ids.dedup();
    ids
}

/// `name='value'` fields of an `aapt dump badging` line.
fn badging_field<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let start = line.find(&format!("{field}='"))? + field.len() + 2;
    let end = line[start..].find('\'')?;
    Some(&line[start..start + end])
}

#[test]
fn manifest_matches_aapt_badging() {
    let out = analyze(&MemTree::apk("full.apk", FULL.to_vec()));
    let manifest = fact(&out, "android.manifest");
    let badging = include_str!("../tests/data/badging.txt");
    let mut permissions = Vec::new();
    let mut checked = 0;
    for line in badging.lines() {
        if line.starts_with("package:") {
            assert_eq!(manifest["package"].as_str(), badging_field(line, "name"));
            assert_eq!(manifest["version_code"].as_i64().map(|v| v.to_string()).as_deref(), badging_field(line, "versionCode"));
            assert_eq!(manifest["version_name"].as_str(), badging_field(line, "versionName"));
            checked += 3;
        } else if let Some(value) = line.strip_prefix("sdkVersion:") {
            assert_eq!(manifest["min_sdk"].as_i64().map(|v| format!("'{v}'")).as_deref(), Some(value));
            checked += 1;
        } else if let Some(value) = line.strip_prefix("targetSdkVersion:") {
            assert_eq!(manifest["target_sdk"].as_i64().map(|v| format!("'{v}'")).as_deref(), Some(value));
            checked += 1;
        } else if line.starts_with("uses-permission:") {
            permissions.extend(badging_field(line, "name"));
        } else if let Some(value) = line.strip_prefix("application-label:") {
            assert_eq!(manifest["application"]["label"]["value"].as_str().map(|v| format!("'{v}'")).as_deref(), Some(value));
            assert_eq!(manifest["application"]["label"]["resource"].as_str(), Some("@string/app_name"));
            checked += 1;
        } else if line.starts_with("launchable-activity:") {
            let launcher = rule(&out, "android.launcher-activity");
            assert_eq!(launcher[0].params["activities"].as_str(), badging_field(line, "name"));
            checked += 1;
        } else if line.starts_with("application-debuggable") {
            assert_eq!(manifest["application"]["debuggable"].as_bool(), Some(true));
            checked += 1;
        }
    }
    assert!(checked >= 8, "badging lines compared: {checked}");
    let ours: Vec<&str> =
        fact(&out, "android.permissions")["requested"].as_array().expect("list").iter().filter_map(|p| p["name"].as_str()).collect();
    assert_eq!(ours, permissions);
}

/// Compares every element and attribute with `aapt dump xmltree`.
#[test]
fn manifest_tree_matches_aapt_xmltree() {
    let data = fixture("AndroidManifest.bin");
    let doc = crate::axml::parse(&data);
    // The fixture's networkSecurityConfig attribute was made by changing the resource id of
    // another attribute (see make-fixtures.sh), which is exactly what this anomaly reports.
    assert_eq!(doc.anomalies, vec!["attribute name text differs from the name of its resource id"]);
    // Flatten our tree in document order: "E name" and "A name(0xid)" lines.
    let mut ours = Vec::new();
    let mut stack = vec![doc.root.as_ref().expect("root")];
    while let Some(element) = stack.pop() {
        ours.push(format!("E {}", element.name));
        for attr in &element.attrs {
            ours.push(match attr.res_id {
                Some(id) => format!("A 0x{id:08x}"),
                None => format!("A {}", attr.raw_name),
            });
        }
        stack.extend(element.children.iter().rev());
    }
    let mut theirs = Vec::new();
    for line in include_str!("../tests/data/xmltree.txt").lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("E: ") {
            theirs.push(format!("E {}", rest.split(' ').next().unwrap_or("")));
        } else if let Some(rest) = line.strip_prefix("A: ") {
            let name = rest.split('=').next().unwrap_or("");
            theirs.push(match name.split_once("(0x") {
                Some((_, id)) => format!("A 0x{}", id.trim_end_matches(')')),
                None => format!("A {name}"),
            });
        }
    }
    assert!(theirs.len() > 80);
    assert_eq!(ours, theirs);
}

#[test]
fn signatures_agree_with_apksigner() {
    let mut rows = 0;
    for line in EXPECTED.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [file, accepted, v1, v2, v3, sha256] = fields.as_slice() else { panic!("bad line {line}") };
        let out = analyze(&MemTree::apk(file, fixture(file)));
        let signing = fact(&out, "android.signing");
        let verified: Vec<&str> = signing["verified_schemes"].as_array().expect("list").iter().filter_map(Json::as_str).collect();
        // The script verified the v2-only and v3-only files for the Android versions that know
        // the scheme; everything else for the manifest's minSdkVersion, as our check does.
        let min_sdk = if file.starts_with("v2-ec") {
            24
        } else if file.starts_with("v3-ec") {
            28
        } else {
            signing["install_check"]["min_sdk"].as_i64().expect("min sdk")
        };
        let failed: Vec<String> =
            signing["failed_schemes"].as_array().expect("list").iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let stripped = signing["stripped_schemes"].as_array().is_some_and(|l| !l.is_empty());
        let has_v2_plus = signing["schemes"].as_array().is_some_and(|l| !l.is_empty());
        let (ours, reasons) =
            crate::emit_signing::install_check(&verified, &failed, !signing["v1"].is_null(), has_v2_plus, stripped, min_sdk);
        assert_eq!(ours, *accepted == "yes", "{file}: apksigner says {accepted}, we say {reasons:?}");
        if *accepted == "yes" {
            assert_eq!(verified.contains(&"v1"), *v1 == "true", "{file} v1");
            assert_eq!(verified.contains(&"v2"), *v2 == "true", "{file} v2");
            assert_eq!(verified.contains(&"v3"), *v3 == "true", "{file} v3");
            let summary = fact(&out, "android.packages");
            assert_eq!(summary["packages"][0]["signer_sha256"][0].as_str(), Some(*sha256), "{file} signer");
            assert!(!has(&out, "android.signature-invalid"), "{file}");
        } else {
            assert!(has(&out, "android.signature-invalid") || has(&out, "android.signature-stripped"), "{file}: {:?}", rules_of(&out));
        }
        rows += 1;
    }
    assert_eq!(rows, 21);
}

#[test]
fn each_tampering_is_blamed_on_the_right_check() {
    let run = |file: &str| analyze(&MemTree::apk(file, fixture(file)));
    let reason = |out: &Output| {
        rule(out, "android.signature-invalid")
            .iter()
            .map(|f| format!("{}: {}", f.params["scheme"], f.params["reason"]))
            .collect::<Vec<_>>()
            .join(" | ")
    };

    let out = run("v1-entry-modified.apk");
    assert!(reason(&out).contains("classes.dex"), "{}", reason(&out));
    let out = run("v1v2-entry-modified.apk");
    assert!(reason(&out).contains("chunked SHA-256") && reason(&out).contains("v1 (JAR)"), "{}", reason(&out));
    let out = run("v1v2-block-modified.apk");
    assert!(reason(&out).contains("signature does not verify"), "{}", reason(&out));
    assert_eq!(fact(&out, "android.signing")["verified_schemes"], serde_json::json!(["v1"]));
    let out = run("v1v2-appended.apk");
    assert!(has(&out, "android.zip-trailing-data"));
    let out = run("v1v2-stripped.apk");
    assert!(has(&out, "android.signature-stripped") && has(&out, "android.v1-only"));
    let out = run("v1-janus.apk");
    assert!(has(&out, "android.janus") && has(&out, "android.signature-verified"));
    assert!(fact(&out, "android.zip")["leading_padding_entries"].is_null());
    assert!(rule(&out, "android.janus")[0].references.contains(&"CVE-2017-13156".to_string()));
    let out = run("unsigned.apk");
    assert!(has(&out, "android.unsigned"));
    let out = run("v2-ec.apk");
    assert!(has(&out, "android.v1-missing"));
}

#[test]
fn certificates_and_rotation() {
    let run = |file: &str| analyze(&MemTree::apk(file, fixture(file)));
    let out = run("debug.apk");
    assert!(has(&out, "android.debug-certificate"));
    let certificate = rule(&out, "android.signing-certificate")[0];
    assert_eq!(certificate.params["subject"], "CN=Android Debug, O=Android, C=US");
    assert_eq!(certificate.params["key"], "RSA 2048");
    assert_eq!(certificate.params["issuer_en"], "same as the subject (self-signed)");
    // The fingerprints apksigner printed.
    let reference = String::from_utf8(fixture("debug.apksigner.txt")).expect("text");
    for (label, param) in [("SHA-256", "sha256"), ("SHA-1", "sha1")] {
        let expected = reference.lines().find_map(|l| l.strip_prefix(&format!("Signer #1 certificate {label} digest: "))).expect("line");
        assert_eq!(certificate.params[param], expected);
    }

    let out = run("weak.apk");
    assert!(has(&out, "android.weak-signing-key") && has(&out, "android.weak-certificate-digest"));
    assert_eq!(rule(&out, "android.weak-signing-key")[0].params["key"], "RSA 1024");

    let out = run("rotated.apk");
    let rotation = rule(&out, "android.key-rotation");
    assert_eq!(rotation.len(), 1);
    assert_eq!(rotation[0].params["count"], 2);
    assert!(!has(&out, "android.signer-mismatch"));
    assert_eq!(rule(&out, "android.signing-certificate").len(), 2);
    let signing = fact(&out, "android.signing");
    let lineage =
        signing["schemes"].as_array().expect("schemes").iter().find(|s| s["scheme"] == "v3").expect("v3")["signers"][0]["lineage"].clone();
    assert_eq!(lineage[1]["signed_by_previous"]["status"], "passed");

    let out = run("v3-ec.apk");
    assert_eq!(rule(&out, "android.signing-certificate")[0].params["key"], "EC P-256");

    // The other key types, with the algorithms apksigner chose for them.
    for (file, key, algorithm) in [
        ("dsa.apk", "DSA 2048", "DSA with SHA2-256"),
        ("ec384.apk", "EC P-384", "ECDSA with SHA2-512"),
        ("rsa4096.apk", "RSA 4096", "RSASSA-PKCS1-v1_5 with SHA2-512"),
    ] {
        let out = run(file);
        assert_eq!(rule(&out, "android.signing-certificate")[0].params["key"], key);
        let v2 = &fact(&out, "android.signing")["schemes"][0];
        assert_eq!(v2["signers"][0]["algorithms"][0], algorithm, "{file}");
        assert_eq!(v2["signers"][0]["content_digest"]["status"], "passed", "{file}");
        assert_eq!(v2["signers"][0]["signature"]["status"], "passed", "{file}");
        assert_eq!(fact(&out, "android.signing")["v1"]["verified"], true, "{file}");
    }
}

#[test]
fn full_package_findings() {
    let out = analyze(&MemTree::apk("full.apk", FULL.to_vec()));
    let ids = rules_of(&out);
    for expected in [
        "android.package",
        "android.app-label",
        "android.sdk-levels",
        "android.application-class",
        "android.launcher-activity",
        "android.signature-verified",
        "android.signing-certificate",
        "android.debuggable",
        "android.allow-backup",
        "android.cleartext-domains",
        "android.trust-user-cas",
        "android.certificate-pinning",
        "android.debug-overrides",
        "android.target-sdk-old",
        "android.permission-dangerous",
        "android.permission-special",
        "android.permissions-normal",
        "android.permissions-signature",
        "android.manifest-anomalies",
        "android.min-sdk-old",
        "android.permissions-declared",
        "android.components",
        "android.exported-activities",
        "android.exported-services",
        "android.exported-providers",
        "android.implicit-export",
        "android.special-component",
        "android.provider-grant-uri",
        "android.deep-links",
        "android.metadata-key",
        "android.sdk-identifiers",
        "android.google-api-key",
        "android.firebase-config",
        "android.dex-summary",
        "android.code-dynamic-loading",
        "android.code-command-exec",
        "android.code-webview-js-interface",
        "android.code-webview-js-enabled",
        "android.code-custom-trust-manager",
        "android.code-weak-cipher",
        "android.code-weak-digest",
        "android.native-libs",
        "android.abi-mismatch",
        "android.native-16k-pages",
        "android.embedded-code",
        "android.framework",
    ] {
        assert!(ids.contains(&expected), "missing {expected}; have {ids:?}");
    }
    // The network security configuration forbids cleartext in general, so the manifest
    // attribute that allows it does not count.
    assert!(!ids.contains(&"android.cleartext-allowed"));
    assert_eq!(rule(&out, "android.debuggable")[0].severity, Severity::High);
    assert_eq!(rule(&out, "android.debuggable")[0].section, Section::Hardening);

    let dangerous: Vec<&str> = rule(&out, "android.permission-dangerous").iter().filter_map(|f| f.params["permission"].as_str()).collect();
    assert_eq!(dangerous, vec!["android.permission.CAMERA", "android.permission.READ_CONTACTS"]);
    assert_eq!(rule(&out, "android.permission-special")[0].params["permission"], "android.permission.SYSTEM_ALERT_WINDOW");
    assert_eq!(rule(&out, "android.permissions-signature")[0].params["permissions"], "android.permission.INSTALL_PACKAGES");

    // Exported: LinkActivity (attribute), SyncService (intent filter), OpenProvider. The receiver
    // is guarded by a signature permission, the accessibility service by a platform one.
    assert_eq!(rule(&out, "android.exported-activities")[0].params["components"], "com.example.aafixture.LinkActivity");
    assert_eq!(rule(&out, "android.exported-services")[0].params["components"], "com.example.aafixture.SyncService");
    assert_eq!(rule(&out, "android.exported-providers")[0].params["components"], "com.example.aafixture.OpenProvider");
    assert!(!has(&out, "android.exported-receivers"));
    assert_eq!(
        rule(&out, "android.implicit-export")[0].params["components"],
        "com.example.aafixture.MainActivity, com.example.aafixture.SyncService"
    );
    let links = fact(&out, "android.deep_links");
    assert_eq!(links["custom_schemes"], serde_json::json!(["aafixture"]));
    assert_eq!(links["app_link_hosts"], serde_json::json!(["fixture.example.com"]));

    // Secrets are redacted everywhere.
    let all = serde_json::to_string(&(&out.findings, out.facts.iter().map(|f| &f.value).collect::<Vec<_>>())).expect("json");
    assert!(!all.contains("FIXTURE-not-a-real-key") && !all.contains("FIXTURE-resource-key"));
    assert!(all.contains("AIza**"));
    assert_eq!(fact(&out, "android.google_services")["google_app_id"], "1:1234567890:android:abcdef0123456789");

    let config = fact(&out, "android.network_security_config");
    assert_eq!(config["base_config"]["cleartext_permitted"], false);
    assert_eq!(config["base_config"]["trusts_user_cas"], true);
    assert_eq!(config["domain_configs"][0]["domains"][0]["domain"], "legacy.example.com");
    assert_eq!(config["domain_configs"][1]["pins"], 1);

    let small = rule(&out, "android.native-16k-pages")[0];
    assert_eq!(small.params["libraries"], "libsmallpage.so");
    assert_eq!((small.params["count"].as_u64(), small.params["total"].as_u64()), (Some(1), Some(3)));
    let framework = rule(&out, "android.framework");
    assert!(
        framework.iter().any(|f| f.params["name"] == "React Native"
            && f.params["detail_en"].as_str().is_some_and(|d| d.contains("Hermes bytecode version 96")))
    );

    // Every finding has evidence and a rule with text.
    for finding in &out.findings {
        assert!(!finding.evidence.is_empty(), "{} has no evidence", finding.rule);
        assert!(crate::rules::RULES.iter().any(|r| r.id == finding.rule), "{}", finding.rule);
        assert_eq!(finding.id.len(), 64);
    }
    for limitation in &out.limitations {
        assert!(crate::rules::RULES.iter().any(|r| r.id == limitation.code), "{}", limitation.code);
    }
    for fact in &out.facts {
        assert!(FACT_KEYS.contains(&fact.key.as_str()), "{}", fact.key);
    }
    assert!(out.kinds.contains(&("full.apk".to_string(), "apk".to_string())));
}

#[test]
fn dex_header_matches_dexdump() {
    let dex = crate::dex::parse(&fixture("classes.dex")).expect("dex");
    let reference = String::from_utf8(fixture("dexdump-header.txt")).expect("text");
    let value = |name: &str| -> u32 {
        let line = reference.lines().find(|l| l.split(':').next().map(str::trim) == Some(name)).unwrap_or_else(|| panic!("no {name}"));
        line.split(':').nth(1).expect("value").trim().parse().expect("number")
    };
    assert_eq!(dex.file_size, value("file_size"));
    assert_eq!(dex.strings, value("string_ids_size"));
    assert_eq!(dex.types, value("type_ids_size"));
    assert_eq!(dex.protos, value("proto_ids_size"));
    assert_eq!(dex.fields, value("field_ids_size"));
    assert_eq!(dex.methods, value("method_ids_size"));
    assert_eq!(dex.classes, value("class_defs_size"));
    assert_eq!(dex.native_methods, 1);
    assert_eq!(dex.class_names, vec!["Lcom/example/aafixture/App;", "Lcom/example/aafixture/MainActivity;"]);
}

#[test]
fn zip_tricks_are_seen() {
    let out = analyze(&MemTree::apk("zip-tricks.apk", fixture("zip-tricks.apk")));
    let duplicates = rule(&out, "android.zip-duplicate-entries");
    assert_eq!(duplicates[0].params["names"], "classes.dex ×2");
    assert!(rule(&out, "android.zip-header-mismatch")[0].params["entries"].as_str().is_some_and(|e| e.contains("assets/renamed.txt")));
}

#[test]
fn deterministic_output() {
    let run = || {
        let out = analyze(&MemTree::apk("full.apk", FULL.to_vec()));
        serde_json::to_string(&(out.findings, out.facts.iter().map(|f| (&f.key, &f.value)).collect::<Vec<_>>(), out.kinds, out.limitations))
            .expect("json")
    };
    assert_eq!(run(), run());
}

#[test]
fn extracted_folder_is_a_package_without_signature_check() {
    let archive = zipraw::parse(FULL).expect("zip");
    let mut tree = MemTree::default();
    for entry in &archive.entries {
        tree.add(&format!("app/{}", entry.name), None, zipraw::read_entry(FULL, entry, 1 << 26).expect("entry"));
    }
    let out = analyze(&tree.finish());
    assert!(has(&out, "android.package") && has(&out, "android.debuggable") && has(&out, "android.dex-summary"));
    assert_eq!(rule(&out, "android.package")[0].params["format_en"], "APK extracted to a folder");
    assert!(out.limitations.iter().any(|l| l.code == "android.signature-not-checked"));
    assert!(!has(&out, "android.signature-verified") && !has(&out, "android.unsigned"));
}

#[test]
fn app_bundle_base_module() {
    let mut tree = MemTree::default();
    tree.add("app.aab", None, b"PK\x05\x06".to_vec());
    tree.artifacts[0].kind = Some("zip".into());
    tree.artifacts[0].unpacked_by = Some("zip".into());
    tree.add("app.aab/BundleConfig.pb", Some("app.aab"), vec![0x0a, 0x00]);
    tree.add("app.aab/base/manifest/AndroidManifest.xml", Some("app.aab"), crate::aab::tests::sample_manifest());
    tree.add("app.aab/base/resources.pb", Some("app.aab"), crate::aab::tests::sample_table());
    tree.add("app.aab/base/dex/classes.dex", Some("app.aab"), fixture("classes.dex"));
    tree.add("app.aab/feature/manifest/AndroidManifest.xml", Some("app.aab"), crate::aab::tests::sample_manifest());
    let out = analyze(&tree.finish());
    assert!(out.kinds.contains(&("app.aab".to_string(), "aab".to_string())));
    assert_eq!(rule(&out, "android.package").len(), 1);
    assert_eq!(rule(&out, "android.package")[0].params["format_en"], "Android App Bundle");
    assert_eq!(rule(&out, "android.app-label")[0].params["label"], "Example");
    assert!(has(&out, "android.debuggable") && has(&out, "android.dex-summary"));
    assert_eq!(rule(&out, "android.bundle-modules")[0].params["modules"], "base, feature");
    assert!(out.limitations.iter().any(|l| l.code == "android.bundle-modules-not-analyzed"));
}

#[test]
fn set_of_apks() {
    let mut tree = MemTree::default();
    tree.add_zip("set.xapk", None, fixture("set.xapk"));
    let out = analyze(&tree.finish());
    assert!(out.kinds.contains(&("set.xapk".to_string(), "xapk".to_string())));
    assert!(out.kinds.contains(&("set.xapk/config.fixture.apk".to_string(), "apk".to_string())));
    let set = rule(&out, "android.apk-set");
    assert_eq!(set[0].params["apks"], 2);
    assert_eq!(set[0].params["base"], "com.example.aafixture.apk");
    assert_eq!(set[0].params["splits"], "config.fixture");
    assert_eq!(set[0].params["package"], "com.example.aafixture");
    assert!(!has(&out, "android.apk-set-mismatch"));
    assert_eq!(rule(&out, "android.split-apk").len(), 1);
    // The split is checked for its signature, not for its (absent) code.
    assert_eq!(rule(&out, "android.signature-verified").len(), 4);
    assert_eq!(rule(&out, "android.dex-summary").len(), 1);

    // A container whose APKs come from different signers is called out.
    let mut tree = MemTree::default();
    tree.add("app.xapk", None, b"PK".to_vec());
    tree.artifacts[0].kind = Some("zip".into());
    tree.artifacts[0].unpacked_by = Some("zip".into());
    tree.add("app.xapk/manifest.json", Some("app.xapk"), b"{}".to_vec());
    tree.add_zip("app.xapk/base.apk", Some("app.xapk"), fixture("v1v2.apk"));
    tree.add_zip("app.xapk/other.apk", Some("app.xapk"), fixture("debug.apk"));
    let out = analyze(&tree.finish());
    assert_eq!(rule(&out, "android.apk-set-mismatch")[0].params["signers"], 2);
    assert_eq!(fact(&out, "android.apk_set")["apks"].as_array().map(Vec::len), Some(2));
}

#[test]
fn not_android_is_left_alone() {
    let mut tree = MemTree::default();
    tree.add_zip("docs.zip", None, zipraw::tests::build_zip(b"", &[("AndroidManifest.xml", b"<manifest/>"), ("readme.txt", b"hi")]));
    tree.add("src/AndroidManifest.xml", None, b"<?xml version=\"1.0\"?><manifest package=\"x\"/>".to_vec());
    let out = analyze(&tree.finish());
    assert!(out.findings.is_empty(), "{:?}", rules_of(&out));
    assert!(out.kinds.is_empty());
}

/// Damaged files inside a package: the analyzer reports what it can and never panics.
#[test]
fn damaged_members_do_not_panic() {
    let archive = zipraw::parse(FULL).expect("zip");
    let members: Vec<(String, Vec<u8>)> =
        archive.entries.iter().map(|e| (e.name.clone(), zipraw::read_entry(FULL, e, 1 << 26).expect("entry"))).collect();
    let build = |target: &str, change: &dyn Fn(&mut Vec<u8>)| {
        let mut tree = MemTree::default();
        // The container's own bytes are left out: signatures are exercised by another test.
        tree.add("x.apk", None, b"PK".to_vec());
        tree.artifacts[0].kind = Some("zip".into());
        tree.artifacts[0].unpacked_by = Some("zip".into());
        for (name, data) in &members {
            let mut data = data.clone();
            if name == target {
                change(&mut data);
            }
            tree.add(&format!("x.apk/{name}"), Some("x.apk"), data);
        }
        tree.finish()
    };
    for target in
        ["AndroidManifest.xml", "resources.arsc", "classes.dex", "res/xml/network_security_config.xml", "lib/x86_64/libfixture.so"]
    {
        let size = members.iter().find(|(n, _)| n == target).map(|(_, d)| d.len()).expect("member");
        // Truncations.
        for cut in [0, 1, 7, 8, 9, 27, 28, 64, 111, 112, size / 3, size / 2, size - 1] {
            let _ = analyze(&build(target, &|d| d.truncate(cut.min(d.len()))));
        }
        // Single-byte damage, spread over the file.
        let step = (size / 150).max(1);
        for position in (0..size).step_by(step) {
            for value in [0x00u8, 0xff] {
                let _ = analyze(&build(target, &|d| d[position] = value));
            }
        }
        // Every 32-bit field near the start set to a huge value.
        for position in (0..size.min(256)).step_by(4) {
            let _ = analyze(&build(target, &|d| {
                if position + 4 <= d.len() {
                    d[position..position + 4].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
                }
            }));
        }
    }
    // A manifest that is not a manifest at all yields a limitation.
    let out = analyze(&build("AndroidManifest.xml", &|d| d.truncate(4)));
    assert!(out.limitations.iter().any(|l| l.code == "android.manifest-unreadable"));
}

/// Damage to the package file itself: the ZIP and signature readers must hold.
#[test]
fn damaged_package_file_does_not_panic() {
    let apk = fixture("rotated.apk");
    let archive = zipraw::parse(&apk).expect("zip");
    let block = crate::sigblock::find(&apk, &archive).expect("block");
    let (start, end) = (block.start as usize, apk.len());
    // Bytes of the signing block, central directory and end record. The structure readers are
    // also covered byte by byte in their own modules; this goes through the whole analyzer.
    for position in (start..end).step_by(11) {
        let mut bad = apk.clone();
        bad[position] = if position % 2 == 0 { 0x00 } else { 0xff };
        let mut tree = MemTree::default();
        tree.add_zip("x.apk", None, bad);
        let _ = analyze(&tree.finish());
    }
    for cut in (0..apk.len()).step_by(397) {
        let mut tree = MemTree::default();
        tree.add_zip("x.apk", None, apk[..cut].to_vec());
        let _ = analyze(&tree.finish());
    }
}

/// Development aid, not a test: analyzes the package named by `AA_ANDROID_SAMPLE` without the
/// engine and writes a report-shaped JSON to `AA_ANDROID_OUT`. Run with
/// `cargo test --release -p aa-android -- --ignored sample_report`.
#[test]
#[ignore = "needs AA_ANDROID_SAMPLE"]
fn sample_report() {
    let (Ok(sample), Ok(target)) = (std::env::var("AA_ANDROID_SAMPLE"), std::env::var("AA_ANDROID_OUT")) else { return };
    let name = sample.rsplit('/').next().unwrap_or(&sample).to_string();
    let data = std::fs::read(&sample).expect("sample");
    let mut tree = MemTree::default();
    tree.add_zip(&name, None, data);
    let mut tree = tree.finish();
    let started = std::time::Instant::now();
    let out = analyze(&tree);
    let elapsed = started.elapsed();
    let mut summary = serde_json::Map::new();
    for fact in out.facts {
        match fact.artifact {
            Some(path) => {
                if let Some(artifact) = tree.artifacts.iter_mut().find(|a| a.path == path) {
                    artifact.facts.insert(fact.key, fact.value);
                }
            }
            None => {
                summary.insert(fact.key, fact.value);
            }
        }
    }
    for (path, kind) in out.kinds {
        if let Some(artifact) = tree.artifacts.iter_mut().find(|a| a.path == path) {
            artifact.kind = Some(kind);
        }
    }
    let texts: Vec<Json> = out
        .findings
        .iter()
        .map(|f| {
            let rule = crate::rules::RULES.iter().find(|r| r.id == f.rule).expect("rule");
            serde_json::json!({ "rule": f.rule, "section": f.section, "severity": f.severity, "confidence": f.confidence,
                "en": aa_core::fill(rule.text_en, &f.params), "zh": aa_core::fill(rule.text_zh, &f.params) })
        })
        .collect();
    let report = serde_json::json!({
        "artifacts": tree.artifacts.iter().filter(|a| !a.facts.is_empty() || a.kind.is_some()).collect::<Vec<_>>(),
        "findings": out.findings,
        "limitations": out.limitations,
        "summary": summary,
        "texts": texts,
        "analysis_ms": elapsed.as_millis() as u64,
    });
    std::fs::write(target, serde_json::to_vec_pretty(&report).expect("json")).expect("write");
}

/// The tricks malware plays on manifest decoders, applied to the fixture manifest: each variant
/// must decode to the same manifest as the original, as it does on a device.
#[test]
fn hostile_manifest_variants_decode_like_the_original() {
    use crate::manifest::{NoResources, extract};
    let original = fixture("AndroidManifest.bin");
    let reference = extract(&crate::axml::parse(&original), &NoResources).expect("manifest").to_json(1000);
    let u16_at = |d: &[u8], at: usize| u16::from_le_bytes([d[at], d[at + 1]]);
    let u32_at = |d: &[u8], at: usize| u32::from_le_bytes([d[at], d[at + 1], d[at + 2], d[at + 3]]);
    let fix_size = |d: &mut Vec<u8>| {
        let size = d.len() as u32;
        d[4..8].copy_from_slice(&size.to_le_bytes());
    };
    let pool_size = u32_at(&original, 12) as usize;
    let mut variants: Vec<(&str, Vec<u8>, &str)> = Vec::new();

    // 1. A wrong file type.
    let mut v = original.clone();
    v[0..2].copy_from_slice(&0u16.to_le_bytes());
    variants.push(("file type", v, "file type"));

    // 2. A string count far beyond the pool.
    let mut v = original.clone();
    v[16..20].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
    variants.push(("string count", v, "more strings"));

    // 3. Unknown flag bits in the string pool.
    let mut v = original.clone();
    let flags = u32_at(&v, 24) | 0xdead_0000;
    v[24..28].copy_from_slice(&flags.to_le_bytes());
    variants.push(("pool flags", v, "flag bits"));

    // 4. A chunk of unknown type between the string pool and the rest.
    let mut v = original[..8 + pool_size].to_vec();
    v.extend_from_slice(&[0x77, 0x77, 8, 0, 16, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    v.extend_from_slice(&original[8 + pool_size..]);
    fix_size(&mut v);
    variants.push(("extra chunk", v, "unknown type"));

    // 5. A file size field that claims more than the file holds.
    let mut v = original.clone();
    v[4..8].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
    variants.push(("file size", v, "file size field"));

    // 6. Attribute records of 24 bytes instead of 20, with junk in the extra bytes.
    let mut v = original[..8].to_vec();
    let mut pos = 8;
    while pos + 8 <= original.len() {
        let (kind, header, size) = (u16_at(&original, pos), usize::from(u16_at(&original, pos + 2)), u32_at(&original, pos + 4) as usize);
        let chunk = &original[pos..pos + size];
        if kind == 0x0102 {
            let count = usize::from(u16_at(chunk, header + 12));
            let mut rebuilt = chunk[..header + 20].to_vec();
            rebuilt[header + 10..header + 12].copy_from_slice(&24u16.to_le_bytes());
            for i in 0..count {
                rebuilt.extend_from_slice(&chunk[header + 20 + i * 20..header + 40 + i * 20]);
                rebuilt.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            }
            let new_size = rebuilt.len() as u32;
            rebuilt[4..8].copy_from_slice(&new_size.to_le_bytes());
            v.extend_from_slice(&rebuilt);
        } else {
            v.extend_from_slice(chunk);
        }
        pos += size;
    }
    fix_size(&mut v);
    variants.push(("attribute size", v, "attribute records are 24 bytes"));

    // 7. Attribute name strings wiped: names must come from the resource ids.
    let mut v = original.clone();
    for name in ["versionCode", "minSdkVersion", "debuggable", "exported", "permission", "authorities"] {
        let needle: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let at = v.windows(needle.len()).position(|w| w == needle.as_slice()).unwrap_or_else(|| panic!("{name} not in the pool"));
        // Keep the length prefix, replace the characters.
        for (i, byte) in v[at..at + needle.len()].iter_mut().enumerate() {
            *byte = if i % 2 == 0 { b'x' } else { 0 };
        }
    }
    variants.push(("attribute names", v, "differs from the name of its resource id"));

    for (what, data, anomaly) in variants {
        assert!(crate::axml::looks_like_axml(&data), "{what}: not recognised");
        let doc = crate::axml::parse(&data);
        assert!(doc.anomalies.iter().any(|a| a.contains(anomaly)), "{what}: anomalies {:?}", doc.anomalies);
        let manifest = extract(&doc, &NoResources).unwrap_or_else(|| panic!("{what}: no manifest"));
        assert_eq!(manifest.to_json(1000), reference, "{what}");
    }
}
