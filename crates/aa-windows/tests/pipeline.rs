//! Runs the crate's unpackers and analyzer over the fixtures in `tests/data`, the way the
//! engine does, and compares the results with what the reference tools reported when the
//! fixtures were built (`*.ref.txt`, written by `tests/data/make-fixtures.sh`).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

use aa_core::plugin::{Bytes, Output, SinkError, Tree, Unpack, UnpackSink};
use aa_core::{Artifact, Digests, Finding, fill, sha256_hex};
use serde_json::Value;

fn data(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn compare_inf_reference(name: &str, expected_fields: usize) -> Run {
    let reference: Value = serde_json::from_slice(&data(&format!("{name}.ref.json"))).expect("SetupAPI reference");
    assert_eq!(sha256_hex(&data(name)), reference["sha256"]);
    let run = analyze(&[(name, data(name))]);
    let fact = run.fact(name, "windows.inf");
    assert_eq!(fact["issue_count"], 0);
    assert_eq!(fact["installed"], false);
    assert_eq!(fact["platform_selected"], false);
    assert_eq!(fact["catalog_verified"], false);
    let sections = fact["sections"].as_array().expect("INF sections");
    let native = reference["sections"].as_array().expect("native sections");
    assert_eq!(sections.len(), native.len());
    let mut compared = 0;
    for section in sections {
        let expected = native
            .iter()
            .find(|s| s["name"].as_str().expect("native name").eq_ignore_ascii_case(section["name"].as_str().expect("name")))
            .expect("native section");
        let entries = section["entries"].as_array().expect("entries");
        let native_entries = expected["entries"].as_array().expect("native entries");
        assert_eq!(entries.len(), native_entries.len());
        for (entry, expected) in entries.iter().zip(native_entries) {
            if let Some(fields) = entry["neutral_fields"].as_array() {
                assert_eq!(entry["neutral_fields"], expected["fields"], "{} line {}", section["name"], entry["line"]);
                compared += fields.len();
            }
        }
    }
    assert_eq!(compared, expected_fields);
    assert_eq!(run.findings("windows.inf").len(), 1);
    assert!(run.out.limitations.iter().any(|l| l.code == "windows.inf-semantics-unresolved"));
    run
}

#[test]
fn independent_inf_source_matches_read_only_setupapi_fields_without_platform_selection() {
    let run = compare_inf_reference("upstream-nullFilter.inf", 91);
    let sections = run.fact("upstream-nullFilter.inf", "windows.inf")["sections"].as_array().expect("INF sections");
    let service = sections.iter().find(|s| s["name"] == "NullFilter.Service").expect("service declaration section");
    let binary = service["entries"]
        .as_array()
        .expect("service entries")
        .iter()
        .find(|e| e["key"] == "ServiceBinary")
        .expect("literal service binary");
    assert_eq!(binary["fields"][0], r"%13%\%DriverName%.sys");
    assert!(binary["neutral_fields"].is_null(), "directory IDs remain unresolved");
}

#[test]
fn controlled_inf_quotes_and_continuations_match_setupapi_snapshot() {
    compare_inf_reference("native-inf-syntax.inf", 25);
}

#[test]
fn independent_shell_link_relative_path_can_name_a_supplied_sibling() {
    let run = analyze(&[("upstream-test.lnk", data("upstream-test.lnk")), ("a.txt", b"supplied text".to_vec())]);
    let refs = run.fact("upstream-test.lnk", "windows.input-references")["references"].as_array().expect("reference declarations");
    let relative = refs.iter().find(|r| r["field"] == "RelativePath").expect("relative path declaration");
    assert_eq!(relative["target"], "a.txt");
    assert_eq!(relative["status"], "matched-supplied-declaration");
    assert_eq!(relative["target_sha256"], sha256_hex(b"supplied text"));
    assert_eq!(run.findings("windows.input-reference").len(), 1);
    assert_eq!(
        run.fact("upstream-test.lnk", "windows.shell-link")["target_resolved"],
        false,
        "a declaration link does not resolve the Windows launch target"
    );
}

fn task_declaration<'a>(root: &'a Value, path: &[&str]) -> &'a Value {
    path.iter().fold(root, |node, name| {
        node["children"].as_array().expect("declaration children").iter().find(|n| n["element"] == *name).expect("native declaration")
    })
}

#[test]
fn unregistered_native_task_matches_literal_fields_without_guessing_omitted_values() {
    let reference: Value = serde_json::from_slice(&data("native-task.xml.ref.json")).expect("task reference");
    let run = analyze(&[("native-task.xml", data("native-task.xml"))]);
    let fact = run.fact("native-task.xml", "windows.scheduled-task");
    assert_eq!(fact["actions"], 1);
    assert_eq!(fact["triggers"], 2);
    assert_eq!(fact["principals"], 1);
    assert_eq!(fact["registered"], false);
    assert_eq!(fact["issue_count"], 0);
    let root = &fact["declarations"];
    for (path, key) in [
        (vec!["Actions", "Exec", "Command"], "command"),
        (vec!["Actions", "Exec", "Arguments"], "arguments"),
        (vec!["Actions", "Exec", "WorkingDirectory"], "working_directory"),
        (vec!["Principals", "Principal", "UserId"], "principal"),
        (vec!["Principals", "Principal", "RunLevel"], "run_level"),
        (vec!["Triggers", "TimeTrigger", "StartBoundary"], "time_start"),
    ] {
        assert_eq!(task_declaration(root, &path)["text"], reference[key], "{path:?}");
    }
    for (path, key) in [
        (vec!["Triggers", "TimeTrigger", "Enabled"], "time_enabled"),
        (vec!["Triggers", "LogonTrigger", "Enabled"], "logon_enabled"),
        (vec!["Settings", "Enabled"], "task_enabled"),
    ] {
        assert_eq!(task_declaration(root, &path)["text"], reference[key].to_string());
    }
    assert_eq!(task_declaration(root, &["Actions"])["attributes"]["Context"], reference["action_context"]);
    let principal = task_declaration(root, &["Principals", "Principal"]);
    assert!(
        !principal["children"].as_array().expect("principal fields").iter().any(|n| n["element"] == "LogonType"),
        "native serializer omits this field; the reader must not invent it"
    );
    assert_eq!(run.findings("windows.task-highest-available").len(), 1);
    let summary = run.findings("windows.scheduled-task");
    let summary_rule = aa_windows::analyzers()
        .into_iter()
        .flat_map(|a| a.rules().to_vec())
        .find(|r| r.id == "windows.scheduled-task")
        .expect("summary wording");
    let rendered = fill(summary_rule.text_en, &summary[0].params);
    assert!(rendered.contains("1 supported action, 2 supported triggers and 1 supported principal"), "{rendered}");
    assert_eq!(run.findings("windows.task-startup-trigger").len(), 1, "disabled trigger is a declaration, not an active task");
}

#[test]
fn independent_task_deployment_sample_is_read_as_data_with_encoding_mismatch_noted() {
    assert_eq!(sha256_hex(&data("upstream-task.xml")), "a426a793001633d0f4eab87ffd5fa82e157d15d5ad924ba95617136bc557fe59");
    let run = analyze(&[("upstream-task.xml", data("upstream-task.xml"))]);
    let fact = run.fact("upstream-task.xml", "windows.scheduled-task");
    let root = &fact["declarations"];
    assert_eq!(task_declaration(root, &["Actions", "Exec", "Command"])["text"], "powershell.exe");
    assert_eq!(task_declaration(root, &["Triggers", "TimeTrigger", "Repetition", "Interval"])["text"], "PT1M");
    assert_eq!(task_declaration(root, &["Principals", "Principal", "UserId"])["text"], "system");
    assert_eq!(fact["registered"], false);
    assert!(
        run.out.limitations.iter().any(|l| l.code == "windows.task-partial" && l.detail.as_deref().is_some_and(|d| d.contains("encoding")))
    );
}

#[test]
fn native_registry_export_matches_read_only_registry_reference() {
    let reference: Value = serde_json::from_slice(&data("native-codepages.reg.ref.json")).expect("registry reference");
    let run = analyze(&[("native-codepages.reg", data("native-codepages.reg"))]);
    let fact = run.fact("native-codepages.reg", "windows.registry");
    assert_eq!(fact["applied"], false);
    assert_eq!(fact["issue_count"], 0);
    let entries = fact["entries"].as_array().expect("registry entries");
    let keys = reference["keys"].as_array().expect("reference keys");
    assert_eq!(entries.len(), keys.iter().map(|key| key["values"].as_array().expect("values").len() + 1).sum::<usize>());
    for key in keys {
        assert!(entries.iter().any(|e| e["operation"] == "create_key" && e["key"] == key["key"]));
        for value in key["values"].as_array().expect("reference values") {
            let entry = entries
                .iter()
                .find(|e| e["operation"] == "set_value" && e["key"] == key["key"] && e["name"] == value["name"])
                .expect("native value declaration");
            assert_eq!(entry["value"], value["value"]);
            assert_eq!(entry["value_type"], if value["kind"] == "DWord" { 4 } else { 1 });
        }
    }
    assert_eq!(run.findings("windows.registry").len(), 1);
}

#[test]
fn shell_links_match_native_producer_and_independent_fixture_declarations() {
    assert_eq!(sha256_hex(&data("upstream-test.lnk")), "09ac337f52c4c9dc49772e97060145a316cb4af076cfb122fb4a219ecbfbfdd7");
    let reference: Value = serde_json::from_slice(&data("native.lnk.ref.json")).expect("native reference");
    let run = analyze(&[("native.lnk", data("native.lnk"))]);
    let fact = run.fact("native.lnk", "windows.shell-link");
    let declarations = fact["declarations"].as_array().expect("declarations");
    for (field, key) in [
        ("LinkInfo/LocalBasePath", "target"),
        ("Name", "description"),
        ("Arguments", "arguments"),
        ("WorkingDirectory", "working_directory"),
    ] {
        assert!(declarations.iter().any(|d| d["field"] == field && d["value"] == reference[key]), "{field}: {fact}");
    }
    let icon = format!(
        "{},{}",
        declarations.iter().find(|d| d["field"] == "IconLocation").expect("icon")["value"].as_str().expect("path"),
        fact["icon_index"]
    );
    assert_eq!(icon, reference["icon"].as_str().expect("reference icon"));
    assert_eq!(fact["show_command"], reference["show_command"]);
    assert_eq!(fact["target_resolved"], false);
    assert_eq!(run.findings("windows.shell-link").len(), 1);
    assert!(run.out.limitations.iter().any(|l| l.code == "windows.shortcut-target-unresolved"));

    let upstream = analyze(&[("upstream-test.lnk", data("upstream-test.lnk"))]);
    let fact = upstream.fact("upstream-test.lnk", "windows.shell-link");
    assert!(
        fact["declarations"]
            .as_array()
            .expect("upstream declarations")
            .iter()
            .any(|d| d["field"] == "LinkInfo/LocalBasePath" && d["value"] == r"C:\test\a.txt")
    );
    assert!(upstream.out.limitations.iter().any(|l| l.code == "windows.shortcut-partial"));
    let disguised = analyze(&[("disguised.bin", data("upstream-test.lnk"))]);
    assert_eq!(disguised.findings("windows.shell-link").len(), 1, "magic recognition does not depend on extension");
    let damaged = analyze(&[("damaged.lnk", vec![0; 8])]);
    assert!(damaged.out.limitations.iter().any(|l| l.code == "windows.shortcut-unreadable"));
}

#[test]
fn windows_generated_url_matches_the_native_producer_and_small_urls_are_read() {
    let reference: Value = serde_json::from_slice(&data("native.url.ref.json")).expect("native producer reference");
    let run = analyze(&[("native.url", data("native.url"))]);
    let fact = run.fact("native.url", "windows.internet-shortcut");
    assert!(fact["fields"].as_array().expect("field declarations").contains(&serde_json::json!(["url", reference["target"]])));
    assert_eq!(fact["target_resolved"], false);
    assert_eq!(run.findings("windows.internet-shortcut").len(), 1);
    assert!(run.out.limitations.iter().any(|l| l.code == "windows.shortcut-partial"), "native extra properties are acknowledged");
    let small = analyze(&[("small.url", b"[InternetShortcut]\nURL=https://example.invalid/\n".to_vec())]);
    assert_eq!(small.findings("windows.internet-shortcut").len(), 1, "text shortcuts may be shorter than a PE header");
    let sensitive = analyze(&[(
        "private.url",
        b"[InternetShortcut]\nURL=https://user:fixture-password@example.invalid/?token=fixture-token\n".to_vec(),
    )]);
    let fact = serde_json::to_string(sensitive.fact("private.url", "windows.internet-shortcut")).expect("facts JSON");
    let evidence = serde_json::to_string(&sensitive.out.findings).expect("findings JSON");
    for secret in ["fixture-password", "fixture-token"] {
        assert!(!fact.contains(secret));
        assert!(!evidence.contains(secret));
    }
}

fn reference(name: &str) -> String {
    String::from_utf8_lossy(&data(name)).into_owned()
}

/// An in-memory artifact tree.
#[derive(Default)]
struct MemoryTree {
    artifacts: Vec<Artifact>,
    contents: BTreeMap<String, Vec<u8>>,
}

impl Tree for MemoryTree {
    fn summary(&self) -> &BTreeMap<String, Value> {
        static COMPLETE: std::sync::LazyLock<BTreeMap<String, Value>> =
            std::sync::LazyLock::new(|| BTreeMap::from([("engine.input-listing".into(), serde_json::json!({"complete": true}))]));
        &COMPLETE
    }
    fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    fn read(&self, path: &str) -> std::io::Result<Bytes> {
        self.contents.get(path).map(|b| Bytes::from_vec(b.clone())).ok_or_else(|| std::io::Error::other("no such artifact"))
    }
}

struct Sink {
    children: Vec<(String, Vec<u8>)>,
    limitations: Vec<String>,
}

impl UnpackSink for Sink {
    fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).map_err(|e| SinkError::Read(e.to_string()))?;
        if self.children.len() >= 10_000 {
            return Err(SinkError::LimitReached);
        }
        self.children.push((path.replace('\\', "/"), bytes));
        Ok(())
    }

    fn limitation(&mut self, code: &str, _detail: Option<String>) {
        self.limitations.push(code.to_string());
    }
}

/// What a run produced.
struct Run {
    tree: MemoryTree,
    out: Output,
    /// Limitation codes raised by unpackers.
    unpack_limitations: Vec<String>,
    /// `artifact path -> kind` as the unpackers named them.
    unpacked: BTreeMap<String, String>,
}

impl Run {
    fn fact(&self, path: &str, key: &str) -> &Value {
        self.tree.get(path).and_then(|a| a.facts.get(key)).unwrap_or_else(|| panic!("no fact {key} on {path}"))
    }

    fn findings(&self, rule: &str) -> Vec<&Finding> {
        self.out.findings.iter().filter(|f| f.rule == rule).collect()
    }

    fn rules(&self) -> BTreeSet<&str> {
        self.out.findings.iter().map(|f| f.rule.as_str()).collect()
    }

    fn sha256(&self, path: &str) -> String {
        sha256_hex(self.tree.contents.get(path).unwrap_or_else(|| panic!("no artifact {path}")))
    }

    fn paths(&self) -> Vec<&str> {
        self.tree.artifacts.iter().map(|a| a.path.as_str()).collect()
    }
}

/// Unpacks and analyzes the given files as one input folder.
fn analyze(files: &[(&str, Vec<u8>)]) -> Run {
    let mut unpackers = aa_windows::unpackers();
    unpackers.extend(aa_unpack::unpackers());
    let mut tree = MemoryTree::default();
    let mut unpack_limitations = Vec::new();
    let mut unpacked = BTreeMap::new();
    let mut queue: Vec<(String, Option<String>, Vec<u8>, u32)> =
        files.iter().map(|(name, bytes)| (name.to_string(), None, bytes.clone(), 0)).collect();
    while let Some((path, parent, bytes, depth)) = queue.pop() {
        let mut artifact = Artifact {
            path: path.clone(),
            parent,
            size: bytes.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: sha256_hex(&bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        };
        if depth < 5 && !bytes.is_empty() {
            for unpacker in &unpackers {
                let mut sink = Sink { children: Vec::new(), limitations: Vec::new() };
                let kind = match unpacker.unpack(&artifact, &bytes, &mut sink) {
                    Unpack::NotMine => continue,
                    Unpack::Done { kind } | Unpack::Failed { kind, .. } => kind,
                };
                artifact.kind = Some(kind.to_string());
                artifact.unpacked_by = Some(unpacker.id().to_string());
                unpacked.insert(path.clone(), kind.to_string());
                unpack_limitations.extend(sink.limitations);
                let mut taken = BTreeSet::new();
                for (name, child) in sink.children {
                    // Like the engine: a second entry of the same name gets a numbered suffix.
                    let mut full = format!("{path}/{name}");
                    let mut copy = 2;
                    while !taken.insert(full.clone()) {
                        full = format!("{path}/{name} ({copy})");
                        copy += 1;
                    }
                    queue.push((full, Some(path.clone()), child, depth + 1));
                }
                break;
            }
        }
        tree.contents.insert(path, bytes);
        tree.artifacts.push(artifact);
    }
    tree.artifacts.sort_by(|a, b| a.path.cmp(&b.path));

    let analyzers = aa_windows::analyzers();
    let mut out = Output::default();
    for analyzer in &analyzers {
        let mut file_pass = Output::default();
        for artifact in &tree.artifacts {
            analyzer.analyze_file(&tree, artifact, &mut file_pass);
        }
        for fact in file_pass.facts.drain(..) {
            match &fact.artifact {
                Some(path) => {
                    if let Some(artifact) = tree.artifacts.iter_mut().find(|a| &a.path == path) {
                        artifact.facts.insert(fact.key.clone(), fact.value.clone());
                    }
                }
                None => out.facts.push(fact),
            }
        }
        out.findings.append(&mut file_pass.findings);
        out.limitations.append(&mut file_pass.limitations);
        out.kinds.append(&mut file_pass.kinds);
        analyzer.analyze_tree(&tree, &mut out);
        // Facts the tree pass attaches to artifacts are merged like those of the file pass.
        let (attached, summary): (Vec<_>, Vec<_>) = out.facts.drain(..).partition(|f| f.artifact.is_some());
        out.facts = summary;
        for fact in attached {
            if let Some(artifact) = tree.artifacts.iter_mut().find(|a| Some(&a.path) == fact.artifact.as_ref()) {
                artifact.facts.insert(fact.key, fact.value);
            }
        }
    }
    check_rules(&out, &unpack_limitations);
    Run { tree, out, unpack_limitations, unpacked }
}

fn run_one(name: &str) -> Run {
    analyze(&[(name, data(name))])
}

/// Every rule and limitation code that was emitted has text in both languages, and every
/// placeholder of the text is filled by the finding's params.
fn check_rules(out: &Output, unpack_limitations: &[String]) {
    let mut rules: BTreeMap<&str, &aa_core::plugin::Rule> = BTreeMap::new();
    for analyzer in aa_windows::analyzers() {
        rules.extend(analyzer.rules().iter().map(|r| (r.id, r)));
    }
    for unpacker in aa_windows::unpackers() {
        rules.extend(unpacker.rules().iter().map(|r| (r.id, r)));
    }
    for rule in rules.values() {
        for text in [rule.title_zh, rule.title_en, rule.text_zh, rule.text_en] {
            assert!(!text.trim().is_empty(), "rule {} has an empty text", rule.id);
        }
    }
    for finding in &out.findings {
        let rule = rules.get(finding.rule.as_str()).unwrap_or_else(|| panic!("finding uses unknown rule {}", finding.rule));
        assert!(!finding.evidence.is_empty(), "{} has no evidence", finding.rule);
        assert_eq!(finding.id.len(), 64, "{} is not sealed", finding.rule);
        for text in [rule.text_zh, rule.text_en] {
            let filled = fill(text, &finding.params);
            assert!(!filled.contains('{'), "{}: unfilled placeholder in {filled:?}", finding.rule);
        }
    }
    for code in out.limitations.iter().map(|l| l.code.as_str()).chain(unpack_limitations.iter().map(String::as_str)) {
        assert!(rules.contains_key(code), "limitation uses unknown code {code}");
    }
}

/// `sha256 -> path` pairs from a `sha256sum` listing inside a reference file.
fn reference_hashes(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once("  "))
        .filter(|(hash, _)| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|(hash, path)| (hash.to_string(), path.trim_start_matches("./").to_string()))
        .collect()
}

/// `Nov 19 22:13:56 2026 GMT` as `2026-11-19T22:13:56Z`.
fn openssl_time(text: &str) -> String {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        .iter()
        .position(|m| *m == parts[0])
        .expect("month")
        + 1;
    format!("{}-{month:02}-{:02}T{}Z", parts[3], parts[1].parse::<u32>().expect("day"), parts[2])
}

/// The first value after `label` on any line of `text`.
fn after<'a>(text: &'a str, label: &str) -> Vec<&'a str> {
    text.lines().filter_map(|line| line.trim().strip_prefix(label)).map(str::trim).collect()
}

// ---- Authenticode ------------------------------------------------------------------------------

/// Compares one signed fixture with osslsigncode's verification output.
fn assert_matches_osslsigncode(name: &str, expected_signatures: usize) -> Run {
    let run = run_one(&format!("{name}.exe"));
    let reference = reference(&format!("{name}.ref.txt"));
    let fact = run.fact(&format!("{name}.exe"), "windows.authenticode");
    let signatures = fact["signatures"].as_array().expect("signatures");
    assert_eq!(signatures.len(), expected_signatures, "{name}: number of signatures");
    assert_eq!(fact["signed"], true);

    let digests = after(&reference, "Current message digest    :");
    let calculated = after(&reference, "Calculated message digest :");
    assert_eq!(digests.len(), expected_signatures);
    for (index, signature) in signatures.iter().enumerate() {
        // osslsigncode prints the signed digest and the one it recomputed.
        assert_eq!(signature["signed_digest"].as_str().expect("digest").to_uppercase(), digests[index], "{name}: signed digest {index}");
        assert_eq!(
            signature["computed_digest"].as_str().expect("digest").to_uppercase(),
            calculated[index],
            "{name}: computed digest {index}"
        );
        for check in ["file_digest", "content_digest", "signature", "chain"] {
            assert_eq!(signature["checks"][check], "passed", "{name}: {check} of signature {index}");
        }
    }
    // The first "Signer #0" block is the signing certificate.
    let subject = after(&reference, "Subject:")[0];
    let ours = format!("/{}", signatures[0]["signer"]["subject"].as_str().expect("subject").replace(", ", "/"));
    assert_eq!(ours, subject, "{name}: signer subject");
    let serial = after(&reference, "Serial :")[0];
    assert_eq!(signatures[0]["signer"]["serial"].as_str().expect("serial").to_uppercase(), serial, "{name}: signer serial");
    let algorithm = after(&reference, "Message digest algorithm  :")[0];
    assert_eq!(signatures[0]["digest_algorithm"].as_str().expect("algorithm").replace('-', ""), algorithm);
    run
}

#[test]
fn rsa_signature_with_rfc3161_timestamp_matches_osslsigncode() {
    let run = assert_matches_osslsigncode("hello-signed", 1);
    let reference = reference("hello-signed.ref.txt");
    let signature = &run.fact("hello-signed.exe", "windows.authenticode")["signatures"][0];
    assert_eq!(signature["program_name"], "Hello Fixture");
    assert_eq!(signature["more_info_url"], "https://example.invalid/hello");
    assert_eq!(signature["signer"]["key"], "RSA 2048");
    assert_eq!(signature["issuers"][0]["common_name"], "Fixture Test Root CA");
    assert_eq!(signature["chain_reaches_embedded_root"], true);
    let stamp = &signature["timestamps"][0];
    assert_eq!(stamp["kind"], "rfc3161");
    assert_eq!(stamp["time"].as_str().expect("time"), openssl_time(after(&reference, "Timestamp time:")[0]));
    assert_eq!(stamp["authority"]["common_name"], "Fixture Timestamp Authority");
    for check in ["covers_signature", "content_digest", "signature", "chain_check"] {
        assert_eq!(stamp[check], "passed", "timestamp {check}");
    }
    assert_eq!(signature["valid_at_timestamp"], true);
    // One Provenance finding for the signer, none about problems.
    let signers = run.findings("windows.signers");
    assert_eq!(signers.len(), 1);
    assert_eq!(signers[0].params["signer"], "Fixture Code Signing");
    assert_eq!(signers[0].params["verified"], 1);
    assert_eq!(signers[0].params["timestamped"], 1);
    assert_eq!(signers[0].params["authorities"], "Fixture Timestamp Authority");
    assert_eq!(signers[0].confidence, aa_core::Confidence::Verified);
    for rule in run.rules() {
        assert!(!rule.starts_with("windows.signature-") && rule != "windows.data-after-signature", "unexpected {rule}");
    }
}

#[test]
fn dual_signature_is_read_as_two() {
    let run = assert_matches_osslsigncode("hello-dual", 2);
    let signatures = &run.fact("hello-dual.exe", "windows.authenticode")["signatures"];
    assert_eq!(signatures[0]["digest_algorithm"], "SHA-1");
    assert_eq!(signatures[0]["nested"], false);
    assert_eq!(signatures[1]["digest_algorithm"], "SHA-256");
    assert_eq!(signatures[1]["nested"], true);
    assert_eq!(signatures[1]["timestamps"].as_array().map(Vec::len), Some(1));
    // A SHA-256 signature is present, so the SHA-1 one is not reported as weak.
    assert!(run.findings("windows.signature-weak-digest").is_empty());
    assert_eq!(run.findings("windows.signers")[0].params["algorithms"], "SHA-1 + SHA-256");
}

#[test]
fn sha1_only_signature_is_flagged_weak_and_untimestamped() {
    let run = assert_matches_osslsigncode("hello-sha1", 1);
    let weak = run.findings("windows.signature-weak-digest");
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].references, ["CWE-328"]);
    assert_eq!(run.findings("windows.signature-no-timestamp").len(), 1);
}

#[test]
fn ecdsa_signature_verifies() {
    let run = assert_matches_osslsigncode("hello-ecdsa", 1);
    let signature = &run.fact("hello-ecdsa.exe", "windows.authenticode")["signatures"][0];
    assert_eq!(signature["signer"]["key"], "ECDSA P-256");
    assert_eq!(signature["digest_algorithm"], "SHA-384");
}

#[test]
fn self_signed_certificate_is_reported() {
    let run = run_one("hello-selfsigned.exe");
    let signature = &run.fact("hello-selfsigned.exe", "windows.authenticode")["signatures"][0];
    for check in ["file_digest", "content_digest", "signature", "chain"] {
        assert_eq!(signature["checks"][check], "passed");
    }
    let found = run.findings("windows.signature-self-signed");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].params["signer"], "CN=Fixture Self Signed");
}

#[test]
fn unsigned_file_is_counted_not_flagged() {
    let run = run_one("hello.exe");
    assert_eq!(run.fact("hello.exe", "windows.authenticode")["signed"], false);
    let unsigned = run.findings("windows.unsigned-files");
    assert_eq!(unsigned.len(), 1);
    assert_eq!((&unsigned[0].params["unsigned"], &unsigned[0].params["total"]), (&Value::from(1), &Value::from(1)));
    assert!(run.findings("windows.signers").is_empty());
}

/// Offset and size of the certificate table, from the fact.
fn certificate_table(run: &Run, path: &str) -> (usize, usize) {
    let fact = run.fact(path, "windows.authenticode");
    (fact["table_offset"].as_u64().expect("offset") as usize, fact["table_size"].as_u64().expect("size") as usize)
}

#[test]
fn modification_after_signing_is_detected() {
    let original = data("hello-signed.exe");
    // A byte of code changed: the file digest no longer matches, the signature itself is intact.
    let mut changed = original.clone();
    changed[0x450] ^= 0xff;
    let run = analyze(&[("changed.exe", changed)]);
    let signature = &run.fact("changed.exe", "windows.authenticode")["signatures"][0];
    assert_eq!(signature["checks"]["file_digest"], "failed");
    assert_eq!(signature["checks"]["signature"], "passed");
    assert_ne!(signature["signed_digest"], signature["computed_digest"]);
    let found = run.findings("windows.signature-digest-mismatch");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, aa_core::Severity::High);
    assert_eq!(run.findings("windows.signers")[0].params["verified"], 0);
    assert_eq!(run.findings("windows.signers")[0].severity, aa_core::Severity::Medium);

    // The checksum and the certificate-table entry are outside the hash: changing them is not a modification.
    let reference_run = run_one("hello-signed.exe");
    let mut harmless = original.clone();
    let pe = u32::from_le_bytes(harmless[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
    harmless[pe + 24 + 64] ^= 0xff;
    let harmless_run = analyze(&[("hello-signed.exe", harmless)]);
    assert_eq!(harmless_run.fact("hello-signed.exe", "windows.authenticode")["signatures"][0]["checks"]["file_digest"], "passed");
    assert_eq!(harmless_run.findings("windows.checksum-mismatch").len(), 1);
    assert!(reference_run.findings("windows.checksum-mismatch").is_empty());
}

/// Position of `needle` in `haystack`.
fn position(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).position(|w| w == needle).expect("bytes present")
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex")).collect()
}

#[test]
fn damaged_signature_data_is_detected() {
    let original = data("hello-signed.exe");
    let reference = reference("hello-signed.ref.txt");

    // The signed attribute holding the digest of the content: changing it breaks both the
    // content digest and the signature over the attributes.
    let message_digest = unhex(after(&reference, "Message digest:")[0]);
    let mut damaged = original.clone();
    let at = position(&damaged, &message_digest);
    damaged[at] ^= 0x01;
    let run = analyze(&[("damaged.exe", damaged)]);
    let checks = &run.fact("damaged.exe", "windows.authenticode")["signatures"][0]["checks"];
    assert_eq!(checks["content_digest"], "failed");
    assert_eq!(checks["signature"], "failed");
    // The file itself is untouched.
    assert_eq!(checks["file_digest"], "passed");
    let found = run.findings("windows.signature-invalid");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, aa_core::Severity::High);
    assert_eq!(found[0].params["signer"], "Fixture Code Signing");

    // The file digest inside the signed content: the content no longer matches its own digest
    // attribute, and no longer matches the file.
    let file_digest = unhex(after(&reference, "Current message digest    :")[0]);
    let mut damaged = original.clone();
    let at = position(&damaged, &file_digest);
    damaged[at] ^= 0x01;
    let run = analyze(&[("damaged.exe", damaged)]);
    let checks = &run.fact("damaged.exe", "windows.authenticode")["signatures"][0]["checks"];
    assert_eq!(checks["file_digest"], "failed");
    assert_eq!(checks["content_digest"], "failed");

    // The timestamp covers the signature value: with the token's imprint changed it no longer does.
    let run_ok = run_one("hello-signed.exe");
    let (table, size) = certificate_table(&run_ok, "hello-signed.exe");
    let mut seen_timestamp_failure = false;
    for at in (table + size - 1400..table + size - 300).step_by(97) {
        let mut damaged = original.clone();
        damaged[at] ^= 0x01;
        let run = analyze(&[("damaged.exe", damaged)]);
        seen_timestamp_failure |= !run.findings("windows.signature-timestamp-invalid").is_empty();
    }
    assert!(seen_timestamp_failure, "damage inside the timestamp token went unnoticed");
}

#[test]
fn data_hidden_in_the_certificate_table_is_reported() {
    let original = data("hello-signed.exe");
    let run_ok = run_one("hello-signed.exe");
    let (table, size) = certificate_table(&run_ok, "hello-signed.exe");
    assert_eq!(table + size, original.len());
    let pe = u32::from_le_bytes(original[0x3c..0x40].try_into().expect("e_lfanew")) as usize;
    // PE32+: the data directories start 112 bytes into the optional header; entry 4 is the certificate table.
    let entry = pe + 24 + 112 + 4 * 8;
    assert_eq!(u32::from_le_bytes(original[entry..entry + 4].try_into().expect("entry")) as usize, table);

    // The classic trick: grow the WIN_CERTIFICATE and the directory entry over appended bytes.
    let mut smuggled = original.clone();
    smuggled.extend_from_slice(b"SMUGGLED PAYLOAD");
    let grow = |bytes: &mut Vec<u8>, at: usize| {
        let value = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("u32")) + 16;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    };
    grow(&mut smuggled, entry + 4);
    grow(&mut smuggled, table);
    let run_smuggled = analyze(&[("smuggled.exe", smuggled)]);
    let fact = run_smuggled.fact("smuggled.exe", "windows.authenticode");
    // The signature still verifies in full: that is what makes the trick work.
    assert_eq!(fact["signatures"][0]["checks"]["file_digest"], "passed");
    assert_eq!(fact["signatures"][0]["checks"]["signature"], "passed");
    let found = run_smuggled.findings("windows.signature-extra-data");
    assert_eq!(found.len(), 1);
    // The 16 smuggled bytes, plus the padding that was already between the signature and them.
    let bytes = found[0].params["bytes"].as_u64().expect("bytes");
    assert!((16..24).contains(&bytes), "{bytes}");
    assert_eq!(found[0].references, ["CVE-2013-3900"]);

    // Bytes simply appended after the table are reported too, and they break the digest.
    let mut appended = original.clone();
    appended.extend_from_slice(b"APPENDED");
    let run_appended = analyze(&[("appended.exe", appended)]);
    assert_eq!(run_appended.findings("windows.data-after-signature")[0].params["bytes"], 8);
    assert_eq!(run_appended.fact("appended.exe", "windows.authenticode")["signatures"][0]["checks"]["file_digest"], "failed");
}

// ---- resources ---------------------------------------------------------------------------------

#[test]
fn version_resource_matches_exiftool() {
    let run = run_one("hello.exe");
    let version = run.fact("hello.exe", "windows.version");
    let reference = reference("hello.version.ref.txt");
    let expected: BTreeMap<&str, &str> = reference.lines().filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim(), v.trim())).collect();
    for (ours, theirs) in [
        ("CompanyName", "CompanyName"),
        ("ProductName", "ProductName"),
        ("FileDescription", "FileDescription"),
        ("FileVersion", "FileVersion"),
        ("ProductVersion", "ProductVersion"),
        ("OriginalFilename", "OriginalFileName"),
        ("InternalName", "InternalName"),
        ("LegalCopyright", "LegalCopyright"),
    ] {
        assert_eq!(version["strings"][ours].as_str(), expected.get(theirs).copied(), "{ours}");
    }
    assert_eq!(version["file_version"].as_str(), expected.get("FileVersionNumber").copied());
    assert_eq!(version["product_version"].as_str(), expected.get("ProductVersionNumber").copied());
    assert_eq!(version["translations"][0], serde_json::json!({ "language": 0x409, "code_page": 1200 }));
    let identity = run.findings("windows.version-info");
    assert_eq!(identity.len(), 1);
    assert!(identity[0].params["fields"].as_str().expect("fields").starts_with("ProductName=Hello Fixture; ProductVersion=1.2; "));
    assert!(run.findings("windows.original-filename-mismatch").is_empty());
}

#[test]
fn renamed_file_and_manifest_are_reported() {
    let run = analyze(&[("svchost.exe", data("hello.exe"))]);
    let renamed = run.findings("windows.original-filename-mismatch");
    assert_eq!(renamed.len(), 1);
    assert_eq!(renamed[0].confidence, aa_core::Confidence::Heuristic);
    assert_eq!(renamed[0].evidence[0].value["original_filename"], "hello.exe");

    let manifest = run.fact("svchost.exe", "windows.manifest");
    assert_eq!(manifest["requested_execution_level"], "requireAdministrator");
    assert_eq!(manifest["assembly_identity"]["name"], "FixtureWorks.Hello");
    assert_eq!(manifest["dpi_awareness"], "PerMonitorV2");
    assert_eq!(run.findings("windows.manifest-elevation")[0].params["level"], "requireAdministrator");
    let resources = run.fact("svchost.exe", "windows.resources");
    let types: Vec<&str> = resources["types"].as_array().expect("types").iter().filter_map(|t| t["type"].as_str()).collect();
    assert_eq!(types, ["MANIFEST", "VERSION"]);
}

#[test]
fn imports_are_grouped_into_capabilities() {
    let run = run_one("hello.exe");
    let capabilities = run.fact("hello.exe", "windows.capabilities");
    let injection: Vec<&str> = capabilities["injection"].as_array().expect("injection").iter().filter_map(Value::as_str).collect();
    assert_eq!(injection, ["kernel32.dll!CreateRemoteThread", "kernel32.dll!VirtualAllocEx", "kernel32.dll!WriteProcessMemory"]);
    assert!(capabilities["network"].as_array().expect("network").contains(&Value::from("ws2_32.dll!connect")));
    assert!(capabilities["registry"].as_array().expect("registry").contains(&Value::from("advapi32.dll!RegSetValueExA")));
    let found = run.findings("windows.imports-injection");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].confidence, aa_core::Confidence::Derived);
    // Registry access is too common to be a finding of its own.
    assert!(!run.rules().iter().any(|r| r.contains("registry")));
}

// ---- .NET --------------------------------------------------------------------------------------

#[test]
fn dotnet_metadata_matches_monodis() {
    let run = run_one("dotnet.exe");
    let net = run.fact("dotnet.exe", "windows.dotnet");
    let reference = reference("dotnet.ref.txt");
    assert_eq!(net["assembly"]["name"].as_str(), after(&reference, "Name:").first().copied());
    assert_eq!(net["assembly"]["version"].as_str(), after(&reference, "Version:").first().copied());
    assert_eq!(net["assembly"]["public_key_token"], Value::Null);
    assert_eq!(net["target_framework"], ".NETFramework,Version=v4.7.2");
    assert_eq!(net["flags"]["il_only"], true);

    // AssemblyRef rows: "N: Version=a.b.c.d", "Name=x", then the token bytes.
    let names = after(&reference, "Name=");
    let versions: Vec<&str> = reference.lines().filter_map(|l| l.split_once(": Version=")).map(|(_, v)| v.trim()).collect();
    let tokens: Vec<String> = reference
        .lines()
        .filter_map(|l| l.strip_prefix("0x00000000: "))
        .map(|t| t.split_whitespace().collect::<String>().to_lowercase())
        .collect();
    let references = net["references"].as_array().expect("references");
    assert_eq!(references.len(), names.len());
    for (index, row) in references.iter().enumerate() {
        assert_eq!(row["name"].as_str(), Some(names[index]));
        assert_eq!(row["version"].as_str(), Some(versions[index]));
        assert_eq!(row["public_key_token"].as_str(), Some(tokens[index].as_str()));
    }
    // ImplMap rows end in "(Function library)".
    let mut expected: Vec<(String, String)> = reference
        .lines()
        .filter(|l| l.contains("::") && l.ends_with(')'))
        .filter_map(|l| l.rsplit_once('(').and_then(|(_, tail)| tail.trim_end_matches(')').split_once(' ')))
        .map(|(function, library)| (library.to_string(), function.to_string()))
        .collect();
    expected.sort();
    let ours: Vec<(String, String)> = net["pinvokes"]
        .as_array()
        .expect("pinvokes")
        .iter()
        .map(|p| (p["library"].as_str().expect("library").to_string(), p["function"].as_str().expect("function").to_string()))
        .collect();
    assert_eq!(ours, expected);
    let typedefs = reference.lines().skip_while(|l| !l.starts_with("Typedef Table")).skip(1).filter(|l| !l.trim().is_empty()).count();
    assert_eq!(net["types"].as_u64(), Some(typedefs as u64));
    assert_eq!(net["namespaces"], serde_json::json!(["Fixture.Net", "Fixture.Net.Protection"]));

    let assembly = run.findings("windows.dotnet-assembly");
    assert_eq!(assembly.len(), 1);
    assert_eq!(assembly[0].params["framework"], ".NETFramework,Version=v4.7.2");
    let obfuscated = run.findings("windows.dotnet-obfuscated");
    assert_eq!(obfuscated[0].params["tools"], "ConfuserEx");
    assert_eq!(obfuscated[0].confidence, aa_core::Confidence::Heuristic);
    // P/Invokes count towards the capability profile.
    assert_eq!(run.fact("dotnet.exe", "windows.capabilities")["injection"][0], "kernel32.dll!VirtualAllocEx");
}

// ---- installers --------------------------------------------------------------------------------

/// Children of `container` as `relative path -> sha256`.
fn children(run: &Run, container: &str) -> BTreeMap<String, String> {
    let prefix = format!("{container}/");
    run.tree
        .artifacts
        .iter()
        .filter(|a| a.parent.as_deref() == Some(container))
        .map(|a| (a.path[prefix.len()..].to_string(), run.sha256(&a.path)))
        .collect()
}

fn assert_nsis_matches_7zip(name: &str, format: &str) {
    let file = format!("{name}.exe");
    let run = run_one(&file);
    assert_eq!(run.unpacked.get(&file).map(String::as_str), Some("nsis"));
    let reference = reference(&format!("{name}.ref.txt"));
    let expected = reference_hashes(&reference);
    assert_eq!(expected.len(), 5);
    let mut ours = children(&run, &file);
    // The reconstructed script is ours alone; everything else must equal 7-Zip's extraction.
    assert!(ours.remove("[NSIS script].txt").is_some());
    let theirs: BTreeMap<String, String> = expected.into_iter().map(|(hash, path)| (path, hash)).collect();
    assert_eq!(ours, theirs, "{name}: extracted files");
    assert_eq!(run.unpack_limitations.len(), 0);

    let installer = run.fact(&file, "windows.installer");
    assert_eq!(installer["kind"], "NSIS");
    assert_eq!(installer["product"], "Fixture App");
    assert_eq!(installer["install_dir"], "$PROGRAMFILES64\\Fixture App");
    assert_eq!(installer["format"], format);
    assert_eq!(installer["requires_admin"]["required"], true);
    assert_eq!(installer["files"], 5);
    assert_eq!(installer["registry_writes"].as_array().map(Vec::len), Some(6));
    assert_eq!(installer["commands"].as_array().map(Vec::len), Some(4));
    assert_eq!(installer["shortcuts"].as_array().map(Vec::len), Some(2));
    assert_eq!(installer["uninstallers"][0], "$INSTDIR\\uninstall.exe");

    let autostart = run.findings("windows.installer-autostart");
    // Both the installer and nothing else: the uninstaller sets up no autostart.
    assert_eq!(autostart.len(), 1);
    assert_eq!(autostart[0].params["count"], 2);
    assert_eq!(autostart[0].evidence[0].value["key"], "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    assert_eq!(autostart[0].evidence[0].location, aa_core::Location::Field("script entry 6".into()));
    assert_eq!(autostart[0].evidence[1].value["shortcut"], "$SMSTARTUP\\Fixture App.lnk");
    for (rule, source) in [
        ("windows.installer-service", "script entry 14"),
        ("windows.installer-firewall", "script entry 15"),
        ("windows.installer-scheduled-task", "script entry 16"),
        ("windows.installer-file-association", "script entry 10"),
    ] {
        let found = run.findings(rule);
        assert_eq!(found.len(), 1, "{rule}");
        assert_eq!(found[0].evidence[0].location, aa_core::Location::Field(source.into()), "{rule}");
    }
    assert_eq!(run.findings("windows.installer-uninstall-entry")[0].params["count"], 2);
    assert_eq!(run.findings("windows.installer-runs")[0].params["count"], 4);
    // The uninstaller's own actions are not reported as installation actions.
    assert_eq!(run.findings("windows.installer-admin").len(), 1);
    assert_eq!(run.findings("windows.installer-runs").len(), 1);
    // The script child holds the commands as text.
    let script = String::from_utf8_lossy(&run.tree.contents[&format!("{file}/[NSIS script].txt")]).into_owned();
    assert!(script.contains("schtasks /Create"));
    // The uninstaller is recognised as one and claims no installed files.
    let uninstaller = run.fact(&format!("{file}/uninstall.exe"), "windows.installer");
    assert_eq!(uninstaller["kind"], "NSIS");
    assert_eq!(run.findings("windows.uninstaller").len(), 1);
    assert_eq!(uninstaller["files"], Value::Null);
}

#[test]
fn nsis_deflate_installer_matches_7zip() {
    assert_nsis_matches_7zip("nsis-zlib", "NSIS V3, Unicode strings, Deflate compression (NonSolid)");
}

#[test]
fn nsis_solid_lzma_installer_matches_7zip() {
    assert_nsis_matches_7zip("nsis-lzma-solid", "NSIS V3, Unicode strings, Lzma compression (Solid)");
}

#[test]
fn nsis_solid_bzip2_ansi_installer_matches_7zip() {
    assert_nsis_matches_7zip("nsis-bzip2-ansi", "NSIS V3, Ansi strings, Bzip2 compression (Solid)");
}

/// The rows of one table in the `msiinfo export` reference: header names, then value rows.
fn msi_table(reference: &str, table: &str) -> Vec<BTreeMap<String, String>> {
    let lines: Vec<&str> =
        reference.lines().skip_while(|l| *l != format!("== {table}")).skip(1).take_while(|l| !l.starts_with("== ")).collect();
    let Some(header) = lines.first() else { return Vec::new() };
    let columns: Vec<&str> = header.split('\t').collect();
    // Line 2 holds the column types and line 3 the table name and keys.
    lines.iter().skip(3).map(|line| columns.iter().zip(line.split('\t')).map(|(c, v)| (c.to_string(), v.to_string())).collect()).collect()
}

#[test]
fn msi_tables_and_files_match_msitools() {
    let run = run_one("fixture.msi");
    assert_eq!(run.unpacked.get("fixture.msi").map(String::as_str), Some("msi"));
    let reference = reference("fixture.msi.ref.txt");
    let installer = run.fact("fixture.msi", "windows.installer");

    let properties: BTreeMap<String, String> =
        msi_table(&reference, "Property").into_iter().map(|row| (row["Property"].clone(), row["Value"].clone())).collect();
    assert_eq!(installer["product"].as_str(), properties.get("ProductName").map(String::as_str));
    assert_eq!(installer["version"].as_str(), properties.get("ProductVersion").map(String::as_str));
    assert_eq!(installer["publisher"].as_str(), properties.get("Manufacturer").map(String::as_str));
    assert_eq!(installer["product_code"].as_str(), properties.get("ProductCode").map(String::as_str));
    assert_eq!(installer["upgrade_code"].as_str(), properties.get("UpgradeCode").map(String::as_str));
    assert_eq!(installer["requires_admin"]["required"], properties.get("ALLUSERS").map(String::as_str) == Some("1"));

    let files = msi_table(&reference, "File");
    assert_eq!(installer["files"].as_u64(), Some(files.len() as u64));
    assert_eq!(installer["files_bytes"].as_u64(), Some(files.iter().map(|f| f["FileSize"].parse::<u64>().expect("size")).sum()));

    let registry = &msi_table(&reference, "Registry")[0];
    let ours = &installer["registry_writes"][0];
    assert_eq!(ours["root"], "HKLM");
    assert_eq!(registry["Root"], "2");
    assert_eq!(ours["key"].as_str(), Some(registry["Key"].as_str()));
    assert_eq!(ours["name"].as_str(), Some(registry["Name"].as_str()));
    assert_eq!(ours["value"].as_str(), Some(registry["Value"].as_str()));
    assert_eq!(ours["tags"], serde_json::json!(["autostart"]));

    let service = &msi_table(&reference, "ServiceInstall")[0];
    let ours = &installer["services"][0];
    assert_eq!(ours["name"].as_str(), Some(service["Name"].as_str()));
    assert_eq!(ours["display_name"].as_str(), Some(service["DisplayName"].as_str()));
    assert_eq!((service["StartType"].as_str(), ours["start"].as_str()), ("2", Some("auto")));
    assert_eq!(ours["account"].as_str(), Some(service["StartName"].as_str()));
    assert_eq!(ours["driver"], false);
    assert_eq!(ours["command"], "ProgramFilesFolder/Fixture MSI/hello.exe --service");

    let action = &msi_table(&reference, "CustomAction")[0];
    let ours = &installer["custom_actions"][0];
    assert_eq!(ours["action"].as_str(), Some(action["Action"].as_str()));
    assert_eq!(ours["type"].to_string(), action["Type"]);
    assert_eq!(ours["flags"], serde_json::json!(["deferred", "runs as SYSTEM"]));
    assert_eq!(installer["commands"][0]["command"], "installed EXE: ProgramFilesFolder/Fixture MSI/hello.exe --first-run");

    let shortcut = &msi_table(&reference, "Shortcut")[0];
    assert_eq!(installer["shortcuts"][0]["path"].as_str(), Some(format!("{}/{}", shortcut["Directory_"], shortcut["Name"]).as_str()));
    let condition = &msi_table(&reference, "LaunchCondition")[0];
    assert_eq!(installer["launch_conditions"][0]["condition"].as_str(), Some(condition["Condition"].as_str()));

    // Files: msiextract writes the same bytes under "Program Files/...".
    let ours = children(&run, "fixture.msi");
    let expected: Vec<(String, String)> =
        reference_hashes(&reference).into_iter().filter(|(_, path)| path.starts_with("Program Files/")).collect();
    assert_eq!(expected.len(), 3);
    for (hash, path) in expected {
        let relative = path.replacen("Program Files/", "ProgramFilesFolder/", 1);
        assert_eq!(ours.get(&relative), Some(&hash), "{relative}");
    }
    assert_eq!(ours.len(), 3);

    for (rule, count) in [
        ("windows.installer-autostart", 1),
        ("windows.installer-service", 1),
        ("windows.installer-admin", 1),
        ("windows.installer-runs", 1),
    ] {
        assert_eq!(run.findings(rule).len(), count, "{rule}");
    }
    assert_eq!(
        run.findings("windows.installer-service")[0].evidence[0].location,
        aa_core::Location::Field("ServiceInstall table, row Svc".into())
    );
    assert_eq!(run.findings("windows.installer")[0].params["kind"], "MSI");
}

// ---- the signature of an MSI itself --------------------------------------------------------------

/// The components of a distinguished name, whichever way the tool wrote it
/// (`/C=XX/O=Example` or `CN=Name,O=Example`).
fn name_parts(name: &str) -> BTreeSet<String> {
    let separator = if name.starts_with('/') { '/' } else { ',' };
    name.split(separator).map(|part| part.trim().to_string()).filter(|part| !part.is_empty()).collect()
}

/// Compares the signature of an MSI fixture with osslsigncode's verification output: the signed
/// and the recomputed content digest, the metadata digest when the package has one, the signer.
fn assert_msi_matches_osslsigncode(name: &str, algorithm: &str, checks: u64) -> Run {
    let file = format!("{name}.msi");
    let run = run_one(&file);
    let reference = reference(&format!("{name}.ref.txt"));
    let fact = run.fact(&file, "windows.msi-signature");
    assert_eq!(fact["signed"], true, "{name}");
    assert_eq!(fact["kind"], "MSI", "{name}");
    assert_eq!(fact["errors"], serde_json::json!([]), "{name}");
    let signatures = fact["signatures"].as_array().expect("signatures");
    assert_eq!(signatures.len(), 1, "{name}");
    let signature = &signatures[0];

    assert_eq!(after(&reference, "Message digest algorithm         :"), [algorithm.replace('-', "")]);
    assert_eq!(signature["digest_algorithm"], algorithm);
    let signed = after(&reference, "Current DigitalSignature         :");
    let calculated = after(&reference, "Calculated DigitalSignature      :");
    assert_eq!((signed.len(), calculated.len()), (1, 1), "{name}: osslsigncode printed one signature");
    assert_eq!(signed, calculated, "{name}: osslsigncode itself found the digest to match");
    assert_eq!(signature["signed_digest"].as_str().expect("digest").to_uppercase(), signed[0], "{name}: signed digest");
    assert_eq!(signature["computed_digest"].as_str().expect("digest").to_uppercase(), calculated[0], "{name}: computed digest");
    for check in ["file_digest", "content_digest", "signature", "chain"] {
        assert_eq!(signature["checks"][check], "passed", "{name}: {check}");
    }

    let stored = after(&reference, "Current MsiDigitalSignatureEx    :");
    let recomputed = after(&reference, "Calculated MsiDigitalSignatureEx :");
    assert_eq!(fact["metadata_stream"], !stored.is_empty(), "{name}: MsiDigitalSignatureEx present");
    if let (Some(stored), Some(recomputed)) = (stored.first(), recomputed.first()) {
        assert_eq!(fact["signed_metadata_digest"].as_str().expect("digest").to_uppercase(), *stored, "{name}: stored metadata digest");
        assert_eq!(fact["computed_metadata_digest"].as_str().expect("digest").to_uppercase(), *recomputed, "{name}: metadata digest");
        assert_eq!(fact["metadata_digest"], "passed", "{name}");
    }

    assert_eq!(name_parts(signature["signer"]["subject"].as_str().expect("subject")), name_parts(after(&reference, "Subject:")[0]));
    assert_eq!(name_parts(signature["signer"]["issuer"].as_str().expect("issuer")), name_parts(after(&reference, "Issuer :")[0]));
    assert_eq!(signature["signer"]["serial"].as_str().expect("serial").to_uppercase(), after(&reference, "Serial :")[0]);

    let found = run.findings("windows.msi-signature");
    assert_eq!(found.len(), 1, "{name}");
    assert_eq!(found[0].severity, aa_core::Severity::Info, "{name}");
    assert_eq!(found[0].confidence, aa_core::Confidence::Verified, "{name}");
    assert_eq!((found[0].params["passed"].as_u64(), found[0].params["checks"].as_u64()), (Some(checks), Some(checks)), "{name}");
    assert_eq!(found[0].params["algorithm"], algorithm);
    for rule in [
        "windows.msi-unsigned",
        "windows.signature-digest-mismatch",
        "windows.signature-invalid",
        "windows.signature-chain-broken",
        "windows.msi-signature-metadata-mismatch",
        "windows.msi-signature-extra-data",
    ] {
        assert!(run.findings(rule).is_empty(), "{name}: {rule}");
    }
    assert!(!run.out.limitations.iter().any(|l| l.code.starts_with("windows.msi-signature")), "{name}: {:?}", run.out.limitations);
    // The package's signature is not a PE signature and is not counted as one.
    assert!(!run.tree.get(&file).expect("artifact").facts.contains_key("windows.authenticode"));
    run
}

#[test]
fn msi_signature_with_timestamp_matches_osslsigncode() {
    let run = assert_msi_matches_osslsigncode("msi-signed", "SHA-256", 4);
    let reference = reference("msi-signed.ref.txt");
    let signature = &run.fact("msi-signed.msi", "windows.msi-signature")["signatures"][0];
    assert_eq!(signature["program_name"].as_str(), after(&reference, "Text description:").first().copied());
    assert_eq!(signature["more_info_url"].as_str(), after(&reference, "URL description:").first().copied());
    assert_eq!(signature["issuers"].as_array().map(Vec::len), Some(1));
    assert_eq!(signature["chain_reaches_embedded_root"], true);
    let stamp = &signature["timestamps"][0];
    assert_eq!(stamp["time"].as_str(), Some(openssl_time(after(&reference, "Timestamp time:")[0]).as_str()));
    for check in ["covers_signature", "content_digest", "signature", "chain_check"] {
        assert_eq!(stamp[check], "passed", "timestamp {check}");
    }
    assert_eq!(signature["valid_at_timestamp"], true);
    let found = run.findings("windows.msi-signature");
    assert_eq!(found[0].params["signer"], "Fixture Code Signing");
    assert_eq!(found[0].params["authority"], "Fixture Timestamp Authority");
    assert_eq!(found[0].params["timestamp"], stamp["time"]);
    assert!(run.findings("windows.signature-no-timestamp").is_empty());
    assert!(run.findings("windows.signature-self-signed").is_empty());
    // The package is still read as an installer.
    assert_eq!(run.unpacked.get("msi-signed.msi").map(String::as_str), Some("msi"));
    assert_eq!(run.fact("msi-signed.msi", "windows.installer")["product"], "Tiny Fixture");
    assert_eq!(run.fact("msi-signed.msi", "windows.installer")["has_digital_signature"], true);
}

#[test]
fn msi_signature_with_metadata_hash_matches_osslsigncode() {
    let run = assert_msi_matches_osslsigncode("msi-signed-dse", "SHA-256", 5);
    assert_eq!(run.findings("windows.signature-self-signed").len(), 1);
    assert_eq!(run.findings("windows.signature-no-timestamp").len(), 1);
    assert_eq!(run.findings("windows.msi-signature")[0].params["timestamp"], "—");
}

#[test]
fn msi_signature_over_nested_storages_matches_osslsigncode() {
    // Not a real installer database: a compound file with storages inside storages and names
    // whose stored order differs from their code-unit order, signed with SHA-384.
    let run = assert_msi_matches_osslsigncode("msi-nested-dse", "SHA-384", 5);
    assert!(run.findings("windows.signature-self-signed").is_empty());
}

#[test]
fn unsigned_msi_is_reported_as_unsigned() {
    let run = run_one("fixture.msi");
    assert_eq!(run.fact("fixture.msi", "windows.msi-signature"), &serde_json::json!({ "signed": false, "kind": "MSI" }));
    let found = run.findings("windows.msi-unsigned");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, aa_core::Severity::Info);
    assert!(run.findings("windows.msi-signature").is_empty());
    assert_eq!(run.fact("fixture.msi", "windows.installer")["has_digital_signature"], false);
    // A signed package with its signature stream removed is unsigned too.
    let mut file = cfb::CompoundFile::open(std::io::Cursor::new(data("msi-signed.msi"))).expect("open");
    file.remove_stream("/\u{5}DigitalSignature").expect("remove");
    file.flush().expect("flush");
    let run = analyze(&[("stripped.msi", file.into_inner().into_inner())]);
    assert_eq!(run.findings("windows.msi-unsigned").len(), 1);
    // Compound files that are not installer packages are left alone.
    let mut other = cfb::CompoundFile::create(std::io::Cursor::new(Vec::new())).expect("create");
    other.create_stream("/WordDocument").expect("stream");
    other.flush().expect("flush");
    let run = analyze(&[("old.doc", other.into_inner().into_inner())]);
    assert!(run.out.findings.iter().all(|f| !f.rule.starts_with("windows.msi")));
    assert!(!run.tree.get("old.doc").expect("artifact").facts.contains_key("windows.msi-signature"));
}

#[test]
fn msi_modified_after_signing_is_detected() {
    // A byte of the string pool changed (the last place the manufacturer's name occurs; the
    // earlier ones are in the certificates): the content digest no longer matches, the
    // signature itself is intact.
    let original = data("msi-signed.msi");
    let mut changed = original.clone();
    let at = original.windows(13).rposition(|w| w == b"Fixture Works").expect("string pool");
    changed[at] = b'f';
    let run = analyze(&[("changed.msi", changed)]);
    let signature = &run.fact("changed.msi", "windows.msi-signature")["signatures"][0];
    assert_eq!(signature["checks"]["file_digest"], "failed");
    assert_eq!(signature["checks"]["signature"], "passed");
    assert_eq!(signature["checks"]["content_digest"], "passed");
    assert_ne!(signature["signed_digest"], signature["computed_digest"]);
    let reference = reference("msi-signed.ref.txt");
    assert_eq!(
        signature["signed_digest"].as_str().expect("digest").to_uppercase(),
        after(&reference, "Current DigitalSignature         :")[0]
    );
    let found = run.findings("windows.signature-digest-mismatch");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, aa_core::Severity::High);
    assert_eq!(found[0].evidence[0].location, aa_core::Location::Field("\\x05DigitalSignature stream".into()));
    let summary = run.findings("windows.msi-signature");
    assert_eq!(summary[0].severity, aa_core::Severity::Medium);
    assert_eq!((summary[0].params["passed"].as_u64(), summary[0].params["checks"].as_u64()), (Some(3), Some(4)));

    // A byte of an embedded file changed (the cabinet lives in ordinary sectors, not the mini stream).
    let mut changed = original.clone();
    let at = position(&changed, b"MSCF") + 300;
    changed[at] ^= 0xff;
    let run = analyze(&[("changed.msi", changed)]);
    assert_eq!(run.findings("windows.signature-digest-mismatch").len(), 1);

    // The signature data itself damaged: the signed attributes no longer verify.
    let mut changed = original.clone();
    let digest = unhex(run.fact("changed.msi", "windows.msi-signature")["signatures"][0]["signed_digest"].as_str().expect("digest"));
    let at = position(&changed, &digest);
    changed[at] ^= 0xff;
    let run = analyze(&[("changed.msi", changed)]);
    assert_eq!(run.findings("windows.signature-invalid").len(), 1);
    assert_eq!(run.findings("windows.signature-digest-mismatch").len(), 1);
}

/// File offset of the directory entry called `name`.
fn directory_entry(bytes: &[u8], name: &str) -> usize {
    let mut stored: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    stored.extend([0, 0]);
    let at = position(bytes, &stored);
    assert_eq!((at - 512) % 128, 0, "a directory entry starts here");
    at
}

#[test]
fn msi_metadata_changed_after_signing_is_detected() {
    let original = data("msi-signed-dse.msi");
    // The state bits of a stream's directory entry: metadata, not content.
    let mut changed = original.clone();
    changed[directory_entry(&original, "\u{5}SummaryInformation") + 96] = 1;
    let run = analyze(&[("changed.msi", changed.clone())]);
    let fact = run.fact("changed.msi", "windows.msi-signature");
    assert_eq!(fact["metadata_digest"], "failed");
    assert_ne!(fact["signed_metadata_digest"], fact["computed_metadata_digest"]);
    assert_eq!(fact["signatures"][0]["checks"]["file_digest"], "passed", "the content is unchanged");
    let found = run.findings("windows.msi-signature-metadata-mismatch");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, aa_core::Severity::High);
    let summary = run.findings("windows.msi-signature");
    assert_eq!(summary[0].severity, aa_core::Severity::Medium);
    assert_eq!((summary[0].params["passed"].as_u64(), summary[0].params["checks"].as_u64()), (Some(4), Some(5)));

    // Without MsiDigitalSignatureEx the same change is outside the signature, and nothing is claimed about it.
    let plain = data("msi-signed.msi");
    let mut changed = plain.clone();
    changed[directory_entry(&plain, "\u{5}SummaryInformation") + 96] = 1;
    let run = analyze(&[("changed.msi", changed)]);
    assert_eq!(run.findings("windows.msi-signature")[0].severity, aa_core::Severity::Info);

    // The stored metadata hash itself changed: it is part of the signed content digest.
    let stored = unhex(fact["signed_metadata_digest"].as_str().expect("digest"));
    let mut changed = original.clone();
    let at = position(&changed, &stored);
    changed[at] ^= 0xff;
    let run = analyze(&[("changed.msi", changed)]);
    assert_eq!(run.findings("windows.signature-digest-mismatch").len(), 1);
    assert_eq!(run.findings("windows.msi-signature-metadata-mismatch").len(), 1);
}

#[test]
fn data_hidden_in_the_msi_signature_stream_is_reported() {
    use std::io::{Seek, SeekFrom, Write};
    let append = |extra: &[u8]| {
        let mut file = cfb::CompoundFile::open(std::io::Cursor::new(data("msi-signed.msi"))).expect("open");
        let mut stream = file.open_stream("/\u{5}DigitalSignature").expect("stream");
        let length = stream.seek(SeekFrom::End(0)).expect("seek");
        stream.write_all(extra).expect("write");
        drop(stream);
        file.flush().expect("flush");
        (length, file.into_inner().into_inner())
    };
    let (length, changed) = append(b"smuggled");
    let run = analyze(&[("extra.msi", changed)]);
    let found = run.findings("windows.msi-signature-extra-data");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].params["bytes"], 8);
    assert_eq!(found[0].params["offset"].as_u64(), Some(length));
    assert_eq!(found[0].severity, aa_core::Severity::Medium);
    // The stream is outside the hash: the signature still verifies, which is the point.
    let summary = run.findings("windows.msi-signature");
    assert_eq!((summary[0].params["passed"].as_u64(), summary[0].params["checks"].as_u64()), (Some(4), Some(4)));
    // Zero padding carries nothing and is not reported.
    let (_, padded) = append(&[0; 8]);
    let run = analyze(&[("padded.msi", padded)]);
    assert!(run.findings("windows.msi-signature-extra-data").is_empty());
    assert_eq!(run.findings("windows.msi-signature").len(), 1);
}

#[test]
fn unreadable_msi_signature_is_a_limitation() {
    // The stream is there but does not hold PKCS#7 data.
    let original = data("msi-signed.msi");
    let run = run_one("msi-signed.msi");
    let digest = unhex(run.fact("msi-signed.msi", "windows.msi-signature")["signatures"][0]["signed_digest"].as_str().expect("digest"));
    let blob_start = {
        // The blob begins with the SignedData OID a few bytes in; walk back to its SEQUENCE.
        let oid = position(&original, &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]);
        assert!(oid < position(&original, &digest));
        oid - 4
    };
    let mut changed = original.clone();
    changed[blob_start] = 0x04;
    changed[blob_start + 5] = 0xff;
    let run = analyze(&[("broken.msi", changed)]);
    assert!(run.out.limitations.iter().any(|l| l.code == "windows.msi-signature-unreadable"), "{:?}", run.out.limitations);
    assert!(run.findings("windows.msi-signature").is_empty());
    assert!(run.findings("windows.msi-unsigned").is_empty(), "an unreadable signature is not an absent one");
    assert_eq!(run.fact("broken.msi", "windows.msi-signature")["signed"], false);
}

#[test]
fn damaged_signed_msi_never_panics() {
    // Header, FAT, directory and signature streams hit byte by byte: the header densely, the
    // rest sampled. (The compound-file reader has its own, denser test.)
    for name in ["msi-signed-dse.msi", "msi-nested-dse.msi"] {
        let original = data(name);
        let places = (0..128).step_by(3).chain((128..original.len()).step_by(83));
        for at in places {
            let mut changed = original.clone();
            changed[at] = if original[at] == 0xff { 0x00 } else { 0xff };
            analyze(&[(name, changed)]);
        }
    }
}

#[test]
fn cabinet_files_match_cabextract() {
    let run = run_one("fixture.cab");
    assert_eq!(run.unpacked.get("fixture.cab").map(String::as_str), Some("cab"));
    let expected: BTreeMap<String, String> =
        reference_hashes(&reference("fixture.cab.ref.txt")).into_iter().map(|(hash, path)| (path, hash)).collect();
    assert_eq!(expected.len(), 3);
    assert_eq!(children(&run, "fixture.cab"), expected);
    assert!(run.unpack_limitations.is_empty());
}

#[test]
fn self_extractor_overlay_is_handed_on() {
    let run = run_one("sfx-7z.exe");
    assert_eq!(run.unpacked.get("sfx-7z.exe").map(String::as_str), Some("sfx"));
    assert!(run.tree.contents["sfx-7z.exe/[overlay].7z"].starts_with(b"7z\xbc\xaf\x27\x1c"));
    // The generic 7z unpacker then opens the child; its files equal the ones packed.
    for (hash, name) in reference_hashes(&reference("sfx-7z.ref.txt")) {
        assert_eq!(run.sha256(&format!("sfx-7z.exe/[overlay].7z/{name}")), hash, "{name}");
    }
    // A plain program and an NSIS installer are not self-extractors.
    assert!(run_one("hello.exe").unpacked.is_empty());
    assert_eq!(run_one("nsis-zlib.exe").unpacked.get("nsis-zlib.exe").map(String::as_str), Some("nsis"));
    // An overlay that is not an archive is left alone.
    let mut unknown = data("hello.exe");
    unknown.extend_from_slice(&[0x42; 4096]);
    assert!(analyze(&[("unknown.exe", unknown)]).unpacked.is_empty());
}

// ---- Electron and folder layout ----------------------------------------------------------------

#[test]
fn electron_application_is_recognised() {
    let mut executable = data("hello.exe");
    // What an Electron build carries: the user-agent string and the fuse wire.
    executable.extend_from_slice(b"\0Chrome/124.0.6367.49 Electron/30.1.2\0");
    executable.extend_from_slice(b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX\x01\x08101r0001");
    let files = [
        ("app/Fixture.exe", executable),
        ("app/chrome_100_percent.pak", vec![0u8; 16]),
        ("app/ffmpeg.dll", data("hello.exe")),
        ("app/resources/app.asar", data("fixture.asar")),
    ];
    let heuristic = analyze(&files);
    assert_eq!(heuristic.unpacked.get("app/resources/app.asar").map(String::as_str), Some("asar"));
    assert!(heuristic.paths().contains(&"app/resources/app.asar/lib/util.js"));
    let app = heuristic.findings("windows.electron-app");
    assert_eq!(app.len(), 1);
    assert_eq!(app[0].params["name"], "fixture-electron");
    assert_eq!(app[0].params["version"], "4.5.6");
    assert_eq!(app[0].params["electron"], "30.1.2");
    assert_eq!(app[0].params["chrome"], "124.0.6367.49");
    assert_eq!(app[0].params["main"], "main.js");
    assert_eq!(app[0].params["dependencies"], 2);
    // Read from a string in the executable: a pattern match.
    assert_eq!(app[0].confidence, aa_core::Confidence::Heuristic);

    let fuses = heuristic.findings("windows.electron-fuses");
    assert_eq!(fuses[0].params["enabled"], "RunAsNode, EnableNodeOptionsEnvironmentVariable, GrantFileProtocolExtraPrivileges");
    assert_eq!(
        fuses[0].params["disabled"],
        "EnableCookieEncryption, EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar, LoadBrowserProcessSpecificV8Snapshot"
    );

    let settings: BTreeMap<String, &Finding> = heuristic
        .findings("windows.electron-setting")
        .into_iter()
        .map(|f| (f.params["setting"].as_str().expect("setting").to_string(), f))
        .collect();
    assert_eq!(settings.keys().map(String::as_str).collect::<Vec<_>>(), ["contextIsolation", "nodeIntegration", "sandbox", "webSecurity"]);
    let node = settings["nodeIntegration"];
    assert_eq!(node.confidence, aa_core::Confidence::Heuristic);
    assert_eq!(node.evidence[0].artifact, "app/resources/app.asar/main.js");
    let aa_core::Location::Bytes { offset, length } = node.evidence[0].location else { panic!("byte location expected") };
    let script = &heuristic.tree.contents["app/resources/app.asar/main.js"];
    assert_eq!(&script[offset as usize..(offset + length) as usize], b"nodeIntegration: true");

    let asar = heuristic.fact("app/resources/app.asar", "windows.asar");
    assert_eq!((asar["files"].as_u64(), asar["integrity_verified"].as_u64()), (Some(3), Some(3)));
    assert!(heuristic.findings("windows.asar-integrity-mismatch").is_empty());

    // With the distribution's `version` file the version is read, not guessed.
    let mut with_version = files.to_vec();
    with_version.push(("app/version", b"30.1.2".to_vec()));
    let verified = analyze(&with_version);
    assert_eq!(verified.findings("windows.electron-app")[0].confidence, aa_core::Confidence::Verified);

    // A changed file inside the asar no longer matches the hash in its header.
    let mut tampered = files.to_vec();
    let last = tampered[3].1.len() - 2;
    tampered[3].1[last] ^= 1;
    let tampered = analyze(&tampered);
    assert_eq!(tampered.findings("windows.asar-integrity-mismatch")[0].params["count"], 1);

    // An asar alone, without Electron's files around it, is not called an Electron app.
    assert!(analyze(&[("x/resources/app.asar", data("fixture.asar"))]).findings("windows.electron-app").is_empty());
}

#[test]
fn runtimes_are_recognised_from_the_layout() {
    let pe = data("hello.exe");
    let run = analyze(&[
        ("app/app.exe", pe.clone()),
        ("app/Qt6Core.dll", pe.clone()),
        ("app/Qt6Gui.dll", pe.clone()),
        ("app/python311.dll", pe.clone()),
        ("app/WebView2Loader.dll", pe.clone()),
        ("app/unins000.exe", pe.clone()),
        (
            "app/tool.runtimeconfig.json",
            br#"{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}"#.to_vec(),
        ),
        ("app/tool.deps.json", br#"{"libraries":{"tool/1.0.0":{"type":"project"},"Serilog/3.1.1":{"type":"package"}}}"#.to_vec()),
        ("app/notqt.dll", pe),
    ]);
    let found: BTreeMap<&str, u64> = run
        .findings("windows.runtime")
        .into_iter()
        .map(|f| (f.params["runtime"].as_str().expect("runtime"), f.params["files"].as_u64().expect("files")))
        .collect();
    assert_eq!(found.get("Qt 6"), Some(&2));
    assert_eq!(found.get("Python (embedded interpreter)"), Some(&1));
    assert_eq!(found.get("Inno Setup uninstaller"), Some(&1));
    assert_eq!(found.get(".NET (framework-dependent application)"), Some(&1));
    assert!(found.keys().any(|k| k.starts_with("Microsoft Edge WebView2")));
    assert_eq!(found.len(), 5);
    let net = run.findings("windows.dotnet-app");
    assert_eq!(net[0].params["frameworks"], "Microsoft.NETCore.App 8.0.0");
    assert_eq!(net[0].params["libraries"], 1);
    assert_eq!(run.fact("app/tool.runtimeconfig.json", "windows.dotnet-app")["libraries"], serde_json::json!(["Serilog 3.1.1"]));
    // Seven PE files from one vendor: one summary, no per-file identity findings.
    assert_eq!(run.findings("windows.vendors")[0].params["vendors"], "Fixture Works (7)");
    assert!(run.findings("windows.version-info").is_empty());
    assert_eq!(run.findings("windows.original-filename-mismatch")[0].params["count"], 7);
}

// ---- hostile input -----------------------------------------------------------------------------

/// Cut points and flipped bytes spread over a file, densest at the start where headers are.
fn mutations(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut list = Vec::new();
    let length = bytes.len();
    let mut cuts: Vec<usize> = (0..24)
        .map(|i| i * 16)
        .chain((1..16).map(|i| length * i / 16))
        .chain([length.saturating_sub(1), length.saturating_sub(9)])
        .collect();
    cuts.retain(|&c| c < length);
    for cut in cuts {
        list.push(bytes[..cut].to_vec());
    }
    for index in 0..48 {
        let mut changed = bytes.to_vec();
        // Four bytes at a time, so 32-bit lengths and offsets turn into huge values.
        let at = if index < 24 { 0x38 + index * 12 } else { length * (index - 23) / 26 };
        for byte in changed.iter_mut().skip(at.min(length.saturating_sub(4))).take(4) {
            *byte = 0xff;
        }
        list.push(changed);
    }
    list
}

#[test]
fn damaged_files_never_panic() {
    for name in [
        "hello.exe",
        "hello-signed.exe",
        "hello-dual.exe",
        "hello-ecdsa.exe",
        "dotnet.exe",
        "nsis-zlib.exe",
        "nsis-lzma-solid.exe",
        "nsis-bzip2-ansi.exe",
        "fixture.msi",
        "msi-signed.msi",
        "msi-signed-dse.msi",
        "msi-nested-dse.msi",
        "fixture.cab",
        "fixture.asar",
        "sfx-7z.exe",
    ] {
        let original = data(name);
        for (index, mutated) in mutations(&original).into_iter().enumerate() {
            // Any panic fails the test; what is found in damaged files is not asserted.
            let result = std::panic::catch_unwind(|| {
                analyze(&[(name, mutated)]);
            });
            assert!(result.is_ok(), "{name}: mutation {index} panicked");
        }
    }
}

#[test]
fn damage_inside_structures_never_panics() {
    // The certificate table, the resource section and the .NET metadata, hit byte by byte.
    let signed = data("hello-signed.exe");
    let table = signed.len() - 6000;
    for at in (table..signed.len()).step_by(37) {
        for value in [0x00, 0x80, 0xff] {
            let mut changed = signed.clone();
            changed[at] = value;
            analyze(&[("s.exe", changed)]);
        }
    }
    let plain = data("hello.exe");
    for at in (0x3c00..plain.len()).step_by(29) {
        let mut changed = plain.clone();
        changed[at] = 0xff;
        analyze(&[("p.exe", changed)]);
    }
    let net = data("dotnet.exe");
    for at in (0x200..net.len()).step_by(23) {
        let mut changed = net.clone();
        changed[at] = 0xff;
        analyze(&[("n.exe", changed)]);
    }
}
