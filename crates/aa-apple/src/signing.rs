//! Findings about code signatures, from the `apple.macho` facts of the file pass: who signed,
//! what was verified, entitlements, sealed resources, provisioning profiles.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Value, json};
use sha2::Digest;

use crate::bundle::{Bundle, Layout, parse_plist, strings, truthy};
use crate::certs;
use crate::codesign::{SLOT_INFO_PLIST, SLOT_RESOURCES, plist_to_json};
use crate::info::{finding, shown};

/// Files named as evidence in one finding.
const MAX_EVIDENCE: usize = 25;

/// The slices of a Mach-O artifact's fact.
pub fn slices(artifact: &Artifact) -> &[Value] {
    artifact.facts.get("apple.macho").and_then(|fact| fact.get("slices")).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

/// The slice findings are written about: arm64 when there is one, else the first.
pub fn main_slice(artifact: &Artifact) -> Option<&Value> {
    let all = slices(artifact);
    all.iter().find(|s| s["arch"].as_str().is_some_and(|a| a.starts_with("arm64"))).or_else(|| all.first())
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// What is known about the platform a subject runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    /// iOS, tvOS, watchOS, visionOS: provisioning profiles, no hardened runtime.
    Embedded,
    Unknown,
}

pub fn platform_of(slice: &Value, bundle: Option<&Bundle<'_>>) -> Platform {
    match text(slice, "platform") {
        Some("macOS" | "Mac Catalyst" | "DriverKit") => Platform::MacOs,
        Some(_) => Platform::Embedded,
        None => match bundle.map(|b| b.layout) {
            Some(Layout::Contents | Layout::Versioned) => Platform::MacOs,
            Some(Layout::Flat) => Platform::Embedded,
            None => Platform::Unknown,
        },
    }
}

/// The outcome of the signature report of one subject, for checks that follow.
#[derive(Debug, Clone, Default)]
pub struct Signed {
    pub team: Option<String>,
    pub signing_type: Option<String>,
    pub entitlements: Option<Value>,
    pub leaf_sha256: Option<String>,
    pub cms_examined: bool,
    /// Page hashes compared and found equal, when none differed.
    pub intact_pages: u64,
}

/// Reports the signature of `file` (a Mach-O with an `apple.macho` fact). `bundle` is given
/// when `file` is that bundle's main executable.
///
/// With `brief` (code that belongs to no bundle, of which there can be many) only who signed
/// and what is wrong are reported; `Signed::intact_pages` carries the rest for a summary.
pub fn report(tree: &dyn Tree, file: &Artifact, bundle: Option<&Bundle<'_>>, brief: bool, out: &mut Output) -> Signed {
    let mut signed = Signed::default();
    let all = slices(file);
    let Some(slice) = main_slice(file) else { return signed };
    let arch = text(slice, "arch").unwrap_or("?");
    let archs: Vec<String> = all.iter().filter_map(|s| text(s, "arch").map(str::to_string)).collect();
    let name = file.name();
    let platform = platform_of(slice, bundle);

    if let Some(error) = text(slice, "signature_error") {
        out.limitation("apple.signature-unreadable", Some(file), Some(format!("{arch}: {error}")));
        return signed;
    }
    let signature = &slice["signature"];
    if signature.is_null() {
        if slice.get("error").is_none() {
            out.finding(
                finding(Section::Provenance, "apple.unsigned", Confidence::Verified, Severity::Medium)
                    .param("file", name)
                    .param("arch", arch)
                    .evidence(Evidence::whole(file, json!({ "LC_CODE_SIGNATURE": null }))),
            );
            signed.signing_type = Some("unsigned".into());
        }
        return signed;
    }
    let offset = slice["offset"].as_u64().unwrap_or(0) + signature["offset"].as_u64().unwrap_or(0);
    let size = signature["size"].as_u64().unwrap_or(0);
    let place = |value: Value| Evidence::bytes(file, offset, size, value);
    let flags = signature["flags"].as_u64().unwrap_or(0);
    let flag_names: Vec<&str> = signature["flag_names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let flags_text = if flag_names.is_empty() { format!("{flags:#x}") } else { format!("{flags:#x} ({})", flag_names.join(", ")) };
    let mut found = finding(Section::Provenance, "apple.signature", Confidence::Verified, Severity::Info)
        .param("file", name)
        .param("identifier", text(signature, "identifier").unwrap_or(""))
        .param("cdhash", text(signature, "cdhash").unwrap_or(""))
        .param("hash_type", text(signature, "hash_type").unwrap_or(""))
        .param("flags", flags_text)
        .param("arch", arch);
    for other in all {
        let other_signature = &other["signature"];
        if let (Some(arch), Some(cdhash)) = (text(other, "arch"), text(other_signature, "cdhash")) {
            found = found.evidence(Evidence::bytes(
                file,
                other["offset"].as_u64().unwrap_or(0) + other_signature["offset"].as_u64().unwrap_or(0),
                other_signature["size"].as_u64().unwrap_or(0),
                json!({ "arch": arch, "identifier": other_signature["identifier"], "cdhash": cdhash, "flags": other_signature["flag_names"] }),
            ));
        }
    }
    // An ad-hoc signature identifies nobody; in brief mode the line saying so is enough.
    let certified = signature["cms"].is_object();
    if !brief || certified {
        out.finding(found);
    }
    if let Some(team) = text(signature, "team_id") {
        signed.team = Some(team.to_string());
        // Apple's certificates carry the team in the signer's name; said once is enough.
        let in_signer_name = text(&signature["cms"]["chain"]["certificates"][0], "common_name").is_some_and(|signer| signer.contains(team));
        if !brief && !in_signer_name {
            out.finding(
                finding(Section::Provenance, "apple.team-id", Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .param("team", team)
                    .evidence(place(json!({ "team_id": team }))),
            );
        }
    }
    // The slices of one file should tell the same story.
    let stories: BTreeSet<String> = all
        .iter()
        .map(|s| format!("{}|{}|{}", s["signature"]["identifier"], s["signature"]["team_id"], s["signature"]["signing_type"]))
        .collect();
    if stories.len() > 1 {
        out.finding(
            finding(Section::Anomalies, "apple.slices-differ", Confidence::Verified, Severity::Medium)
                .param("file", name)
                .param("archs", archs.join(", "))
                .evidence(Evidence::whole(file, json!(stories))),
        );
    }

    // Who signed.
    let signing_type = text(signature, "signing_type").unwrap_or("other");
    signed.signing_type = Some(signing_type.to_string());
    let cms = &signature["cms"];
    let leaf = &cms["chain"]["certificates"][0];
    let leaf_name = text(leaf, "common_name").unwrap_or("");
    signed.leaf_sha256 = text(leaf, "sha256").map(str::to_string);
    let (rule, severity) = match signing_type {
        "adhoc" => ("apple.signed-adhoc", Severity::Low),
        "adhoc-linker" => ("apple.signed-adhoc-linker", Severity::Low),
        "developer-id" | "developer-id-installer" => ("apple.signed-developer-id", Severity::Info),
        "development" => ("apple.signed-development", Severity::Info),
        "distribution" | "distribution-installer" => ("apple.signed-distribution", Severity::Info),
        "mac-app-store" | "ios-app-store" => ("apple.signed-app-store", Severity::Info),
        "apple-system" => ("apple.signed-apple-system", Severity::Info),
        _ => ("apple.signed-other", Severity::Low),
    };
    let mut found = finding(Section::Provenance, rule, Confidence::Derived, severity).param("file", name).param("signer", leaf_name);
    found = if leaf.is_object() {
        found.evidence(place(
            json!({ "signer_common_name": leaf_name, "signer_sha256": leaf["sha256"], "apple_extensions": leaf["apple_extensions"] }),
        ))
    } else {
        found.evidence(place(json!({ "flags": signature["flag_names"], "cms_signature": "absent" })))
    };
    out.finding(found);

    if let Some(error) = text(signature, "cms_error") {
        out.limitation("apple.cms-unreadable", Some(file), Some(error.to_string()));
    }
    if cms.is_object() {
        signed.cms_examined = true;
        report_cms(file, name, cms, brief, &place, out);
    }

    // What the hashes in the signature say about the file itself.
    let directories = signature["directories"].as_array().map(Vec::as_slice).unwrap_or_default();
    let mut checked = 0u64;
    let mut skipped = 0u64;
    let mut mismatched: Vec<Value> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for other in all {
        for directory in other["signature"]["directories"].as_array().into_iter().flatten() {
            let pages = &directory["pages"];
            checked += pages["checked"].as_u64().unwrap_or(0);
            skipped += pages["skipped_encrypted"].as_u64().unwrap_or(0);
            if pages["mismatched"].as_u64().unwrap_or(0) > 0 {
                mismatched.push(json!({
                    "arch": other["arch"], "hash_type": directory["hash_type"], "mismatched_pages": pages["mismatched"],
                    "of": pages["pages"], "first": pages["first_mismatches"], "page_size": directory["page_size"],
                }));
            }
            if let Some(error) = text(pages, "error") {
                errors.push(format!("{}: {error}", text(other, "arch").unwrap_or("?")));
            }
        }
    }
    let no_page_mismatch = mismatched.is_empty();
    if !mismatched.is_empty() {
        let pages: u64 = mismatched.iter().map(|m| m["mismatched_pages"].as_u64().unwrap_or(0)).sum();
        let mut found = finding(Section::Provenance, "apple.code-modified", Confidence::Verified, Severity::High)
            .param("file", name)
            .param("pages", pages);
        for entry in mismatched {
            found = found.evidence(Evidence::whole(file, entry));
        }
        out.finding(found);
    }
    let pages_intact = no_page_mismatch && checked > 0;
    if !errors.is_empty() {
        out.limitation("apple.pages-unchecked", Some(file), Some(errors.join("; ")));
    }

    // Special slots: the blobs inside the signature, and the bundle's Info.plist and CodeResources.
    let mut intact: Vec<String> = Vec::new();
    let mut broken: Vec<(String, &'static str)> = Vec::new();
    let labels = [
        ("requirements", "requirements"),
        ("entitlements", "entitlements"),
        ("entitlements_der", "DER entitlements"),
        ("embedded_info_plist", "embedded Info.plist"),
    ];
    for (key, label) in labels {
        let outcomes: BTreeSet<&str> = directories.iter().filter_map(|d| text(&d["slots"], key)).collect();
        if outcomes.contains("mismatch") {
            broken.push((label.to_string(), "mismatch"));
        } else if outcomes.contains("data-missing") {
            broken.push((label.to_string(), "data-missing"));
        } else if outcomes.contains("match") {
            intact.push(label.to_string());
        }
    }
    if let Some(bundle) = bundle {
        let sealed = [
            (SLOT_INFO_PLIST, "Info.plist", Some(bundle.info)),
            (SLOT_RESOURCES, "CodeResources", tree.get(&bundle.rooted("_CodeSignature/CodeResources"))),
        ];
        for (slot, label, target) in sealed {
            let mut outcomes: BTreeSet<&'static str> = BTreeSet::new();
            for directory in directories {
                let Some(stored) = text(&directory["special"], &slot.to_string()) else { continue };
                let Some(target) = target else {
                    outcomes.insert("data-missing");
                    continue;
                };
                let digest = match (text(directory, "hash_type"), &target.digests) {
                    (Some("sha1"), Some(digests)) => Some(digests.sha1.clone()),
                    (Some("sha256"), Some(digests)) => Some(digests.sha256.clone()),
                    (Some("sha256-truncated"), Some(digests)) => digests.sha256.get(..40).map(str::to_string),
                    (Some("sha384"), _) => tree.read(&target.path).ok().map(|bytes| hex::encode(sha2::Sha384::digest(&bytes[..]))),
                    _ => None,
                };
                match digest {
                    Some(digest) => outcomes.insert(if digest == stored { "match" } else { "mismatch" }),
                    None => outcomes.insert("unchecked"),
                };
            }
            if outcomes.contains("mismatch") {
                broken.push((label.to_string(), "mismatch"));
            } else if outcomes.contains("data-missing") {
                broken.push((label.to_string(), "data-missing"));
            } else if outcomes.contains("match") {
                intact.push(label.to_string());
            }
        }
    }
    if brief {
        if pages_intact {
            signed.intact_pages = checked;
        }
    } else if pages_intact {
        let rule = if intact.is_empty() { "apple.code-intact" } else { "apple.code-and-seal-intact" };
        out.finding(
            finding(Section::Provenance, rule, Confidence::Verified, Severity::Info)
                .param("file", name)
                .param("pages", checked)
                .param("archs", archs.join(", "))
                .param("slots", intact.join(", "))
                .evidence(Evidence::whole(
                    file,
                    json!({ "pages_checked": checked, "pages_skipped_encrypted": skipped, "slots_matching": intact }),
                )),
        );
    } else if !intact.is_empty() {
        out.finding(
            finding(Section::Provenance, "apple.seal-intact", Confidence::Verified, Severity::Info)
                .param("file", name)
                .param("slots", intact.join(", "))
                .evidence(place(json!({ "slots_matching": intact }))),
        );
    }
    for (label, problem) in broken {
        let (rule, severity) =
            if problem == "mismatch" { ("apple.seal-broken", Severity::High) } else { ("apple.seal-data-missing", Severity::Low) };
        out.finding(
            finding(Section::Provenance, rule, Confidence::Verified, severity)
                .param("file", name)
                .param("slot", label.as_str())
                .evidence(place(json!({ "slot": label, "outcome": problem }))),
        );
    }

    // Hardened runtime matters where Gatekeeper asks for it: Developer ID code on macOS.
    if platform == Platform::MacOs && slice["kind"] == "executable" {
        if signature["hardened_runtime"] == true && !brief {
            out.finding(
                finding(Section::Hardening, "apple.hardened-runtime", Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .evidence(place(json!({ "flags": signature["flag_names"], "runtime_version": signature["runtime_version"] }))),
            );
        } else if signature["hardened_runtime"] != true && !signing_type.starts_with("adhoc") {
            out.finding(
                finding(Section::Hardening, "apple.hardened-runtime-missing", Confidence::Verified, Severity::Low)
                    .param("file", name)
                    .evidence(place(json!({ "flags": signature["flag_names"] }))),
            );
        }
    }

    if let Some(error) = text(signature, "entitlements_error") {
        out.limitation("apple.entitlements-unreadable", Some(file), Some(error.to_string()));
    }
    if signature["entitlements_der_same_keys"] == false {
        out.finding(
            finding(Section::Anomalies, "apple.entitlements-differ", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(place(json!({ "xml": signature["entitlements"], "der": signature["entitlements_der"] }))),
        );
    }
    if signature["entitlements"].is_object() {
        signed.entitlements = Some(signature["entitlements"].clone());
        report_entitlements(file, name, &signature["entitlements"], signing_type, platform, bundle.is_some_and(|b| b.kind() == "app"), out);
    } else if platform == Platform::MacOs
        && bundle.is_some_and(|b| b.kind() == "app" && b.parent.is_none())
        && !signing_type.starts_with("adhoc")
    {
        out.finding(
            finding(Section::Hardening, "apple.sandbox-off", Confidence::Verified, Severity::Info)
                .param("file", name)
                .evidence(place(json!({ "entitlements": "none" }))),
        );
    }
    signed
}

fn report_cms(file: &Artifact, name: &str, cms: &Value, brief: bool, place: &dyn Fn(Value) -> Evidence, out: &mut Output) {
    let certificates = cms["chain"]["certificates"].as_array().map(Vec::as_slice).unwrap_or_default();
    let names: Vec<String> = certificates.iter().map(|c| text(c, "common_name").unwrap_or("?").to_string()).collect();
    let list_certificates = |mut found: aa_core::Finding| {
        for (index, certificate) in certificates.iter().enumerate() {
            found = found.evidence(Evidence::field(
                file,
                format!("cms.certificates[{index}]"),
                json!({
                    "subject": certificate["subject"], "issuer": certificate["issuer"], "serial": certificate["serial"],
                    "not_before": certificate["not_before"], "not_after": certificate["not_after"], "sha256": certificate["sha256"], "key": certificate["key"],
                }),
            ));
        }
        found
    };
    let links: Vec<&str> = cms["chain"]["links"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let anchor = text(&cms["chain"], "anchor").unwrap_or("");
    let anchored = !links.is_empty() && links.iter().all(|link| *link == "valid") && anchor.starts_with("known root: ");
    if !certificates.is_empty() && !brief && !anchored {
        out.finding(list_certificates(
            finding(Section::Provenance, "apple.certificate-chain", Confidence::Verified, Severity::Info)
                .param("file", name)
                .param("count", certificates.len())
                .param("chain", names.join(" ← ")),
        ));
    }
    let digest_matches = cms["digest_matches"].as_bool();
    let signature = text(cms, "signature").unwrap_or("");
    if signature == "valid" && digest_matches == Some(true) {
        if !brief {
            out.finding(
            finding(Section::Provenance, "apple.cms-valid", Confidence::Verified, Severity::Info)
                .param("file", name)
                .param("digest", text(cms, "digest_algorithm").unwrap_or("?"))
                .param("signer", text(&certificates.first().cloned().unwrap_or_default(), "common_name").unwrap_or("?"))
                .evidence(place(json!({ "message_digest_matches_code_directory": true, "signature": "valid", "alternate_directories_bound": cms["cdhashes_bound"] }))),
        );
        }
    } else if signature == "invalid" || digest_matches == Some(false) {
        out.finding(
            finding(Section::Provenance, "apple.cms-invalid", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(place(json!({ "message_digest_matches_code_directory": digest_matches, "signature": signature }))),
        );
    } else {
        out.limitation("apple.cms-unchecked", Some(file), Some(signature.to_string()));
    }
    if cms["cdhashes_bound"] == false {
        out.finding(
            finding(Section::Provenance, "apple.directory-unbound", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(place(json!({ "alternate_directories_bound": false }))),
        );
    }
    let chain_evidence = place(json!({ "links": links, "anchor": anchor }));
    if links.contains(&"invalid") {
        out.finding(
            finding(Section::Provenance, "apple.chain-broken", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(chain_evidence),
        );
    } else if links.iter().any(|link| link.starts_with("unchecked")) {
        out.limitation("apple.chain-unchecked", Some(file), Some(links.join("; ")));
    } else if let Some(root) = anchor.strip_prefix("known root: ") {
        if !brief {
            out.finding(list_certificates(
                finding(Section::Provenance, "apple.chain-apple-root", Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .param("root", root)
                    .param("count", links.len())
                    .param("chain", names.join(" ← "))
                    .evidence(chain_evidence),
            ));
        }
    } else if anchor.starts_with("self-signed") {
        out.finding(
            finding(Section::Provenance, "apple.chain-unknown-root", Confidence::Verified, Severity::Medium)
                .param("file", name)
                .evidence(chain_evidence),
        );
    } else if !certificates.is_empty() {
        out.finding(
            finding(Section::Provenance, "apple.chain-incomplete", Confidence::Verified, Severity::Low)
                .param("file", name)
                .evidence(chain_evidence),
        );
    }
    if let Some(time) = text(cms, "signing_time") {
        let rule = if cms["timestamped"] == true { "apple.signing-time-stamped" } else { "apple.signing-time" };
        if !brief {
            out.finding(
                finding(Section::Provenance, rule, Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .param("time", time)
                    .evidence(place(json!({ "signing_time": time, "timestamp_token": cms["timestamped"] }))),
            );
        }
        if cms["signed_within_validity"] == false {
            out.finding(
                finding(Section::Anomalies, "apple.signed-outside-validity", Confidence::Verified, Severity::Medium)
                    .param("file", name)
                    .param("time", time)
                    .evidence(place(json!({ "signing_time": time, "not_before": cms["chain"]["certificates"][0]["not_before"], "not_after": cms["chain"]["certificates"][0]["not_after"] }))),
            );
        }
    }
}

/// Entitlements that loosen the hardened runtime, and how much each matters.
const RUNTIME_EXCEPTIONS: &[(&str, Severity)] = &[
    ("com.apple.security.cs.allow-jit", Severity::Info),
    ("com.apple.security.cs.allow-unsigned-executable-memory", Severity::Low),
    ("com.apple.security.cs.disable-executable-page-protection", Severity::Medium),
    ("com.apple.security.cs.disable-library-validation", Severity::Low),
    ("com.apple.security.cs.allow-dyld-environment-variables", Severity::Low),
    ("com.apple.security.cs.debugger", Severity::Low),
];

fn report_entitlements(
    file: &Artifact,
    name: &str,
    entitlements: &Value,
    signing_type: &str,
    platform: Platform,
    is_app: bool,
    out: &mut Output,
) {
    let Some(map) = entitlements.as_object() else { return };
    let at = |key: &str| Evidence::field(file, format!("entitlements.{key}"), map.get(key).cloned().unwrap_or_default());
    let list = |key: &str| -> Vec<String> {
        match map.get(key) {
            Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            Some(Value::String(one)) => vec![one.clone()],
            _ => Vec::new(),
        }
    };
    if !map.is_empty() {
        let keys: Vec<String> = map.keys().cloned().collect();
        let mut found = finding(Section::Capabilities, "apple.entitlements", Confidence::Verified, Severity::Info)
            .param("file", name)
            .param("count", keys.len())
            .param("keys", shown(&keys));
        for key in keys.iter().take(40) {
            found = found.evidence(at(key));
        }
        out.finding(found);
    }
    for key in ["get-task-allow", "com.apple.security.get-task-allow"] {
        if map.get(key) == Some(&Value::Bool(true)) {
            // Expected in a development build, a defect in anything meant for distribution.
            let release = matches!(signing_type, "developer-id" | "distribution" | "mac-app-store" | "ios-app-store");
            out.finding(
                finding(
                    Section::Hardening,
                    if release { "apple.debuggable-release" } else { "apple.debuggable" },
                    Confidence::Verified,
                    if release { Severity::Medium } else { Severity::Low },
                )
                .param("file", name)
                .param("key", key)
                .reference("MASVS-RESILIENCE-4")
                .reference("CWE-489")
                .evidence(at(key)),
            );
        }
    }
    for (key, severity) in RUNTIME_EXCEPTIONS {
        if map.get(*key) == Some(&Value::Bool(true)) {
            out.finding(
                finding(Section::Hardening, "apple.runtime-exception", Confidence::Verified, *severity)
                    .param("file", name)
                    .param("key", *key)
                    .evidence(at(key)),
            );
        }
    }
    let exceptions: Vec<String> = map.keys().filter(|k| k.starts_with("com.apple.security.temporary-exception.")).cloned().collect();
    if !exceptions.is_empty() {
        let mut found = finding(Section::Hardening, "apple.sandbox-exceptions", Confidence::Verified, Severity::Low)
            .param("file", name)
            .param("keys", shown(&exceptions));
        for key in exceptions.iter().take(MAX_EVIDENCE) {
            found = found.evidence(at(key));
        }
        out.finding(found);
    }
    let private: Vec<String> = map.keys().filter(|k| k.starts_with("com.apple.private.")).cloned().collect();
    if !private.is_empty() {
        let mut found = finding(Section::Anomalies, "apple.private-entitlements", Confidence::Verified, Severity::Low)
            .param("file", name)
            .param("keys", shown(&private));
        for key in private.iter().take(MAX_EVIDENCE) {
            found = found.evidence(at(key));
        }
        out.finding(found);
    }
    if platform == Platform::MacOs && is_app {
        let sandboxed = map.get("com.apple.security.app-sandbox") == Some(&Value::Bool(true));
        out.finding(
            finding(
                Section::Hardening,
                if sandboxed { "apple.sandbox-on" } else { "apple.sandbox-off" },
                Confidence::Verified,
                Severity::Info,
            )
            .param("file", name)
            .evidence(at("com.apple.security.app-sandbox")),
        );
    }
    let listed = [
        ("com.apple.security.application-groups", "apple.app-groups"),
        ("keychain-access-groups", "apple.keychain-groups"),
        ("com.apple.developer.associated-domains", "apple.associated-domains"),
        ("com.apple.developer.icloud-container-identifiers", "apple.icloud-containers"),
    ];
    for (key, rule) in listed {
        let values = list(key);
        if !values.is_empty() {
            out.finding(
                finding(Section::Capabilities, rule, Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .param("count", values.len())
                    .param("values", shown(&values))
                    .evidence(at(key)),
            );
        }
    }
    for key in ["aps-environment", "com.apple.developer.aps-environment"] {
        if let Some(environment) = map.get(key).and_then(Value::as_str) {
            out.finding(
                finding(Section::Capabilities, "apple.push-notifications", Confidence::Verified, Severity::Info)
                    .param("file", name)
                    .param("environment", environment)
                    .evidence(at(key)),
            );
        }
    }
}

/// One entry of `CodeResources`.
enum Sealed {
    /// A file with its recorded digests (hex).
    File {
        sha1: Option<String>,
        sha256: Option<String>,
        optional: bool,
    },
    /// Nested code, identified by its cdhash.
    Code {
        cdhash: String,
    },
    Symlink,
}

fn sealed_entries(plist: &plist::Dictionary) -> (BTreeMap<String, Sealed>, &'static str) {
    let mut entries = BTreeMap::new();
    let (table, version) =
        match (plist.get("files2").and_then(plist::Value::as_dictionary), plist.get("files").and_then(plist::Value::as_dictionary)) {
            (Some(table), _) => (table, "files2"),
            (None, Some(table)) => (table, "files"),
            (None, None) => return (entries, "none"),
        };
    for (path, value) in table {
        let entry = match value {
            plist::Value::Data(digest) => Sealed::File { sha1: Some(hex::encode(digest)), sha256: None, optional: false },
            plist::Value::Dictionary(fields) => {
                if let Some(cdhash) = fields.get("cdhash").and_then(plist::Value::as_data) {
                    Sealed::Code { cdhash: hex::encode(cdhash) }
                } else if fields.contains_key("symlink") {
                    Sealed::Symlink
                } else {
                    Sealed::File {
                        sha1: fields.get("hash").and_then(plist::Value::as_data).map(hex::encode),
                        sha256: fields.get("hash2").and_then(plist::Value::as_data).map(hex::encode),
                        optional: truthy(fields.get("optional")) == Some(true),
                    }
                }
            }
            _ => continue,
        };
        entries.insert(path.clone(), entry);
    }
    (entries, version)
}

/// Every cdhash the code at `path` (a Mach-O file or a bundle folder) answers to.
fn cdhashes_at(tree: &dyn Tree, bundles: &[Bundle<'_>], path: &str) -> Option<Vec<String>> {
    let file = match tree.get(path) {
        Some(file) => file,
        None => {
            let nested = bundles.iter().find(|b| b.dir == path)?;
            tree.get(&nested.executable_path()?)?
        }
    };
    let all = slices(file);
    if all.is_empty() {
        return None;
    }
    Some(
        all.iter()
            .flat_map(|s| s["signature"]["directories"].as_array().into_iter().flatten())
            .filter_map(|d| d["cdhash"].as_str().map(str::to_string))
            .collect(),
    )
}

/// Compares the bundle's files with the digests sealed in `_CodeSignature/CodeResources`.
/// With `quiet`, only problems are reported. Returns true when files were checked and all matched.
pub fn resources(tree: &dyn Tree, bundles: &[Bundle<'_>], bundle: &Bundle<'_>, quiet: bool, out: &mut Output) -> bool {
    let Some(file) = tree.get(&bundle.rooted("_CodeSignature/CodeResources")) else { return false };
    out.kind(file, "code-resources");
    let plist = match tree.read(&file.path).map_err(|e| e.to_string()).and_then(|bytes| parse_plist(&bytes)) {
        Ok(plist) => plist,
        Err(error) => {
            out.limitation("apple.plist-unreadable", Some(file), Some(error));
            return false;
        }
    };
    let Some(dictionary) = plist.as_dictionary() else { return false };
    let (entries, version) = sealed_entries(dictionary);
    if version == "none" {
        return false;
    }
    let (mut matched, mut nested_matched) = (0u64, 0u64);
    let mut modified: Vec<&Artifact> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut nested_wrong: Vec<String> = Vec::new();
    let mut unchecked = 0u64;
    let mut nested_roots: Vec<String> = Vec::new();
    for (path, entry) in &entries {
        let full = bundle.rooted(path);
        match entry {
            Sealed::Symlink => {}
            Sealed::Code { cdhash } => {
                nested_roots.push(format!("{full}/"));
                match cdhashes_at(tree, bundles, &full) {
                    Some(found) if found.iter().any(|c| c == cdhash) => nested_matched += 1,
                    Some(_) => nested_wrong.push(path.clone()),
                    // The nested code is not in the tree (a symlinked framework version, a skipped file).
                    None => unchecked += 1,
                }
            }
            Sealed::File { sha1, sha256, optional } => {
                let Some(target) = tree.get(&full) else {
                    if !optional {
                        missing.push(path.clone());
                    }
                    continue;
                };
                let Some(digests) = &target.digests else {
                    unchecked += 1;
                    continue;
                };
                let same = match (sha256, sha1) {
                    (Some(expected), _) => *expected == digests.sha256,
                    (None, Some(expected)) => *expected == digests.sha1,
                    (None, None) => {
                        unchecked += 1;
                        continue;
                    }
                };
                if same {
                    matched += 1;
                } else {
                    modified.push(target);
                }
            }
        }
    }
    // Files on disk the seal does not mention. The rules that exempt files can be customised
    // per bundle; only the standard exemptions are applied here, hence "derived".
    let main_executable = bundle.executable_path();
    let root_prefix = if bundle.root.is_empty() { String::new() } else { format!("{}/", bundle.root) };
    let mut added: Vec<&Artifact> = Vec::new();
    for artifact in tree.under(&bundle.root) {
        // Files unpacked out of a file of the bundle are not bundle files.
        if artifact.parent != file.parent {
            continue;
        }
        let Some(relative) = artifact.path.strip_prefix(&root_prefix) else { continue };
        let name = artifact.name();
        let exempt = entries.contains_key(relative)
            || relative.starts_with("_CodeSignature/")
            || relative == "CodeResources"
            || relative == "Info.plist"
            || relative == "PkgInfo"
            || name == ".DS_Store"
            || relative.ends_with(".lproj/locversion.plist")
            || main_executable.as_deref() == Some(artifact.path.as_str())
            || nested_roots.iter().any(|nested| artifact.path.starts_with(nested.as_str()))
            // iOS seals the application's own folder contents but not these store-added files.
            || relative.starts_with("SC_Info/");
        if !exempt {
            added.push(artifact);
        }
    }
    let seal = |value: Value| Evidence::whole(file, value);
    let intact = matched + nested_matched > 0 && modified.is_empty() && nested_wrong.is_empty() && missing.is_empty() && added.is_empty();
    if !quiet && matched + nested_matched > 0 && modified.is_empty() && nested_wrong.is_empty() {
        out.finding(
            finding(Section::Provenance, "apple.resources-intact", Confidence::Verified, Severity::Info)
                .param("bundle", bundle.name())
                .param("files", matched)
                .param("nested", nested_matched)
                .evidence(seal(json!({ "table": version, "files_matching": matched, "nested_code_matching": nested_matched, "not_checkable": unchecked }))),
        );
    }
    if !modified.is_empty() {
        let mut found = finding(Section::Provenance, "apple.resources-modified", Confidence::Verified, Severity::High)
            .param("bundle", bundle.name())
            .param("count", modified.len());
        for target in modified.iter().take(MAX_EVIDENCE) {
            found = found.evidence(Evidence::whole(
                target,
                json!({ "matches_CodeResources": false, "sha256": target.digests.as_ref().map(|d| d.sha256.as_str()) }),
            ));
        }
        out.finding(found);
    }
    if !nested_wrong.is_empty() {
        out.finding(
            finding(Section::Provenance, "apple.nested-code-replaced", Confidence::Verified, Severity::High)
                .param("bundle", bundle.name())
                .param("count", nested_wrong.len())
                .param("paths", shown(&nested_wrong))
                .evidence(seal(json!(nested_wrong.iter().take(MAX_EVIDENCE).collect::<Vec<_>>()))),
        );
    }
    if !missing.is_empty() {
        out.finding(
            finding(Section::Provenance, "apple.resources-missing", Confidence::Verified, Severity::Medium)
                .param("bundle", bundle.name())
                .param("count", missing.len())
                .param("paths", shown(&missing))
                .evidence(seal(json!(missing.iter().take(MAX_EVIDENCE).collect::<Vec<_>>()))),
        );
    }
    if !added.is_empty() {
        let mut found = finding(Section::Provenance, "apple.resources-added", Confidence::Derived, Severity::Medium)
            .param("bundle", bundle.name())
            .param("count", added.len());
        for target in added.iter().take(MAX_EVIDENCE) {
            found = found.evidence(Evidence::whole(target, json!({ "listed_in_CodeResources": false })));
        }
        out.finding(found);
    }
    intact
}

/// A provisioning profile, as far as this crate reads it.
pub struct Profile {
    pub entitlements: Value,
    pub certificates: Vec<String>,
}

/// Reports an `embedded.mobileprovision` / `embedded.provisionprofile` file.
pub fn profile(tree: &dyn Tree, file: &Artifact, out: &mut Output) -> Option<Profile> {
    out.kind(file, "provisioning-profile");
    let fail = |out: &mut Output, error: String| {
        out.limitation("apple.profile-unreadable", Some(file), Some(error));
        None
    };
    let bytes = match tree.read(&file.path) {
        Ok(bytes) => bytes,
        Err(error) => return fail(out, error.to_string()),
    };
    let signed = match certs::Signed::parse(&bytes) {
        Ok(signed) => signed,
        Err(error) => return fail(out, error),
    };
    let Some(content) = signed.content() else { return fail(out, "the profile carries no content".into()) };
    let plist = match parse_plist(content) {
        Ok(plist) => plist,
        Err(error) => return fail(out, error),
    };
    let Some(dictionary) = plist.as_dictionary() else { return fail(out, "the profile is not a dictionary".into()) };
    let string = |key: &str| dictionary.get(key).and_then(plist::Value::as_string).map(str::to_string);
    let date = |key: &str| dictionary.get(key).and_then(plist::Value::as_date).map(|d| d.to_xml_format());
    let entitlements = dictionary.get("Entitlements").map(plist_to_json).unwrap_or(Value::Null);
    let devices = dictionary.get("ProvisionedDevices").and_then(plist::Value::as_array).map(Vec::len);
    let all_devices = truthy(dictionary.get("ProvisionsAllDevices")) == Some(true);
    let platforms = strings(dictionary.get("Platform"));
    let debuggable =
        ["get-task-allow", "com.apple.security.get-task-allow"].iter().any(|key| entitlements.get(key) == Some(&Value::Bool(true)));
    let is_mac = platforms.iter().any(|p| p == "OSX") || file.name().ends_with(".provisionprofile");
    let (profile_type, rule) = match (all_devices, devices, debuggable) {
        (true, _, _) if is_mac => ("developer-id", "apple.profile-developer-id"),
        (true, _, _) => ("enterprise", "apple.profile-enterprise"),
        (false, Some(_), true) => ("development", "apple.profile-development"),
        (false, Some(_), false) => ("ad-hoc", "apple.profile-ad-hoc"),
        (false, None, _) => ("app-store", "apple.profile-app-store"),
    };
    let developer_certificates: Vec<Vec<u8>> = dictionary
        .get("DeveloperCertificates")
        .and_then(plist::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_data().map(<[u8]>::to_vec))
        .collect();
    let certificates: Vec<certs::CertInfo> = certs::parse_certificates(&developer_certificates).iter().map(certs::CertInfo::of).collect();
    let team_ids = strings(dictionary.get("TeamIdentifier"));
    let check = signed.check(None).ok();
    let fact = json!({
        "name": string("Name"),
        "uuid": string("UUID"),
        "app_id_name": string("AppIDName"),
        "team_name": string("TeamName"),
        "team_identifiers": team_ids,
        "application_identifier_prefix": strings(dictionary.get("ApplicationIdentifierPrefix")),
        "platforms": platforms,
        "creation_date": date("CreationDate"),
        "expiration_date": date("ExpirationDate"),
        "type": profile_type,
        "provisions_all_devices": all_devices,
        // Device identifiers are personal data: only their number is kept.
        "provisioned_devices": devices,
        "xcode_managed": truthy(dictionary.get("IsXcodeManaged")),
        "entitlements": entitlements,
        "developer_certificates": certificates.iter().map(certs::CertInfo::json).collect::<Vec<_>>(),
        "signature": check.as_ref().map(certs::SignatureCheck::json),
    });
    out.fact(file, "apple.profile", fact);
    let field = |key: &str, value: Value| Evidence::field(file, key, value);
    let mut found = finding(Section::Provenance, "apple.profile", Confidence::Verified, Severity::Info)
        .param("name", string("Name").unwrap_or_default())
        .param("team", format!("{} ({})", string("TeamName").unwrap_or_default(), team_ids.join(", ")))
        .param("created", date("CreationDate").unwrap_or_default())
        .param("expires", date("ExpirationDate").unwrap_or_default())
        .evidence(field("Name", json!(string("Name"))))
        .evidence(field("UUID", json!(string("UUID"))))
        .evidence(field("TeamIdentifier", json!(team_ids)))
        .evidence(field("ExpirationDate", json!(date("ExpirationDate"))));
    if let Some(app_id) = entitlements.get("application-identifier").or_else(|| entitlements.get("com.apple.application-identifier")) {
        found = found.evidence(field("Entitlements.application-identifier", app_id.clone()));
    }
    out.finding(found);
    let severity = if profile_type == "enterprise" { Severity::Low } else { Severity::Info };
    out.finding(
        finding(Section::Provenance, rule, Confidence::Derived, severity)
            .param("devices", devices.unwrap_or(0))
            .evidence(field("ProvisionsAllDevices", json!(all_devices)))
            .evidence(field("ProvisionedDevices.count", json!(devices)))
            .evidence(field("Entitlements.get-task-allow", json!(debuggable))),
    );
    if let Some(check) = &check {
        if check.signature == certs::Verdict::Valid && check.digest_matches != Some(false) {
            out.finding(
                finding(Section::Provenance, "apple.profile-signature-valid", Confidence::Verified, Severity::Info)
                    .param("signer", check.leaf().and_then(|leaf| leaf.common_name.clone()).unwrap_or_default())
                    .param("anchored", check.chain.as_ref().is_some_and(certs::Chain::anchored))
                    .evidence(Evidence::whole(file, check.json())),
            );
        } else if check.signature == certs::Verdict::Invalid || check.digest_matches == Some(false) {
            out.finding(
                finding(Section::Provenance, "apple.profile-signature-invalid", Confidence::Verified, Severity::High)
                    .evidence(Evidence::whole(file, check.json())),
            );
        }
    }
    Some(Profile { entitlements, certificates: certificates.into_iter().map(|c| c.sha256).collect() })
}

/// True when the profile's value for an entitlement covers the binary's.
fn grants(allowed: &Value, wanted: &Value) -> bool {
    let pattern =
        |allowed: &str, wanted: &str| allowed == wanted || allowed.strip_suffix('*').is_some_and(|prefix| wanted.starts_with(prefix));
    match (allowed, wanted) {
        (Value::String(allowed), Value::String(wanted)) => pattern(allowed, wanted),
        (Value::Array(allowed), Value::Array(wanted)) => wanted.iter().all(|w| {
            allowed.iter().any(|a| match (a, w) {
                (Value::String(a), Value::String(w)) => pattern(a, w),
                _ => a == w,
            })
        }),
        (Value::Array(allowed), single) => allowed.iter().any(|a| grants(a, single)),
        // A profile that allows debugging also covers a binary that does not ask for it.
        (Value::Bool(true), Value::Bool(_)) => true,
        _ => allowed == wanted,
    }
}

/// Compares what the main executable claims with what its provisioning profile grants.
pub fn compare_profile(file: &Artifact, profile_file: &Artifact, profile: &Profile, signed: &Signed, out: &mut Output) {
    if let (Some(entitlements), Some(granted)) = (signed.entitlements.as_ref().and_then(Value::as_object), profile.entitlements.as_object())
    {
        let mut beyond: Vec<String> = Vec::new();
        for (key, wanted) in entitlements {
            match granted.get(key) {
                Some(allowed) if grants(allowed, wanted) => {}
                _ => beyond.push(key.clone()),
            }
        }
        if beyond.is_empty() {
            out.finding(
                finding(Section::Provenance, "apple.profile-covers-entitlements", Confidence::Derived, Severity::Info)
                    .param("count", entitlements.len())
                    .evidence(Evidence::whole(file, json!({ "entitlements": entitlements.keys().collect::<Vec<_>>() })))
                    .evidence(Evidence::field(profile_file, "Entitlements", json!(granted.keys().collect::<Vec<_>>()))),
            );
        } else {
            let mut found = finding(Section::Anomalies, "apple.profile-entitlement-mismatch", Confidence::Derived, Severity::Medium)
                .param("count", beyond.len())
                .param("keys", shown(&beyond));
            for key in beyond.iter().take(MAX_EVIDENCE) {
                found = found
                    .evidence(Evidence::field(file, format!("entitlements.{key}"), entitlements.get(key).cloned().unwrap_or_default()))
                    .evidence(Evidence::field(profile_file, format!("Entitlements.{key}"), granted.get(key).cloned().unwrap_or_default()));
            }
            out.finding(found);
        }
    }
    if let Some(leaf) = &signed.leaf_sha256
        && !profile.certificates.is_empty()
    {
        let listed = profile.certificates.iter().any(|c| c == leaf);
        out.finding(
            finding(
                if listed { Section::Provenance } else { Section::Anomalies },
                if listed { "apple.profile-lists-signer" } else { "apple.profile-signer-not-listed" },
                Confidence::Verified,
                if listed { Severity::Info } else { Severity::Medium },
            )
            .evidence(Evidence::whole(file, json!({ "signer_certificate_sha256": leaf })))
            .evidence(Evidence::field(profile_file, "DeveloperCertificates", json!(profile.certificates))),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_grants() {
        assert!(grants(&json!("TEAM.*"), &json!("TEAM.com.example.app")));
        assert!(!grants(&json!("TEAM.com.example.*"), &json!("TEAM.org.other")));
        assert!(grants(&json!(["TEAM.*"]), &json!(["TEAM.a", "TEAM.b"])));
        assert!(!grants(&json!(["TEAM.a"]), &json!(["TEAM.a", "OTHER.b"])));
        assert!(grants(&json!(["development", "production"]), &json!("production")));
        assert!(grants(&json!(true), &json!(false)));
        assert!(!grants(&json!(false), &json!(true)));
        assert!(grants(&json!("x"), &json!("x")));
    }

    #[test]
    fn sealed_entries_of_both_generations() {
        let plist = parse_plist(
            b"<plist><dict><key>files</key><dict><key>a</key><data>AAAA</data></dict>
              <key>files2</key><dict>
                <key>a</key><dict><key>hash2</key><data>AAAA</data></dict>
                <key>F.framework</key><dict><key>cdhash</key><data>AAAA</data><key>requirement</key><string>x</string></dict>
                <key>l</key><dict><key>symlink</key><string>a</string></dict>
                <key>junk</key><string>x</string>
              </dict></dict></plist>",
        )
        .expect("plist");
        let (entries, version) = sealed_entries(plist.as_dictionary().expect("dictionary"));
        assert_eq!(version, "files2");
        assert_eq!(entries.len(), 3);
        assert!(matches!(entries.get("a"), Some(Sealed::File { sha256: Some(h), .. }) if h == "000000"));
        assert!(matches!(entries.get("F.framework"), Some(Sealed::Code { cdhash }) if cdhash == "000000"));
        assert!(matches!(entries.get("l"), Some(Sealed::Symlink)));
        let empty = parse_plist(b"<plist><dict/></plist>").expect("plist");
        assert_eq!(sealed_entries(empty.as_dictionary().expect("dictionary")).1, "none");
    }
}
