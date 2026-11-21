//! Bundle declarations versus raw stored packages, captured children and inner identities.

use super::{Directory, Result, map_bytes, parse, span};
use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn part_name(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 8192
        || name.ends_with([' ', '.'])
        || matches!(name, "." | "..")
        || name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err("package file name is outside the supported single OPC part-name profile");
    }
    let mut encoded = String::new();
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").map_err(|_| "OPC part-name encoding")?;
        }
    }
    if !name.ends_with(".appx") && !name.ends_with(".msix") {
        return Err("bundle payload extension is outside appx/msix profile");
    }
    Ok(encoded)
}

fn canonical_part(name: &str) -> Result<String> {
    let mut decoded = Vec::new();
    let mut bytes = name.as_bytes().iter();
    while let Some(byte) = bytes.next() {
        if *byte == b'%' {
            let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
            let high = bytes.next().copied().and_then(digit).ok_or("invalid OPC escape")?;
            let low = bytes.next().copied().and_then(digit).ok_or("invalid OPC escape")?;
            decoded.push(high * 16 + low);
        } else {
            decoded.push(*byte);
        }
    }
    let decoded = std::str::from_utf8(&decoded).map_err(|_| "OPC package name is not UTF-8")?;
    let canonical = part_name(decoded)?;
    if canonical != name {
        return Err("noncanonical OPC package name or encoded alias");
    }
    Ok(decoded.to_ascii_lowercase())
}

fn child<'a>(tree: &'a dyn Tree, parent: &Artifact, name: &str) -> Result<&'a Artifact> {
    let path = format!("{}/{name}", parent.path);
    tree.get(&path)
        .filter(|a| {
            a.parent.as_deref() == Some(&parent.path)
                && !a.facts.get("engine.entry-name").is_some_and(|f| f["normalized"] == true || f["colliding"] == true)
        })
        .ok_or("canonical child was not captured unambiguously in the same container")
}

fn bind(source: &Artifact, bytes: &[u8], fact: Option<&Value>) -> Result<()> {
    if source.size != bytes.len() as u64 {
        return Err("raw size differs from captured source");
    }
    let digest = aa_core::sha256_hex(bytes);
    if source.size != bytes.len() as u64
        || source.digests.as_ref().is_none_or(|d| d.sha256 != digest)
        || fact.is_some_and(|v| v["source_sha256"] != digest)
    {
        return Err("raw bytes differ from captured source or declaration digest");
    }
    Ok(())
}

fn compare(checks: &mut Vec<Value>, field: &str, declared: Value, observed: Value) {
    let agrees = if field == "version" {
        let quad = |value: &Value| -> Option<Vec<u16>> { value.as_str()?.split('.').map(|p| p.parse().ok()).collect() };
        match (quad(&declared), quad(&observed)) {
            (Some(a), Some(b)) if a.len() == 4 && b.len() == 4 => a == b,
            _ => false,
        }
    } else {
        declared == observed
    };
    checks.push(json!({"field":field,"status":if agrees {"agrees"}else{"differs"},"declared":declared,"observed":observed}));
}

fn package_type(model: &Value) -> Option<&'static str> {
    if model["property_sections"] != 1 {
        return None;
    }
    match model["resource_package"].as_str() {
        Some("true" | "1") => Some("resource"),
        Some("false" | "0") => Some("application"),
        None if !model["property_declarations"].as_array()?.iter().any(|r| r["name"] == "ResourcePackage") => Some("application"),
        _ => None,
    }
}

fn unresolved_package(directory: &Directory<'_>, row: &Value, reason: &str) -> Value {
    let mut checks = Vec::new();
    if row["projection_established"] == true
        && let Some(name) = row["file_name"].as_str().and_then(|s| part_name(s).ok())
        && let Some(entry) = directory.entries.iter().find(|e| e.name == name)
    {
        compare(&mut checks, "offset", row["offset"].clone(), json!(entry.data));
        if entry.method == 0 {
            compare(&mut checks, "size", row["size"].clone(), json!(entry.size));
        } else {
            checks.push(json!({"field":"size","status":"unresolved","declared":row["size"],"zip_compressed_extent":entry.compressed,
                "zip_uncompressed_size":entry.size,"reason":"stored-package size semantics cannot be applied to a compressed package"}));
        }
    }
    let differs = checks.iter().any(|c| c["status"] == "differs");
    json!({"status":if differs {"differs"}else{"unresolved"},"reason":reason,"checks":checks,
        "resource_declaration_comparison":{"status":"unresolved","reason":reason},"target_device_family_comparison":{"status":"unresolved","reason":reason},
        "inner_identity_comparison_performed":false,"bundle_signed_byte_coverage":false,"windows_trust_checked":false})
}

struct BundleInputs<'a, 'bytes> {
    parent: &'a Artifact,
    bytes: &'bytes [u8],
    directory: &'a Directory<'bytes>,
    model: &'a Value,
    binding: Option<&'a Value>,
}

fn check_package(tree: &dyn Tree, inputs: &BundleInputs<'_, '_>, row: &Value, work_left: &mut usize) -> Result<Value> {
    let BundleInputs { parent, bytes, directory, model, binding } = *inputs;
    if row["projection_established"] != true || model["identity_projection_established"] != true {
        return Err("bundle identity or package declaration is not reusable");
    }
    let name = part_name(row["file_name"].as_str().ok_or("package name absent")?)?;
    let entry = directory.entries.iter().find(|e| e.name == name).ok_or("declared package is absent from original ZIP directory")?;
    if entry.method != 0 {
        return Err("bundle payload package is compressed; stored package profile required");
    }
    let plain = span(bytes, entry.data, entry.compressed)?;
    *work_left = work_left.checked_sub(plain.len()).ok_or("nested package work budget exhausted")?;
    if crc32fast::hash(plain) != entry.crc {
        return Err("bundle payload CRC differs from raw ZIP declarations");
    }
    let target = child(tree, parent, &name)?;
    bind(target, plain, None)?;
    if target.unpacked_by.as_deref() != Some("zip") || target.facts.get("engine.container-listing").is_none_or(|f| f["complete"] != true) {
        return Err("nested package ZIP capture/listing is incomplete");
    }
    let nested = parse(plain)?;
    let manifest_entry = nested.entries.iter().find(|e| e.name == "AppxManifest.xml").ok_or("nested canonical package manifest absent")?;
    let cost = usize::try_from(manifest_entry.size)
        .ok()
        .and_then(|n| n.checked_add(manifest_entry.compressed))
        .ok_or("nested manifest work overflow")?;
    *work_left = work_left.checked_sub(cost).ok_or("nested manifest work budget exhausted")?;
    let manifest_bytes = map_bytes(plain, manifest_entry)?;
    let manifest = child(tree, target, "AppxManifest.xml")?;
    let identity = manifest.facts.get("windows.msix").ok_or("nested package identity absent")?;
    bind(manifest, &manifest_bytes, Some(identity))?;
    if identity["identity_projection_established"] != true {
        return Err("nested package identity is missing, ambiguous or unsupported");
    }
    let mut checks = Vec::new();
    compare(&mut checks, "offset", row["offset"].clone(), json!(entry.data));
    compare(&mut checks, "size", row["size"].clone(), json!(entry.size));
    for (field, declared) in
        [("name", &model["identity"]["name"]), ("publisher", &model["identity"]["publisher"]), ("version", &row["version"])]
    {
        compare(&mut checks, field, declared.clone(), identity["identity"][field].clone());
    }
    for (field, default) in [("architecture", "neutral"), ("resource_id", "")] {
        compare(&mut checks, field, row[field].clone(), json!(identity["identity"][field].as_str().unwrap_or(default)));
    }
    if let Some(kind) = package_type(identity) {
        compare(&mut checks, "type", row["type"].clone(), json!(kind));
    } else {
        checks.push(json!({"field":"type","status":"unresolved","reason":"ResourcePackage declaration is unread or ambiguous"}));
    }
    let coverage = binding.is_some_and(|b| {
        b["cms_signature_verified"] == true
            && b["all_declared_package_digests_agree"] == true
            && b["checks"]
                .as_array()
                .is_some_and(|checks| checks.iter().any(|c| c["label"] == "AXPC" && c["status"] == "declared-digest-agrees"))
    });
    let status = if checks.iter().any(|c| c["status"] == "differs") {
        "differs"
    } else if checks.iter().any(|c| c["status"] == "unresolved") {
        "partial"
    } else {
        "corresponds"
    };
    Ok(
        json!({"status":status,"target":target.path,"target_sha256":aa_core::sha256_hex(plain),"inner_manifest_sha256":aa_core::sha256_hex(&manifest_bytes),
        "checks":checks,"bundle_signed_byte_coverage":coverage,"coverage_basis":if coverage {Some("verified-CMS/AXPC-and-package-digests/stored-original-payload")}else{None},
        "coverage_reason":if coverage {None}else{Some("verified bundle CMS and original package digest correspondence were not established")},
        "resource_declaration_comparison":crate::msix_declarations::compare_resources(row,identity),
        "target_device_family_comparison":crate::msix_declarations::compare_families(row,identity),
        "inner_identity_comparison_performed":true,"inner_signature_required_inferred":false,"windows_trust_checked":false}),
    )
}

pub(crate) fn analyze(tree: &dyn Tree, out: &mut Output) {
    let sources: Vec<_> = tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.msix-bundle")).take(33).collect();
    if sources.len() > 32 || tree.artifacts().len() > 100_000 {
        out.limitation("windows.msix-bundle-unresolved", None, Some("bundle source or artifact index count budget".into()));
    }
    if tree.artifacts().len() > 100_000 {
        return;
    }
    let mut bytes_left = 512 * 1024 * 1024usize;
    let mut nested_left = 512 * 1024 * 1024usize;
    let mut published_left = 16 * 1024 * 1024usize;
    for source in sources.into_iter().take(32) {
        let result = (|| -> Result<(&Artifact, Value)> {
            let parent = source.parent.as_deref().and_then(|p| tree.get(p)).ok_or("original bundle ZIP not captured")?;
            if source.path != format!("{}/{}", parent.path, crate::msix_bundle::MANIFEST)
                || parent.unpacked_by.as_deref() != Some("zip")
                || parent.facts.get("engine.container-listing").is_none_or(|f| f["complete"] != true)
            {
                return Err("bundle manifest location or original ZIP listing is not established");
            }
            if parent.size > super::MAX_PACKAGE as u64 || parent.size > bytes_left as u64 {
                return Err("bundle original-byte budget exhausted");
            }
            bytes_left -= parent.size as usize;
            let raw = tree.read(&parent.path).map_err(|_| "original bundle bytes unreadable")?;
            if raw.len() > super::MAX_PACKAGE {
                return Err("original bundle byte budget exhausted after read");
            }
            bind(parent, &raw, None)?;
            let directory = parse(&raw)?;
            let entry =
                directory.entries.iter().find(|e| e.name == crate::msix_bundle::MANIFEST).ok_or("original bundle manifest absent")?;
            let model = &source.facts["windows.msix-bundle"];
            bind(source, &map_bytes(&raw, entry)?, Some(model))?;
            let mut aliases = BTreeSet::new();
            let mut actual = BTreeSet::new();
            for entry in &directory.entries {
                if entry.name.ends_with(".appx") || entry.name.ends_with(".msix") {
                    if !aliases.insert(canonical_part(entry.name)?) {
                        return Err("ambiguous decoded OPC package names");
                    }
                    actual.insert(entry.name.to_string());
                }
            }
            let binding = out
                .facts
                .iter()
                .rev()
                .find(|f| f.artifact.as_deref() == Some(&parent.path) && f.key == "windows.msix-signature-binding")
                .map(|f| f.value.clone());
            let mut records = Vec::new();
            let inputs = BundleInputs { parent, bytes: &raw, directory: &directory, model, binding: binding.as_ref() };
            for (index, row) in model["packages"].as_array().ok_or("bundle package declarations absent")?.iter().take(1024).enumerate() {
                if let Some(name) = row["file_name"].as_str().and_then(|s| part_name(s).ok()) {
                    actual.remove(&name);
                }
                let checked = match check_package(tree, &inputs, row, &mut nested_left) {
                    Ok(value) => value,
                    Err(reason) => unresolved_package(&directory, row, reason),
                };
                records.push(json!({"declaration":index,"result":checked}));
            }
            let count = |status: &str| records.iter().filter(|r| r["result"]["status"] == status).count();
            let facet_count = |facet: &str, status: &str| records.iter().filter(|r| r["result"][facet]["status"] == status).count();
            let undeclared: Vec<_> = actual.iter().take(128).map(|s| aa_core::text::redact_sensitive_text(s).ok()).collect();
            let unresolved_relationships = records
                .iter()
                .filter(|r| {
                    r["result"]["reason"].is_string()
                        || matches!(r["result"]["status"].as_str(), Some("partial" | "unresolved"))
                        || r["result"]["resource_declaration_comparison"]["status"] == "unresolved"
                        || r["result"]["target_device_family_comparison"]["status"] == "unresolved"
                })
                .count();
            let fact = json!({"profile":"stored-bundle-opc-v1","source_sha256":model["source_sha256"],"original_sha256":parent.digests.as_ref().map(|d|&d.sha256),
                "packages_corresponding":count("corresponds"),"packages_differing":count("differs"),"packages_partial":count("partial"),"packages_unresolved":count("unresolved"),
                "packages_with_unresolved_relationships":unresolved_relationships,
                "resource_declarations_agree":facet_count("resource_declaration_comparison","agrees"),
                "resource_declarations_differ":facet_count("resource_declaration_comparison","differs"),
                "resource_declarations_unresolved":facet_count("resource_declaration_comparison","unresolved"),
                "target_device_families_agree":facet_count("target_device_family_comparison","agrees"),
                "target_device_families_differ":facet_count("target_device_family_comparison","differs"),
                "target_device_families_unresolved":facet_count("target_device_family_comparison","unresolved"),
                "target_device_families_not_declared":facet_count("target_device_family_comparison","not-declared"),
                "records":records,"undeclared_packages":undeclared,"undeclared_packages_omitted":actual.len().saturating_sub(128),
                "schema_validated":false,"windows_trust_checked":false,"installation_eligibility_checked":false});
            let size = serde_json::to_vec(&fact).map_err(|_| "bundle comparison serialization")?.len();
            if size > 8 * 1024 * 1024 || size > published_left {
                return Err("bundle comparison output byte budget exhausted");
            }
            published_left -= size;
            Ok((parent, fact))
        })();
        match result {
            Ok((parent, fact)) => {
                out.kind(parent, "msix-bundle");
                for (rule, key, severity) in [
                    ("windows.msix-bundle-correspondence", "packages_corresponding", Severity::Info),
                    ("windows.msix-bundle-mismatch", "packages_differing", Severity::High),
                ] {
                    if fact[key].as_u64().unwrap_or(0) > 0 {
                        out.finding(
                            Finding::new(Section::Structure, "windows", rule, Confidence::Verified, severity)
                                .param("count", fact[key].clone())
                                .evidence(Evidence::field(
                                    source,
                                    "Bundle/Packages declarations versus original payloads",
                                    json!(
                                        fact["records"]
                                            .as_array()
                                            .into_iter()
                                            .flatten()
                                            .filter(|r| r["result"]["status"]
                                                == if key == "packages_corresponding" { "corresponds" } else { "differs" })
                                            .take(6)
                                            .collect::<Vec<_>>()
                                    ),
                                ))
                                .evidence(Evidence::field(parent, "captured original ZIP/SHA256", fact["original_sha256"].clone())),
                        );
                    }
                }
                for (facet, summary, status, rule) in [
                    ("resource_declaration_comparison", "resource_declarations_agree", "agrees", "windows.msix-bundle-resources"),
                    (
                        "resource_declaration_comparison",
                        "resource_declarations_differ",
                        "differs",
                        "windows.msix-bundle-resource-difference",
                    ),
                    ("target_device_family_comparison", "target_device_families_agree", "agrees", "windows.msix-bundle-device-families"),
                    (
                        "target_device_family_comparison",
                        "target_device_families_differ",
                        "differs",
                        "windows.msix-bundle-device-family-difference",
                    ),
                ] {
                    if fact[summary].as_u64().unwrap_or(0) > 0 {
                        let evidence:Vec<_>=fact["records"].as_array().into_iter().flatten().filter(|r|r["result"][facet]["status"]==status)
                            .take(6).map(|r|json!({"declaration":r["declaration"],"comparison":r["result"][facet],"inner_manifest_sha256":r["result"]["inner_manifest_sha256"]})).collect();
                        out.finding(
                            Finding::new(Section::Structure, "windows", rule, Confidence::Verified, Severity::Info)
                                .param("count", fact[summary].clone())
                                .evidence(Evidence::field(
                                    source,
                                    "Bundle/Packages declarations versus bound inner manifests",
                                    json!(evidence),
                                ))
                                .evidence(Evidence::field(parent, "captured original ZIP/SHA256", fact["original_sha256"].clone())),
                        );
                    }
                }
                if fact["packages_with_unresolved_relationships"] != 0 || !fact["undeclared_packages"].as_array().is_some_and(Vec::is_empty)
                {
                    out.limitation(
                        "windows.msix-bundle-unresolved",
                        Some(source),
                        Some("some package declarations, captured identities or undeclared payload relationships remain unresolved".into()),
                    );
                }
                out.fact(parent, "windows.msix-bundle-checks", fact);
            }
            Err(reason) => out.limitation("windows.msix-bundle-unresolved", Some(source), Some(reason.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opc_names_are_canonical_logical_identifiers_and_never_host_paths() {
        assert_eq!(part_name("महसुस.appx").expect("UTF8 OPC name"), "%E0%A4%AE%E0%A4%B9%E0%A4%B8%E0%A5%81%E0%A4%B8.appx");
        assert_eq!(part_name("a b.appx").expect("escaped space"), "a%20b.appx");
        assert_eq!(canonical_part("A%20B.appx").expect("canonical part"), "a b.appx");
        for name in ["../a.appx", "a/b.appx", "a\\b.appx", "C:a.appx", "a.appx.", "a.exe", "a\u{0}.appx"] {
            assert!(part_name(name).is_err(), "{name}");
        }
        for name in ["%61.appx", "a%2fb.appx", "a%2Fb.appx", "bad%.appx", "a%FF.appx"] {
            assert!(canonical_part(name).is_err(), "{name}");
        }
        let mut checks = Vec::new();
        compare(&mut checks, "version", json!("01.002.0.0"), json!("1.2.0.0"));
        compare(&mut checks, "version", json!("1.2.0.0"), json!("1.3.0.0"));
        assert_eq!(checks[0]["status"], "agrees");
        assert_eq!(checks[1]["status"], "differs");
    }
}
