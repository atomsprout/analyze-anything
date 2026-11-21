//! Reconstruct the signed package regions without loading or trusting a package.

use super::{Directory, Entry, Result, map_bytes, n16, n32, span};
use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub(super) struct Budget {
    left: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Self { left: 512 * 1024 * 1024 }
    }
}

pub(super) fn read(bytes: &[u8], entry: &Entry<'_>, budget: &mut Budget) -> Result<Vec<u8>> {
    let cost = entry.size.checked_add(entry.compressed as u64).ok_or("signature footprint work overflow")?;
    budget.left = budget.left.checked_sub(cost).ok_or("signature footprint work budget exhausted")?;
    map_bytes(bytes, entry)
}

fn unsigned_directory(bytes: &[u8], directory: &Directory<'_>, signature: &Entry<'_>) -> Result<Vec<u8>> {
    let record_size = 46
        + n16(bytes, signature.central + 28)? as usize
        + n16(bytes, signature.central + 30)? as usize
        + n16(bytes, signature.central + 32)? as usize;
    if signature.end + signature.descriptor != directory.start || signature.central + record_size != directory.footer {
        return Err("signature is not the final local and central record in the checked signing profile");
    }
    let central = span(bytes, directory.start, signature.central - directory.start)?;
    let mut end = bytes.get(directory.footer..).ok_or("signature footer absent")?.to_vec();
    let count = directory.entries.len().checked_sub(1).ok_or("signature directory count underflow")?;
    let eocd = if directory.zip64 {
        for (at, value) in [(24, count), (32, count), (40, central.len()), (48, signature.local), (64, signature.local + central.len())] {
            end.get_mut(at..at + 8).ok_or("unsigned ZIP64 footer extent")?.copy_from_slice(&(value as u64).to_le_bytes());
        }
        76
    } else {
        0
    };
    for at in [8, 10] {
        if n16(&end, eocd + at)? != u16::MAX {
            end.get_mut(eocd + at..eocd + at + 2).ok_or("unsigned ZIP count extent")?.copy_from_slice(&(count as u16).to_le_bytes());
        }
    }
    // All values fit ZIP32 under the original-record reader's independent package/directory limits.
    for (at, value) in [(12, central.len()), (16, signature.local)] {
        if n32(&end, eocd + at)? != u32::MAX {
            end.get_mut(eocd + at..eocd + at + 4).ok_or("unsigned ZIP offset extent")?.copy_from_slice(&(value as u32).to_le_bytes());
        }
    }
    let mut reconstructed = Vec::with_capacity(central.len() + end.len());
    reconstructed.extend_from_slice(central);
    reconstructed.extend(end);
    Ok(reconstructed)
}

pub(super) fn analyze(tree: &dyn Tree, parent: &Artifact, bytes: &[u8], directory: &Directory<'_>, budget: &mut Budget, out: &mut Output) {
    let result = (|| -> Result<(Value, &Artifact)> {
        let entry = directory.entries.iter().find(|e| e.name == "AppxSignature.p7x").ok_or("canonical signature footprint absent")?;
        if entry.size > crate::msix_signature::MAX_BYTES as u64 {
            return Err("original P7X exceeds signature byte limit");
        }
        let path = if parent.path.is_empty() { "AppxSignature.p7x".into() } else { format!("{}/AppxSignature.p7x", parent.path) };
        let source = tree
            .get(&path)
            .filter(|s| s.parent.as_deref() == Some(parent.path.as_str()))
            .ok_or("signature child not captured in original container")?;
        let envelope = source.facts.get("windows.msix-signature").ok_or("signature declarations were not established")?;
        let bundle = directory.entries.iter().any(|e| e.name == crate::msix_bundle::MANIFEST);
        let package = directory.entries.iter().any(|e| e.name == "AppxManifest.xml");
        if bundle == package || envelope["sip_subject"] != if bundle { "appx-bundle" } else { "appx" } {
            return Err("SIP subject does not correspond to one canonical package or bundle manifest");
        }
        let signature = read(bytes, entry, budget)?;
        let digest = aa_core::sha256_hex(&signature);
        if source.digests.as_ref().is_none_or(|d| d.sha256 != digest) || envelope["source_sha256"] != digest {
            return Err("original P7X differs from captured declaration source");
        }
        let declared = envelope["digests"].as_object().ok_or("signature digest declarations absent")?;
        let ci = directory.entries.iter().any(|e| e.name == "AppxMetadata/CodeIntegrity.cat");
        let mut checks = Vec::new();
        for label in ["AXPC", "AXCD", "AXCT", "AXBM", "AXCI"] {
            let Some(expected) = declared.get(label).and_then(Value::as_str) else {
                continue;
            };
            let computed = (|| -> Result<String> {
                if label == "AXPC" {
                    if entry.end + entry.descriptor != directory.start {
                        return Err("signature is not the final local record in the checked signing profile");
                    }
                    return Ok(aa_core::sha256_hex(span(bytes, 0, entry.local)?));
                }
                if label == "AXCD" {
                    return Ok(aa_core::sha256_hex(&unsigned_directory(bytes, directory, entry)?));
                }
                let name = match label {
                    "AXCT" => "[Content_Types].xml",
                    "AXBM" => "AppxBlockMap.xml",
                    _ => "AppxMetadata/CodeIntegrity.cat",
                };
                let footprint = directory.entries.iter().find(|e| e.name == name).ok_or("declared signature footprint absent")?;
                Ok(aa_core::sha256_hex(&read(bytes, footprint, budget)?))
            })();
            checks.push(match computed {
                Ok(computed)=>json!({"label":label,"expected":expected,"computed":computed,"status":if expected==computed {"declared-digest-agrees"} else {"digest-mismatch"}}),
                Err(reason)=>json!({"label":label,"expected":expected,"status":"unresolved","reason":reason}),
            });
        }
        let matches = checks.iter().filter(|c| c["status"] == "declared-digest-agrees").count();
        let mismatches = checks.iter().filter(|c| c["status"] == "digest-mismatch").count();
        let unresolved = checks.iter().filter(|c| c["status"] == "unresolved").count();
        let cms_verified = envelope["cms"].as_array().is_some_and(|s| {
            !s.is_empty()
                && s.iter()
                    .all(|s| ["signed_attributes", "algorithms", "content_digest", "signature"].iter().all(|k| s["checks"][k] == "passed"))
        });
        Ok((
            json!({"profile":"sha256-msix-final-signature-record","source_sha256":parent.digests.as_ref().map(|d|d.sha256.as_str()),
            "signature_sha256":digest,"checks":checks,"matching_digests":matches,"mismatching_digests":mismatches,"unresolved_digests":unresolved,
            "code_integrity_declaration_corresponds_to_presence":ci==declared.contains_key("AXCI"),"cms_signature_verified":cms_verified,
            "all_declared_package_digests_agree":matches==declared.len() && unresolved==0 && mismatches==0,
            "publisher_checked":false,"certificate_policy_checked":false,"timestamp_checked":false,"windows_trust_checked":false}),
            source,
        ))
    })();
    let (mut fact, source) = match result {
        Ok(result) => result,
        Err(reason) => {
            out.limitation("windows.msix-signature-unbound", Some(parent), Some(reason.into()));
            return;
        }
    };
    for (rule, severity, key) in [
        ("windows.msix-package-digests", Severity::Info, "matching_digests"),
        ("windows.msix-package-digest-mismatch", Severity::High, "mismatching_digests"),
    ] {
        if fact[key].as_u64().unwrap_or(0) > 0 {
            out.finding(
                Finding::new(Section::Provenance, "windows", rule, Confidence::Verified, severity)
                    .param("count", fact[key].clone())
                    .evidence(Evidence::field(parent, "original package regions and footprint comparisons", fact["checks"].clone()))
                    .evidence(Evidence::field(source, "captured P7X/SHA256", fact["signature_sha256"].clone())),
            );
        }
    }
    if fact["unresolved_digests"].as_u64().unwrap_or(0) > 0 || fact["code_integrity_declaration_corresponds_to_presence"] != true {
        out.limitation(
            "windows.msix-signature-unbound",
            Some(parent),
            Some("some signature footprint comparisons or coverage were not established".into()),
        );
    }
    let publisher = super::publisher::analyze(tree, parent, bytes, directory, budget, &fact, out);
    fact["publisher_checked"] = publisher["publisher_checked"].clone();
    if publisher["publisher_checked"] == true {
        fact["publisher_matches"] = publisher["matches"].clone();
        fact["publisher_profile"] = publisher["profile"].clone();
        fact["publisher_manifest_signed_coverage"] = publisher["manifest_signed_coverage"]["established"].clone();
    }
    out.fact(parent, "windows.msix-signature-binding", fact);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_unsigned_region_reconstruction_matches_the_signed_capsule() {
        let bytes = include_bytes!("../../tests/data/upstream-TestAppxPackage_Win32.appx");
        let directory = super::super::parse(bytes).expect("native layout");
        let entry = directory.entries.iter().find(|e| e.name == "AppxSignature.p7x").expect("signature");
        let mut budget = Budget::default();
        let signature = read(bytes, entry, &mut budget).expect("P7X content");
        let declaration = crate::msix_signature::parse(&signature).expect("native capsule");
        assert_eq!(aa_core::sha256_hex(&bytes[..entry.local]), declaration["digests"]["AXPC"]);
        assert_eq!(
            aa_core::sha256_hex(&unsigned_directory(bytes, &directory, entry).expect("unsigned directory")),
            declaration["digests"]["AXCD"]
        );
        assert!(read(bytes, entry, &mut Budget { left: 0 }).is_err());
    }
    #[test]
    fn zip32_reconstruction_preserves_comments_and_refuses_nonfinal_signature_records() {
        let mut bytes = super::super::tests::stored("AppxSignature.p7x", b"dummy", 0);
        let end = bytes.len() - 22;
        bytes[end + 20..end + 22].copy_from_slice(&3u16.to_le_bytes());
        bytes.extend_from_slice(b"abc");
        let directory = super::super::parse(&bytes).expect("ZIP32");
        let entry = &directory.entries[0];
        let reconstructed = unsigned_directory(&bytes, &directory, entry).expect("unsigned empty ZIP");
        let mut expected = vec![0; 22];
        expected[..4].copy_from_slice(b"PK\x05\x06");
        expected[20] = 3;
        expected.extend_from_slice(b"abc");
        assert_eq!(reconstructed, expected);
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for name in ["AppxSignature.p7x", "after.bin"] {
            writer.start_file(name, zip::write::SimpleFileOptions::default()).expect("entry");
            writer.write_all(b"test").expect("bytes");
        }
        let bytes = writer.finish().expect("ZIP").into_inner();
        let directory = super::super::parse(&bytes).expect("layout");
        assert!(unsigned_directory(&bytes, &directory, &directory.entries[0]).is_err());
    }
}
