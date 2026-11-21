//! P7X declarations and CMS mathematics, separate from package bytes and Windows policy.

use crate::der::{self, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE};
use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub(super) const MAX_BYTES: usize = 4 * 1024 * 1024;

fn finish(mut fields: der::Reader<'_>) -> Result<(), String> {
    if fields.next().is_some() { Err("extra MSIX signature fields".into()) } else { Ok(()) }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_BYTES || !bytes.starts_with(b"PKCX") {
        return Err("P7X prefix or byte budget is outside supported profile".into());
    }
    let cms = &bytes[4..];
    crate::catalog::bounded_asn1(cms).map_err(|r| r.replace("catalog", "MSIX CMS"))?;
    let (content, signatures) = crate::authenticode::msix_envelope(cms)?;
    let (indirect, rest) = der::parse_prefix(&content)?;
    if !rest.is_empty() || indirect.tag != TAG_SEQUENCE {
        return Err("MSIX indirect content is not one sequence".into());
    }
    let mut fields = indirect.children();
    let mut data = fields.expect(TAG_SEQUENCE)?.children();
    if data.expect(TAG_OID)?.oid().as_deref() != Some("1.3.6.1.4.1.311.2.1.30") {
        return Err("MSIX SIP data type is unsupported".into());
    }
    let mut sip = data.expect(TAG_SEQUENCE)?.children();
    finish(data)?;
    if sip.expect(TAG_INTEGER)?.integer_bytes() != Some(&[1, 1, 0, 0])
        || sip.expect(TAG_OCTET_STRING)?.content
            != [0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1]
    {
        return Err("MSIX SIP version or subject identifier is unsupported".into());
    }
    for _ in 0..5 {
        if sip.expect(TAG_INTEGER)?.integer_bytes() != Some(&[0]) {
            return Err("MSIX SIP reserved field is unsupported".into());
        }
    }
    finish(sip)?;
    let mut info = fields.expect(TAG_SEQUENCE)?.children();
    finish(fields)?;
    let mut algorithm = info.expect(TAG_SEQUENCE)?.children();
    if algorithm.expect(TAG_OID)?.oid().as_deref() != Some("2.16.840.1.101.3.4.2.1") {
        return Err("MSIX package digest algorithm is outside SHA256 profile".into());
    }
    if let Some(null) = algorithm.next() {
        let null = null?;
        if null.tag != 5 || !null.content.is_empty() {
            return Err("MSIX digest parameters are unsupported".into());
        }
    }
    finish(algorithm)?;
    let digests = info.expect(TAG_OCTET_STRING)?.content;
    finish(info)?;
    if !digests.starts_with(b"APPX") || !matches!(digests.len(), 148 | 184) {
        return Err("MSIX digest capsule length or prefix is unsupported".into());
    }
    let mut declarations = serde_json::Map::new();
    for record in digests[4..].chunks_exact(36) {
        let label = std::str::from_utf8(&record[..4]).map_err(|_| "MSIX digest label is not ASCII")?;
        if !matches!(label, "AXPC" | "AXCD" | "AXCT" | "AXBM" | "AXCI")
            || declarations.insert(label.into(), json!(hex::encode(&record[4..]))).is_some()
        {
            return Err("MSIX digest capsule has an unknown or repeated label".into());
        }
    }
    if ["AXPC", "AXCD", "AXCT", "AXBM"].iter().any(|label| !declarations.contains_key(*label)) {
        return Err("MSIX required digest declaration absent".into());
    }
    let mut fact = json!({"source_sha256":aa_core::sha256_hex(bytes),"algorithm":"sha256","digests":declarations,"cms":signatures,
        "package_digests_checked":false,"publisher_checked":false,"windows_trust_checked":false,"timestamp_checked":false,"certificate_policy_checked":false});
    redact(&mut fact)?;
    if serde_json::to_vec(&fact).map_err(|_| "MSIX signature publication failed")?.len() > 8 * 1024 * 1024 {
        return Err("MSIX signature fact byte limit".into());
    }
    Ok(fact)
}

fn redact(value: &mut Value) -> Result<(), String> {
    match value {
        Value::String(text) => *text = aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?,
        Value::Array(items) => {
            for item in items {
                redact(item)?;
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                redact(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("p7x") && !bytes.starts_with(b"PKCX") {
        return;
    }
    let fact = match parse(bytes) {
        Ok(fact) => fact,
        Err(reason) => {
            out.limitation("windows.msix-signature-unreadable", Some(file), Some(reason));
            return;
        }
    };
    if file.digests.as_ref().is_some_and(|d| fact["source_sha256"] != d.sha256) {
        out.limitation("windows.msix-signature-unreadable", Some(file), Some("P7X bytes differ from captured digest".into()));
        return;
    }
    let cms = fact["cms"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    out.kind(file, "msix-signature");
    let passed = cms
        .iter()
        .filter(|s| ["signed_attributes", "algorithms", "content_digest", "signature"].iter().all(|k| s["checks"][k] == "passed"))
        .count();
    let failed = cms.iter().filter(|s| ["content_digest", "signature"].iter().any(|k| s["checks"][k] == "failed")).count();
    if cms.is_empty() || passed + failed < cms.len() {
        out.limitation(
            "windows.msix-signature-unreadable",
            Some(file),
            Some("some CMS signature checks are unsupported or unresolved".into()),
        );
    }
    out.finding(
        Finding::new(Section::Provenance, "windows", "windows.msix-signature", Confidence::Verified, Severity::Info)
            .param("count", fact["digests"].as_object().map_or(0, |m| m.len()))
            .evidence(Evidence::field(file, "SpcIndirectDataContent/package digest capsule", fact["digests"].clone())),
    );
    for (rule, severity, count) in
        [("windows.msix-cms-signature", Severity::Info, passed), ("windows.msix-cms-mismatch", Severity::High, failed)]
    {
        if count > 0 {
            out.finding(
                Finding::new(Section::Provenance, "windows", rule, Confidence::Verified, severity)
                    .param("count", count)
                    .evidence(Evidence::field(file, "SignedData/SignerInfo cryptographic checks", fact["cms"].clone())),
            );
        }
    }
    out.limitation("windows.msix-signature-scope", Some(file), None);
    out.fact(file, "windows.msix-signature", fact);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        use std::io::Read;
        let mut archive =
            zip::ZipArchive::new(std::io::Cursor::new(include_bytes!("../tests/data/upstream-TestAppxPackage_Win32.appx").as_slice()))
                .expect("licensed fixture");
        let mut bytes = Vec::new();
        archive.by_name("AppxSignature.p7x").expect("signature").read_to_end(&mut bytes).expect("content");
        bytes
    }
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 128 {
            out.push(body.len() as u8);
        } else if body.len() < 256 {
            out.extend([0x81, body.len() as u8]);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }
    fn sequence(parts: Vec<Vec<u8>>) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }
    fn constructed() -> Vec<u8> {
        let hash = sequence(vec![tlv(6, &[0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1]), tlv(5, &[])]);
        let mut sip = vec![
            tlv(2, &[1, 1, 0, 0]),
            tlv(4, &[0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1]),
        ];
        for _ in 0..5 {
            sip.push(tlv(2, &[0]));
        }
        let mut capsule = b"APPX".to_vec();
        for label in [b"AXPC", b"AXCD", b"AXCT", b"AXBM"] {
            capsule.extend(label);
            capsule.extend([7; 32]);
        }
        let indirect = sequence(vec![
            sequence(vec![tlv(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 1, 0x1e]), sequence(sip)]),
            sequence(vec![hash.clone(), tlv(4, &capsule)]),
        ]);
        let signer = sequence(vec![
            tlv(2, &[1]),
            sequence(vec![sequence(vec![]), tlv(2, &[1])]),
            hash.clone(),
            tlv(0xa0, &[]),
            sequence(vec![tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1]), tlv(5, &[])]),
            tlv(4, &[1]),
        ]);
        let body = sequence(vec![
            tlv(2, &[1]),
            tlv(0x31, &hash),
            sequence(vec![tlv(6, &[0x2b, 6, 1, 4, 1, 0x82, 0x37, 2, 1, 4]), tlv(0xa0, &indirect)]),
            tlv(0x31, &signer),
        ]);
        let mut bytes = b"PKCX".to_vec();
        bytes.extend(sequence(vec![tlv(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]), tlv(0xa0, &body)]));
        bytes
    }
    #[test]
    fn constructed_declarations_without_a_captured_signer_do_not_claim_verified_cms() {
        let bytes = constructed();
        let fact = parse(&bytes).expect("bounded declarations with unknown key");
        assert_eq!(fact["digests"].as_object().expect("capsule").len(), 4);
        assert_ne!(fact["cms"][0]["checks"]["signature"], "passed");
    }
    #[test]
    fn malformed_capsules_encodings_and_changed_cms_parts_are_distinguished() {
        let original = fixture();
        let mut signature = original.clone();
        *signature.last_mut().expect("signature value") ^= 1;
        let fact = parse(&signature).expect("changed signature remains readable");
        assert_eq!(fact["cms"][0]["checks"]["signature"], "failed");
        assert_eq!(fact["cms"][0]["checks"]["content_digest"], "passed");
        let at = original.windows(4).position(|s| s == b"AXBM").expect("controlled capsule");
        let mut content = original.clone();
        content[at + 4] ^= 1;
        let fact = parse(&content).expect("changed digest remains readable");
        assert_eq!(fact["cms"][0]["checks"]["content_digest"], "failed");
        for name in [b"AXPC", b"XXXX"] {
            let mut bytes = original.clone();
            bytes[at..at + 4].copy_from_slice(name);
            assert!(parse(&bytes).is_err());
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(parse(&trailing).is_err());
        assert!(parse(&vec![0; MAX_BYTES + 1]).is_err());
        let guid = [0x4b, 0xdf, 0xc5, 0x0a, 0x07, 0xce, 0xe2, 0x4d, 0xb7, 0x6e, 0x23, 0xc8, 0x39, 0xa0, 0x9f, 0xd1];
        let position = original.windows(guid.len()).position(|s| s == guid).expect("SIP subject");
        let mut unknown = original.clone();
        unknown[position] ^= 1;
        assert!(parse(&unknown).is_err());
        for cut in 0..original.len() {
            assert!(parse(&original[..cut]).is_err());
        }
        for at in (4..original.len() - 4).step_by(13) {
            let mut bytes = original.clone();
            bytes[at..at + 4].fill(0xff);
            let _ = parse(&bytes);
        }
    }
    #[test]
    fn stale_captured_signature_bytes_do_not_publish_declarations_or_mathematics() {
        let bytes = fixture();
        let file = Artifact {
            path: "renamed.p7x".into(),
            parent: None,
            size: bytes.len() as u64,
            digests: Some(aa_core::Digests { md5: String::new(), sha1: String::new(), sha256: "00".repeat(32) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        };
        let mut out = Output::default();
        analyze(&file, &bytes, &mut out);
        assert!(out.facts.is_empty());
        assert!(out.findings.is_empty());
        assert!(out.limitations.iter().any(|l| l.code == "windows.msix-signature-unreadable"));
    }
    #[test]
    fn independent_microsoft_p7x_exposes_five_digests_and_verified_cms_mathematics() {
        use std::io::Read;
        let bytes = include_bytes!("../tests/data/upstream-TestAppxPackage_Win32.appx");
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes.as_slice())).expect("licensed APPX");
        let mut signature = Vec::new();
        archive.by_name("AppxSignature.p7x").expect("P7X").read_to_end(&mut signature).expect("P7X bytes");
        let fact = parse(&signature).expect("strict APPX signature");
        assert_eq!(fact["digests"].as_object().expect("digests").len(), 5);
        for check in ["signed_attributes", "algorithms", "content_digest", "signature"] {
            assert_eq!(fact["cms"][0]["checks"][check], "passed", "{check}: {fact}");
        }
        assert_eq!(fact["package_digests_checked"], false);
    }
}
