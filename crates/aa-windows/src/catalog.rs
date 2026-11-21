//! Catalog structure and cryptographic checks. No Windows trust provider is used.

use std::collections::BTreeSet;

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::{Value, json};

use crate::der::{self, TAG_INTEGER, TAG_OCTET_STRING, TAG_SEQUENCE, TAG_SET, Tlv};

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_NODES: usize = 250_000;
const MAX_ENTRIES: usize = 16_384;
const INDIRECT: &str = "1.3.6.1.4.1.311.2.1.4";
const INFO: &str = "1.3.6.1.4.1.311.12.2.2";
const INFO2: &str = "1.3.6.1.4.1.311.12.2.3";
const PE_GUID: &str = "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}";
const FLAT_GUID: &str = "{DE351A42-8E59-11D0-8C47-00C04FC295EE}";
type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Default, Serialize)]
struct Member {
    index: usize,
    subject_identifier: String,
    reference_tag: Option<String>,
    sip_guid: Option<String>,
    data_oid: Option<String>,
    digest_algorithm: Option<String>,
    digest: Option<String>,
    sip_hash_profile: Option<&'static str>,
    #[serde(skip)]
    parameters: Option<&'static str>,
    attributes: Vec<Value>,
    issues: Vec<String>,
}

struct Catalog {
    subject_algorithm: String,
    identifier: Option<String>,
    sequence_number_encoded: Option<String>,
    this_update: String,
    next_update: Option<String>,
    members: Vec<Member>,
    signatures: Vec<Value>,
    issues: Vec<&'static str>,
}

// Count actual nodes before a shared CMS helper allocates lists. Primitive octets are
// opaque here; an encapsulated CTL receives the same check again before interpretation.
fn bounded_asn1(data: &[u8]) -> Result<()> {
    fn visit(node: Tlv<'_>, depth: usize, count: &mut usize) -> Result<()> {
        *count += 1;
        if depth > 32 || *count > MAX_NODES {
            return Err("catalog ASN.1 nesting or node budget exceeded".into());
        }
        // Support definite, minimally encoded DER. A permissive shared BER decoder
        // must not turn an untested representation into a successful catalog check.
        let length = *node.raw.get(1).ok_or("truncated catalog length")?;
        if length == 0x80 || (length > 0x80 && (node.content.len() < 128 || node.raw.get(2) == Some(&0))) {
            return Err("catalog BER or nonminimal DER lengths are unsupported".into());
        }
        if node.tag == crate::der::TAG_OID {
            if node.oid().is_none() || node.content.last().is_none_or(|b| b & 0x80 != 0) {
                return Err("invalid catalog OID encoding".into());
            }
            let mut first = true;
            for byte in node.content {
                if first && *byte == 0x80 {
                    return Err("nonminimal catalog OID encoding".into());
                }
                first = byte & 0x80 == 0;
            }
        }
        if node.tag == TAG_INTEGER
            && (node.content.is_empty()
                || (node.content.len() > 1
                    && ((node.content[0] == 0 && node.content[1] & 0x80 == 0) || (node.content[0] == 0xff && node.content[1] & 0x80 != 0))))
        {
            return Err("nonminimal catalog INTEGER encoding".into());
        }
        if node.tag & 0x20 != 0 {
            let mut previous = None;
            for child in node.children() {
                let child = child?;
                if node.tag == TAG_SET && previous.is_some_and(|p: &[u8]| p > child.raw) {
                    return Err("catalog DER SET is not ordered".into());
                }
                previous = Some(child.raw);
                visit(child, depth + 1, count)?;
            }
        }
        Ok(())
    }
    if data.len() > MAX_BYTES {
        return Err("catalog exceeds the 16 MiB input budget".into());
    }
    let (root, rest) = der::parse_prefix(data)?;
    if !rest.is_empty() {
        return Err("bytes follow the catalog ASN.1 object".into());
    }
    visit(root, 0, &mut 0)
}

fn exact(node: Tlv<'_>, tag: u8, maximum: usize) -> Result<Vec<Tlv<'_>>> {
    if node.tag != tag {
        return Err("unexpected catalog structure tag".into());
    }
    let mut fields = Vec::new();
    for field in node.children() {
        if fields.len() >= maximum {
            return Err("catalog field count exceeds the budget".into());
        }
        fields.push(field?);
    }
    Ok(fields)
}

fn one(node: Tlv<'_>) -> Result<Tlv<'_>> {
    let values = exact(node, TAG_SET, 1)?;
    values.first().copied().ok_or_else(|| "empty catalog attribute value set".into())
}

fn oid(node: Tlv<'_>) -> Result<String> {
    node.oid().ok_or_else(|| "invalid or oversized catalog OID".into())
}

fn algorithm(node: Tlv<'_>) -> Result<String> {
    let fields = exact(node, TAG_SEQUENCE, 2)?;
    if fields.len() == 2 && (fields[1].tag != 0x05 || !fields[1].content.is_empty()) {
        return Err("catalog algorithm parameters are unsupported".into());
    }
    oid(*fields.first().ok_or("catalog algorithm is absent")?)
}

fn member_info(value: Tlv<'_>, compact: bool) -> Result<String> {
    if compact {
        return match (value.tag, value.content) {
            (0x80, []) => Ok(PE_GUID.into()),
            (0x82, []) => Ok(FLAT_GUID.into()),
            _ => Err("compact member subject type is unsupported".into()),
        };
    }
    let fields = exact(value, TAG_SEQUENCE, 2)?;
    if fields.len() != 2 || fields[0].tag != 0x1e || fields[0].content.len() != 76 || fields[1].integer_bytes() != Some(&[2, 0]) {
        return Err("invalid catalog member-info structure".into());
    }
    let units: Vec<u16> = fields[0].content.chunks_exact(2).map(|b| u16::from_be_bytes([b[0], b[1]])).collect();
    let guid = String::from_utf16(&units).map_err(|_| "invalid member GUID text")?.to_ascii_uppercase();
    if guid.is_ascii()
        && guid.len() == 38
        && guid.starts_with('{')
        && guid.ends_with('}')
        && guid[1..37].bytes().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() })
    {
        Ok(guid)
    } else {
        Err("invalid member subject GUID".into())
    }
}

fn indirect(value: Tlv<'_>, member: &mut Member) -> Result<()> {
    let fields = exact(value, TAG_SEQUENCE, 2)?;
    if fields.len() != 2 {
        return Err("invalid member indirect data".into());
    }
    let data = exact(fields[0], TAG_SEQUENCE, 2)?;
    let digest = exact(fields[1], TAG_SEQUENCE, 2)?;
    if digest.len() != 2 || digest[1].tag != TAG_OCTET_STRING || digest[1].content.len() > 64 {
        return Err("invalid catalog member digest".into());
    }
    member.data_oid = Some(oid(*data.first().ok_or("member data OID is absent")?)?);
    member.parameters = data.get(1).and_then(|value| match value.raw {
        [0xa2, 2, 0x80, 0] => Some("flat-default"),
        [0x30, 10, 3, 2, 5, 0xa0, 0xa0, 4, 0xa2, 2, 0x80, 0] => Some("pe-default"),
        _ => None,
    });
    member.digest_algorithm = Some(algorithm(digest[0])?);
    member.digest = Some(hex::encode(digest[1].content));
    Ok(())
}

fn read_member(node: Tlv<'_>, index: usize, legacy: bool) -> Result<Member> {
    let fields = exact(node, TAG_SEQUENCE, 2)?;
    if fields.len() != 2 || fields[0].tag != TAG_OCTET_STRING || fields[0].content.len() > 512 {
        return Err("invalid or oversized catalog subject identifier".into());
    }
    let id = fields[0].content;
    // Version 1 tags are terminated UTF-16LE; version 2 identifiers are binary.
    let reference_tag = if legacy && id.len().is_multiple_of(2) && id.ends_with(&[0, 0]) {
        let units: Vec<u16> = id[..id.len() - 2].chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
        String::from_utf16(&units).ok().filter(|s| s.is_ascii() && s.bytes().all(|b| b.is_ascii_hexdigit()))
    } else {
        None
    };
    let mut member = Member { index, subject_identifier: hex::encode(id), reference_tag, ..Member::default() };
    let mut seen = BTreeSet::new();
    for attr in exact(fields[1], TAG_SET, 32)? {
        let fields = exact(attr, TAG_SEQUENCE, 2)?;
        if fields.len() != 2 {
            return Err("invalid catalog attribute".into());
        }
        let name = oid(fields[0])?;
        member
            .attributes
            .push(json!({"oid": name, "value_bytes": fields[1].raw.len(), "value_sha256": aa_core::sha256_hex(fields[1].raw)}));
        if !seen.insert(name.clone()) {
            member.issues.push("duplicate catalog member attribute".into());
            continue;
        }
        let result = match name.as_str() {
            INDIRECT => one(fields[1]).and_then(|v| indirect(v, &mut member)),
            INFO | INFO2 => one(fields[1]).and_then(|v| member_info(v, name == INFO2)).map(|guid| member.sip_guid = Some(guid)),
            _ => Err("opaque catalog member attribute".into()),
        };
        if let Err(reason) = result {
            member.issues.push(reason);
        }
    }
    if member.issues.iter().any(|i| i == "duplicate catalog member attribute") {
        // Conflicting declarations cannot later become verified coverage.
        member.digest = None;
        member.sip_guid = None;
    }
    member.sip_hash_profile = match (member.sip_guid.as_deref(), member.data_oid.as_deref(), member.parameters) {
        (Some(FLAT_GUID), Some("1.3.6.1.4.1.311.2.1.25"), Some("flat-default")) => Some("flat-file"),
        (Some(PE_GUID), Some("1.3.6.1.4.1.311.2.1.15"), Some("pe-default")) => Some("pe-default"),
        _ => None,
    };
    Ok(member)
}

fn parse(bytes: &[u8]) -> Result<Catalog> {
    bounded_asn1(bytes)?;
    let (ctl, signatures) = crate::authenticode::catalog_envelope(bytes)?;
    bounded_asn1(&ctl)?;
    let (root, _) = der::parse_prefix(&ctl)?;
    if root.tag != TAG_SEQUENCE {
        return Err("catalog CTL is not a sequence".into());
    }
    let mut fields = root.children();
    if let Some(version) = fields.optional(TAG_INTEGER)
        && version.integer_bytes() != Some(&[0])
    {
        return Err("unsupported CTL version".into());
    }
    let usage = fields.expect(TAG_SEQUENCE)?;
    let usage = exact(usage, TAG_SEQUENCE, 16)?.into_iter().map(oid).collect::<Result<Vec<_>>>()?;
    if usage != ["1.3.6.1.4.1.311.12.1.1"] {
        return Err("CTL usage is not the supported catalog-list usage".into());
    }
    let identifier = fields.optional(TAG_OCTET_STRING);
    if identifier.is_some_and(|v| v.content.len() > 256) {
        return Err("oversized CTL identifier".into());
    }
    let sequence_number = fields.optional(TAG_INTEGER);
    if sequence_number.is_some_and(|s| s.content.len() > 64) {
        return Err("oversized CTL sequence number".into());
    }
    let this_update = fields.any()?.time().ok_or("unsupported CTL update time")?;
    let next_update =
        fields.optional(0x17).or_else(|| fields.optional(0x18)).map(|v| v.time().ok_or("unsupported CTL next-update time")).transpose()?;
    let subject_algorithm = algorithm(fields.expect(TAG_SEQUENCE)?)?;
    let mut issues = Vec::new();
    if !matches!(subject_algorithm.as_str(), "1.3.6.1.4.1.311.12.1.2" | "1.3.6.1.4.1.311.12.1.3") {
        issues.push("unsupported catalog subject-identifier algorithm");
    }
    let entries = fields.optional(TAG_SEQUENCE);
    let mut members = Vec::new();
    if let Some(entries) = entries {
        for (index, member) in exact(entries, TAG_SEQUENCE, MAX_ENTRIES)?.into_iter().enumerate() {
            members.push(read_member(member, index, subject_algorithm == "1.3.6.1.4.1.311.12.1.2")?);
        }
    }
    if fields.next().is_some() {
        issues.push("CTL extensions or trailing fields are opaque");
    }
    Ok(Catalog {
        subject_algorithm,
        identifier: identifier.map(|v| hex::encode(v.content)),
        sequence_number_encoded: sequence_number.map(|v| hex::encode(v.content)),
        this_update,
        next_update,
        members,
        signatures,
        issues,
    })
}

fn redact(value: &mut Value) -> Result<()> {
    match value {
        Value::String(text) => *text = aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?,
        Value::Array(values) => {
            for value in values {
                redact(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                redact(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn signer_evidence(mut finding: Finding, file: &Artifact, index: usize, signature: &Value) -> Finding {
    for (key, field) in [
        ("checks", "checks"),
        ("message_digest_claimed", "signedAttrs/messageDigest"),
        ("content_digest_computed", "computedContentDigest"),
        ("signature_sha256", "signature/SHA256"),
    ] {
        if !signature[key].is_null() {
            finding = finding.evidence(Evidence::field(file, format!("SignedData/SignerInfo/{index}/{field}"), signature[key].to_string()));
        }
    }
    finding
}

fn signature_failed(signature: &Value) -> bool {
    ["content_digest", "signature"].iter().any(|check| signature["checks"][check] == "failed")
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("cat") {
        return;
    }
    let catalog = match parse(bytes) {
        Ok(catalog) => catalog,
        Err(reason) => {
            out.limitation("windows.catalog-unreadable", Some(file), Some(reason));
            return;
        }
    };
    let mut fact = json!({
        "subject_algorithm": catalog.subject_algorithm, "list_identifier": catalog.identifier,
        "sequence_number_encoded": catalog.sequence_number_encoded,
        "this_update_claimed": catalog.this_update, "next_update_claimed": catalog.next_update,
        "entries": catalog.members, "signatures": catalog.signatures, "issues": catalog.issues,
        "payloads_checked": false, "windows_trust_checked": false, "timestamps_verified": false,
    });
    if let Err(reason) = redact(&mut fact) {
        out.limitation("windows.catalog-unreadable", Some(file), Some(reason));
        return;
    }
    let partial = !catalog.issues.is_empty() || catalog.members.iter().any(|m| !m.issues.is_empty());
    let failed = catalog.signatures.iter().any(signature_failed);
    let unchecked = catalog.signatures.iter().any(|s| {
        s.get("unreadable").is_some()
            || s["unsigned_attributes_present"] == true
            || s["checks"]["embedded_chain"] != "passed"
            || s["checks"].as_object().is_none_or(|c| c.values().any(Value::is_object))
    });
    out.kind(file, "windows-catalog");
    let mut summary = Finding::new(Section::Provenance, "windows", "windows.catalog", Confidence::Verified, Severity::Info)
        .param("entries", catalog.members.len())
        .param("signatures", catalog.signatures.len())
        .evidence(Evidence::field(file, "SignedData/encapsulatedContentInfo/contentType", "1.3.6.1.4.1.311.10.1"))
        .evidence(Evidence::field(file, "CTL/subjectAlgorithm", catalog.subject_algorithm.as_str()));
    for (index, signature) in fact["signatures"].as_array().into_iter().flatten().enumerate() {
        summary = signer_evidence(summary, file, index, signature);
    }
    out.finding(summary);
    if failed {
        let mut finding =
            Finding::new(Section::Provenance, "windows", "windows.catalog-integrity-failed", Confidence::Verified, Severity::High);
        for (index, signature) in fact["signatures"].as_array().into_iter().flatten().enumerate() {
            if signature_failed(signature) {
                finding = signer_evidence(finding, file, index, signature);
            }
        }
        out.finding(finding);
    }
    if partial || unchecked {
        out.limitation("windows.catalog-partial", Some(file), None);
    }
    out.limitation("windows.catalog-scope", Some(file), None);
    out.fact(file, "windows.catalog", fact);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn fixture(version: usize, unsigned: bool) -> &'static [u8] {
        match (version, unsigned) {
            (1, false) => include_bytes!("../tests/data/native-catalog-v1.cat"),
            (1, true) => include_bytes!("../tests/data/native-catalog-v1-unsigned.cat"),
            (2, false) => include_bytes!("../tests/data/native-catalog-v2.cat"),
            _ => include_bytes!("../tests/data/native-catalog-v2-unsigned.cat"),
        }
    }

    #[test]
    fn native_catalog_profiles_keep_compatibility_entries_separate_and_check_signers() {
        for version in [1, 2] {
            for unsigned in [true, false] {
                let catalog = parse(fixture(version, unsigned)).expect("native MakeCat catalog");
                assert!(catalog.issues.is_empty());
                assert!(catalog.members.iter().all(|m| m.issues.is_empty()));
                assert_eq!(catalog.members.len(), if version == 1 { 2 } else { 4 });
                assert_eq!(catalog.members.iter().filter(|m| m.digest.is_some()).count(), 2);
                assert_eq!(catalog.signatures.len(), usize::from(!unsigned));
                for signature in &catalog.signatures {
                    for value in signature["checks"].as_object().expect("cryptographic checks").values() {
                        assert_eq!(value, "passed", "{signature}");
                    }
                    assert_eq!(signature["chain_reaches_embedded_root"], true);
                }
                let flat = catalog
                    .members
                    .iter()
                    .find(|m| m.sip_guid.as_deref() == Some(FLAT_GUID) && m.digest.is_some())
                    .expect("flat digest declaration");
                let bytes = b"Analyze Anything catalog fixture.\r\n";
                assert_eq!(
                    flat.digest.as_deref(),
                    Some(
                        if version == 1 { hex::encode(sha1::Sha1::digest(bytes)) } else { hex::encode(sha2::Sha256::digest(bytes)) }
                            .as_str()
                    )
                );
            }
        }
    }

    #[test]
    fn catalog_content_and_signature_corruption_fail_different_checks() {
        let bytes = fixture(2, false);
        let mut damaged = bytes.to_vec();
        *damaged.last_mut().expect("signature bytes") ^= 1;
        let parsed = parse(&damaged).expect("damaged signature stays structurally readable");
        assert_eq!(parsed.signatures[0]["checks"]["content_digest"], "passed");
        assert_eq!(parsed.signatures[0]["checks"]["signature"], "failed");
        let original = parse(bytes).expect("original catalog");
        let digest = hex::decode(original.members.iter().find_map(|m| m.digest.as_ref()).expect("member digest")).expect("hex digest");
        let offset = bytes.windows(digest.len()).rposition(|w| w == digest).expect("literal member digest");
        let mut damaged = bytes.to_vec();
        damaged[offset] ^= 1;
        let parsed = parse(&damaged).expect("damaged content stays structurally readable");
        assert_eq!(parsed.signatures[0]["checks"]["content_digest"], "failed");
        assert_eq!(parsed.signatures[0]["checks"]["signature"], "passed");
    }

    #[test]
    fn a_certificate_link_failure_does_not_become_a_catalog_content_failure() {
        let bytes = fixture(2, false);
        let (outer, _) = der::parse_prefix(bytes).expect("ContentInfo");
        let mut fields = outer.children();
        fields.expect(crate::der::TAG_OID).expect("signedData OID");
        let body = fields.expect(0xa0).expect("wrapper").children().expect(TAG_SEQUENCE).expect("SignedData");
        let bag = body.children().map(|v| v.expect("field")).find(|v| v.tag == 0xa0).expect("certificate bag");
        let certificate = bag.children().any().expect("embedded certificate");
        let offset = bytes.windows(certificate.raw.len()).position(|w| w == certificate.raw).expect("certificate bytes");
        let mut damaged = bytes.to_vec();
        damaged[offset + certificate.raw.len() - 1] ^= 1;
        let catalog = parse(&damaged).expect("certificate signature mutation");
        assert_eq!(catalog.signatures[0]["checks"]["signature"], "passed");
        assert_eq!(catalog.signatures[0]["checks"]["content_digest"], "passed");
        assert_eq!(catalog.signatures[0]["checks"]["embedded_chain"], "failed");
        let file = Artifact {
            path: "changed-chain.cat".into(),
            parent: None,
            size: damaged.len() as u64,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        };
        let mut out = Output::default();
        analyze(&file, &damaged, &mut out);
        assert!(!out.findings.iter().any(|f| f.rule == "windows.catalog-integrity-failed"));
        assert!(out.limitations.iter().any(|l| l.code == "windows.catalog-partial"));
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if content.len() < 128 {
            result.push(content.len() as u8);
        } else {
            let bytes = content.len().to_be_bytes();
            let bytes = &bytes[bytes.iter().position(|b| *b != 0).expect("nonzero length")..];
            result.push(0x80 | bytes.len() as u8);
            result.extend_from_slice(bytes);
        }
        result.extend_from_slice(content);
        result
    }

    #[test]
    fn unsupported_encodings_lengths_counts_and_unicode_guids_are_bounded_errors() {
        for bytes in [b"".as_slice(), b"not a catalog", &[0x30, 0x80, 0, 0], &[0x30, 0x81, 0], &[0x06, 1, 0x80], &[0x06, 2, 0x80, 0x01]] {
            assert!(parse(bytes).is_err());
        }
        assert!(parse(&vec![0; MAX_BYTES + 1]).is_err());
        let mut nested = tlv(TAG_OCTET_STRING, &[]);
        for _ in 0..34 {
            nested = tlv(TAG_SEQUENCE, &nested);
        }
        assert!(bounded_asn1(&nested).is_err());
        assert!(bounded_asn1(&tlv(TAG_SEQUENCE, &tlv(TAG_OCTET_STRING, &[]).repeat(MAX_NODES))).is_err());
        let nodes = tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &[]).repeat(MAX_ENTRIES + 1));
        assert!(exact(der::parse_prefix(&nodes).expect("DER sequence").0, TAG_SEQUENCE, MAX_ENTRIES).is_err());
        let bad_guid = "中".repeat(38);
        let mut fields = tlv(0x1e, &bad_guid.encode_utf16().flat_map(u16::to_be_bytes).collect::<Vec<_>>());
        fields.extend(tlv(TAG_INTEGER, &[2, 0]));
        let fields = tlv(TAG_SEQUENCE, &fields);
        assert!(member_info(der::parse_prefix(&fields).expect("member info").0, false).is_err());
        for length in 0..fixture(2, false).len() {
            assert!(parse(&fixture(2, false)[..length]).is_err());
        }
    }
}
