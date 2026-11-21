//! Digest agreement inside the supplied tree, independent of Windows trust or installation.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};
use sha2::Digest;

use crate::pe::{Pe, u16_at, u32_at};

const MAX_FILES: usize = 100_000;
const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;
const MAX_PE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TOTAL_PE_BYTES: usize = 512 * 1024 * 1024;
const MAX_CATALOGS: usize = 256;
const MAX_ENTRIES: usize = 32_768;
const MAX_MATCHES: usize = 4096;
const MAX_MATCH_PATH_BYTES: usize = 2 * 1024 * 1024;

/// Windows catalog SIP hashing adds zero alignment to unsigned PE files. This differs
/// from hashing the existing bytes alone and from some embedded-signature edge cases.
fn pe_digest<D: Digest>(pe: &Pe<'_>) -> Result<Vec<u8>, &'static str> {
    let bytes = pe.data;
    let optional = pe.pe_offset.checked_add(24).ok_or("PE header overflow")?;
    let optional_size = u16_at(bytes, pe.pe_offset + 20).ok_or("truncated COFF header")? as usize;
    let optional_end = optional.checked_add(optional_size).ok_or("optional header overflow")?;
    let entry = pe.directories_offset.checked_add(32).ok_or("security directory overflow")?;
    if entry + 8 > optional_end || optional_end > bytes.len() || pe.checksum_offset + 4 > entry {
        return Err("PE optional header has no complete security directory slot");
    }
    let section_end = optional_end.checked_add(usize::from(pe.declared_sections) * 40).ok_or("section table overflow")?;
    if pe.sections.len() != usize::from(pe.declared_sections)
        || section_end > pe.size_of_headers as usize
        || pe.size_of_headers as usize > bytes.len()
    {
        return Err("PE headers or section table are incomplete");
    }
    let mut image_end = pe.size_of_headers as usize;
    for section in &pe.sections {
        if section.raw_size == 0 {
            continue;
        }
        let end = (section.raw_pointer as usize).checked_add(section.raw_size as usize).ok_or("section extent overflow")?;
        if end > bytes.len() {
            return Err("PE section data extends beyond the supplied bytes");
        }
        image_end = image_end.max(end);
    }
    // The native SIP reads this fixed optional-header slot even when NumberOfRvaAndSizes
    // is smaller. Its availability is established above, independently of that count.
    let offset = u32_at(bytes, entry).ok_or("security directory offset is absent")? as usize;
    let size = u32_at(bytes, entry + 4).ok_or("security directory size is absent")? as usize;
    let (start, end, padding) = if offset == 0 || size == 0 {
        (bytes.len(), bytes.len(), (8 - bytes.len() % 8) % 8)
    } else {
        let end = offset.checked_add(size).ok_or("certificate extent overflow")?;
        if offset < image_end || end != bytes.len() || !offset.is_multiple_of(8) || !size.is_multiple_of(8) {
            return Err("PE certificate extent is not an aligned terminal table outside section data");
        }
        (offset, end, 0)
    };
    let mut hash = D::new();
    hash.update(bytes.get(..pe.checksum_offset).ok_or("checksum offset outside file")?);
    hash.update(bytes.get(pe.checksum_offset + 4..entry).ok_or("invalid checksum/security span")?);
    hash.update(bytes.get(entry + 8..start).ok_or("invalid security/content span")?);
    hash.update(bytes.get(end..).ok_or("invalid certificate extent")?);
    hash.update(&[0; 7][..padding]);
    Ok(hash.finalize().to_vec())
}

type Key<'a> = (Option<&'a str>, &'static str, &'static str, String);
struct Index<'a> {
    matches: BTreeMap<Key<'a>, Vec<&'a Artifact>>,
    incomplete_pe: BTreeSet<Option<&'a str>>,
    incomplete_flat: BTreeSet<Option<&'a str>>,
}

fn algorithm(oid: &str) -> Option<&'static str> {
    match oid {
        "1.3.14.3.2.26" => Some("sha1"),
        "2.16.840.1.101.3.4.2.1" => Some("sha256"),
        _ => None,
    }
}

fn index<'a>(tree: &'a dyn Tree, pe_scopes: &BTreeSet<Option<&str>>, out: &mut Output) -> Result<Index<'a>, &'static str> {
    if tree.artifacts().len() > MAX_FILES {
        return Err("catalog digest index exceeds 100,000 artifacts");
    }
    let mut paths = 0usize;
    for file in tree.artifacts() {
        paths = paths.saturating_add(file.path.len());
        if paths > MAX_PATH_BYTES || file.path.len() > 8192 {
            return Err("catalog digest index exceeds its path budget");
        }
    }
    let mut index = Index { matches: BTreeMap::new(), incomplete_pe: BTreeSet::new(), incomplete_flat: BTreeSet::new() };
    let mut pe_bytes = 0usize;
    for file in tree.artifacts() {
        let scope = file.parent.as_deref();
        if file.facts.get("windows.pe-structure-unreadable") == Some(&Value::Bool(true)) {
            index.incomplete_pe.insert(scope);
        }
        let Some(digests) = &file.digests else {
            index.incomplete_flat.insert(scope);
            index.incomplete_pe.insert(scope);
            continue;
        };
        for (algorithm, digest) in [("sha1", &digests.sha1), ("sha256", &digests.sha256)] {
            index.matches.entry((scope, "flat-file", algorithm, digest.clone())).or_default().push(file);
        }
        if !pe_scopes.contains(&scope) || !file.facts.contains_key("windows.pe") {
            continue;
        }
        let result = (|| {
            let size = usize::try_from(file.size).map_err(|_| "PE byte size is outside the index profile")?;
            if size > MAX_PE_BYTES || pe_bytes.saturating_add(size) > MAX_TOTAL_PE_BYTES {
                return Err("PE SIP byte budget exhausted");
            }
            pe_bytes += size;
            let bytes = tree.read(&file.path).map_err(|_| "supplied PE bytes could not be read")?;
            if bytes.len() != size {
                return Err("supplied PE byte length changed");
            }
            // Freeze once, and bind all SIP calculations to the report's original digest.
            let snapshot = bytes.to_vec();
            if aa_core::sha256_hex(&snapshot) != digests.sha256 {
                return Err("supplied PE bytes do not match the report digest");
            }
            let pe = Pe::parse(&snapshot).map_err(|_| "supplied PE structure could not be read")?;
            Ok((hex::encode(pe_digest::<sha1::Sha1>(&pe)?), hex::encode(pe_digest::<sha2::Sha256>(&pe)?)))
        })();
        match result {
            Ok((sha1, sha256)) => {
                for (algorithm, digest) in [("sha1", sha1), ("sha256", sha256)] {
                    index.matches.entry((scope, "pe-default", algorithm, digest)).or_default().push(file);
                }
            }
            Err(reason) => {
                index.incomplete_pe.insert(scope);
                out.limitation("windows.catalog-payload-unchecked", Some(file), Some(reason.into()));
            }
        }
    }
    Ok(index)
}

fn namespace_complete(tree: &dyn Tree, source: &Artifact) -> bool {
    match source.parent.as_deref() {
        None => tree.summary().get("engine.input-listing").and_then(|v| v.get("complete")) == Some(&Value::Bool(true)),
        Some(parent) => {
            tree.get(parent).and_then(|p| p.facts.get("engine.container-listing")).and_then(|v| v.get("complete"))
                == Some(&Value::Bool(true))
        }
    }
}

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    let catalogs: Vec<_> = tree.artifacts().iter().filter(|f| f.facts.contains_key("windows.catalog")).collect();
    if catalogs.is_empty() {
        return;
    }
    let pe_scopes: BTreeSet<_> = catalogs
        .iter()
        .filter(|f| {
            f.facts["windows.catalog"]["entries"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|e| e["sip_hash_profile"] == "pe-default"))
        })
        .map(|f| f.parent.as_deref())
        .collect();
    let index = match index(tree, &pe_scopes, out) {
        Ok(index) => index,
        Err(reason) => {
            out.limitation("windows.catalog-membership-limit", None, Some(reason.into()));
            return;
        }
    };
    let mut entries_left = MAX_ENTRIES;
    let mut matches_left = MAX_MATCHES;
    let mut path_bytes_left = MAX_MATCH_PATH_BYTES;
    for (source_index, source) in catalogs.iter().enumerate() {
        if source_index >= MAX_CATALOGS {
            out.limitation("windows.catalog-membership-limit", None, Some("only the first 256 catalog sources were considered".into()));
            break;
        }
        let catalog = &source.facts["windows.catalog"];
        let binding: Vec<_> = catalog["signatures"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|s| ["signed_attributes", "algorithms", "content_digest", "signature"].iter().all(|key| s["checks"][key] == "passed"))
            .filter_map(|s| s["index"].as_u64())
            .collect();
        let scope = source.parent.as_deref();
        let listing_complete = namespace_complete(tree, source);
        let mut records = Vec::new();
        let mut matched = 0;
        let mut unresolved = 0;
        let mut omitted = 0;
        let mut details_truncated = false;
        let mut evidence = Vec::new();
        for (position, entry) in catalog["entries"].as_array().into_iter().flatten().enumerate() {
            if entries_left == 0 {
                omitted = catalog["entries"].as_array().map_or(0, Vec::len).saturating_sub(position);
                break;
            }
            entries_left -= 1;
            let Some(digest) = entry["digest"].as_str() else {
                let opaque = entry["issues"].as_array().is_some_and(|issues| !issues.is_empty());
                if opaque {
                    unresolved += 1;
                }
                records.push(json!({"entry": entry["index"], "status": if opaque {"uninterpreted-member-declaration"} else {"no-explicit-member-digest"}}));
                continue;
            };
            let profile = entry["sip_hash_profile"].as_str().filter(|p| matches!(*p, "flat-file" | "pe-default"));
            let algorithm = entry["digest_algorithm"].as_str().and_then(algorithm);
            let (Some(profile), Some(algorithm)) = (profile, algorithm) else {
                unresolved += 1;
                records.push(json!({"entry": entry["index"], "status": "unsupported-hash-profile-or-algorithm"}));
                continue;
            };
            if digest.len() != if algorithm == "sha1" { 40 } else { 64 } || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                unresolved += 1;
                records.push(json!({"entry": entry["index"], "status": "invalid-declared-digest-width"}));
                continue;
            }
            let identifier_matches = match catalog["subject_algorithm"].as_str() {
                Some("1.3.6.1.4.1.311.12.1.2") => entry["reference_tag"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(digest)),
                Some("1.3.6.1.4.1.311.12.1.3") => entry["subject_identifier"].as_str().is_some_and(|id| id.eq_ignore_ascii_case(digest)),
                _ => false,
            };
            if !identifier_matches {
                unresolved += 1;
                records.push(json!({"entry": entry["index"], "status": "subject-identifier-outside-supported-hash-tag-profile"}));
                continue;
            }
            let search_complete = listing_complete
                && !if profile == "pe-default" { index.incomplete_pe.contains(&scope) } else { index.incomplete_flat.contains(&scope) };
            let candidates = index.matches.get(&(scope, profile, algorithm, digest.into())).map(Vec::as_slice).unwrap_or_default();
            let mut targets = Vec::new();
            for target in candidates.iter().take(8) {
                if matches_left == 0 || target.path.len() > path_bytes_left {
                    break;
                }
                matches_left -= 1;
                path_bytes_left -= target.path.len();
                targets.push(json!({"path": target.path, "sha256": target.digests.as_ref().map(|d| d.sha256.as_str())}));
                if evidence.len() < 12 {
                    evidence.push((position, *target, profile, digest));
                }
            }
            if candidates.is_empty() {
                unresolved += 1;
            } else {
                matched += 1;
            }
            details_truncated |= targets.len() < candidates.len();
            records.push(json!({"entry": entry["index"], "status": if candidates.is_empty() {"no-matching-checked-artifact"} else {"digest-agreement"},
                "sip_hash_profile": profile, "algorithm": algorithm, "declared_digest": digest, "observed_match_count": candidates.len(),
                "search_complete": search_complete, "matches_truncated": targets.len() < candidates.len(), "matches": targets}));
        }
        if !evidence.is_empty() {
            let mut finding =
                Finding::new(Section::Provenance, "windows", "windows.catalog-digest-agreement", Confidence::Derived, Severity::Info)
                    .param("count", matched)
                    .param("signers", binding.len());
            for (entry, target, profile, digest) in evidence {
                finding = finding
                    .evidence(Evidence::field(source, format!("CTL/entries/{entry}/digest"), digest))
                    .evidence(Evidence::field(target, format!("SIP/{profile}/digest"), digest))
                    .evidence(Evidence::field(
                        target,
                        "supplied artifact/SHA256",
                        target.digests.as_ref().map(|d| d.sha256.as_str()).unwrap_or(""),
                    ));
            }
            out.finding(finding);
        }
        if unresolved > 0 {
            out.limitation(
                "windows.catalog-membership-unresolved",
                Some(source),
                Some(aa_core::counted(unresolved, "entries were unresolved")),
            );
        }
        if omitted > 0 {
            out.limitation(
                "windows.catalog-membership-limit",
                Some(source),
                Some(aa_core::counted(omitted as u64, "entries were not compared")),
            );
        }
        if details_truncated {
            out.limitation(
                "windows.catalog-membership-limit",
                Some(source),
                Some("match details reached a per-entry or global output budget".into()),
            );
        }
        out.fact(
            source,
            "windows.catalog-membership",
            json!({"entries": records, "entries_omitted": omitted,
            "signed_content_binding_signers": binding, "namespace_listing_complete": listing_complete, "windows_trust_checked": false,
            "windows_catalog_api_acceptance_checked": false,
            "profile": "supplied-artifact-digest-agreement-within-parent-container"}),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;
    use aa_core::plugin::Bytes;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Supplied {
        files: Vec<Artifact>,
        complete: BTreeMap<String, Value>,
        bytes: BTreeMap<String, Vec<u8>>,
        reads: AtomicUsize,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn summary(&self) -> &BTreeMap<String, Value> {
            &self.complete
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.bytes.get(path).map(|v| Bytes::from_vec(v.clone())).ok_or_else(|| std::io::Error::other("no supplied bytes"))
        }
    }
    fn file(path: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: bytes.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: hex::encode(sha1::Sha1::digest(bytes)), sha256: aa_core::sha256_hex(bytes) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    fn tree(profile: &str, digest: &str) -> Supplied {
        let mut catalog = file("a.cat", b"catalog");
        catalog.facts.insert(
            "windows.catalog".into(),
            json!({"subject_algorithm":"1.3.6.1.4.1.311.12.1.3","signatures":[],"entries":[{
                "index":0,"digest":digest,"digest_algorithm":"2.16.840.1.101.3.4.2.1","sip_hash_profile":profile,"subject_identifier":digest
            }]}),
        );
        Supplied {
            files: vec![catalog],
            complete: BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]),
            bytes: BTreeMap::new(),
            reads: AtomicUsize::new(0),
        }
    }
    fn comparison(out: &Output) -> &Value {
        &out.facts.iter().find(|f| f.key == "windows.catalog-membership").expect("comparison fact").value["entries"][0]
    }

    #[test]
    fn digest_relations_do_not_cross_containers_and_do_not_need_flat_payload_reads() {
        let mut supplied = tree("flat-file", &aa_core::sha256_hex(b"payload"));
        let mut nested = file("archive/payload", b"payload");
        nested.parent = Some("archive".into());
        supplied.files.push(nested);
        let mut out = Output::default();
        analyze(&supplied, &mut out);
        assert_eq!(comparison(&out)["status"], "no-matching-checked-artifact");
        supplied.files.push(file("中文.dat", b"payload"));
        supplied.complete.clear();
        let mut out = Output::default();
        analyze(&supplied, &mut out);
        assert_eq!(comparison(&out)["status"], "digest-agreement");
        assert_eq!(comparison(&out)["search_complete"], false);
        assert_eq!(supplied.reads.load(Ordering::Relaxed), 0, "flat digest comparison must use captured report digests");
    }

    #[test]
    fn stale_pe_bytes_and_exhausted_read_budgets_cannot_establish_digest_agreement() {
        let original = sample("hello.exe");
        let mut changed = original.clone();
        changed[100] ^= 1;
        let desired = hex::encode(pe_digest::<sha2::Sha256>(&Pe::parse(&changed).expect("changed PE")).expect("changed SIP digest"));
        let mut supplied = tree("pe-default", &desired);
        let mut payload = file("payload.exe", &original);
        payload.facts.insert("windows.pe".into(), json!({}));
        supplied.files.push(payload.clone());
        supplied.bytes.insert("payload.exe".into(), changed);
        let mut out = Output::default();
        analyze(&supplied, &mut out);
        assert_eq!(comparison(&out)["status"], "no-matching-checked-artifact");
        assert_eq!(comparison(&out)["search_complete"], false);
        assert!(out.limitations.iter().any(|l| l.code == "windows.catalog-payload-unchecked"));
        let mut supplied = tree("pe-default", &desired);
        for index in 0..9 {
            let mut f = payload.clone();
            f.path = format!("payload-{index}.exe");
            f.size = MAX_PE_BYTES as u64;
            supplied.files.push(f);
        }
        let mut out = Output::default();
        analyze(&supplied, &mut out);
        assert_eq!(supplied.reads.load(Ordering::Relaxed), 8, "the total byte budget applies before an additional read");
        assert_eq!(comparison(&out)["search_complete"], false);
    }

    #[test]
    fn index_and_match_detail_limits_are_visible_without_inventing_unique_targets() {
        let mut supplied = tree("flat-file", &aa_core::sha256_hex(b"payload"));
        for index in 0..10 {
            supplied.files.push(file(&format!("payload-{index}"), b"payload"));
        }
        let mut out = Output::default();
        analyze(&supplied, &mut out);
        assert_eq!(comparison(&out)["observed_match_count"], 10);
        assert_eq!(comparison(&out)["matches"].as_array().expect("bounded matches").len(), 8);
        assert_eq!(comparison(&out)["matches_truncated"], true);
        assert!(out.limitations.iter().any(|l| l.code == "windows.catalog-membership-limit"));
        let mut supplied = tree("flat-file", &aa_core::sha256_hex(b"payload"));
        supplied.files = vec![file("payload", b"payload"); MAX_FILES + 1];
        assert!(index(&supplied, &BTreeSet::new(), &mut Output::default()).is_err());
        supplied.files = vec![file(&"p".repeat(8193), b"payload")];
        assert!(index(&supplied, &BTreeSet::new(), &mut Output::default()).is_err());
    }

    fn sample(name: &str) -> Vec<u8> {
        match name {
            "hello.exe" => include_bytes!("../tests/data/hello.exe").to_vec(),
            "hello-signed.exe" => include_bytes!("../tests/data/hello-signed.exe").to_vec(),
            "dotnet.exe" => include_bytes!("../tests/data/dotnet.exe").to_vec(),
            _ => panic!("unrecognized fixture base"),
        }
    }

    fn variant(case: &Value) -> Vec<u8> {
        let mut bytes = sample(case["base"].as_str().expect("fixture base"));
        let parts: Vec<_> = case["operation"].as_str().expect("operation").split(':').collect();
        match parts.as_slice() {
            ["copy"] => {}
            ["append", count] => bytes.extend(vec![b'Z'; count.parse().expect("append length")]),
            ["truncate", count] => bytes.truncate(count.parse().expect("truncation length")),
            ["u32", at, value] => {
                let at: usize = at.parse().expect("field offset");
                let value: u32 = value.parse().expect("field value");
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            }
            ["section-gap", count] => {
                let gap: usize = count.parse().expect("gap length");
                let pe = Pe::parse(&bytes).expect("base PE");
                let headers = pe.size_of_headers as usize;
                let sections = pe.sections.clone();
                bytes.splice(headers..headers, vec![0; gap]);
                for section in sections {
                    if section.raw_pointer != 0 {
                        let pointer = section.raw_pointer + u32::try_from(gap).expect("small gap");
                        bytes[section.header_offset + 20..section.header_offset + 24].copy_from_slice(&pointer.to_le_bytes());
                    }
                }
            }
            _ => panic!("unrecognized fixture operation"),
        }
        bytes
    }

    #[test]
    fn pe_catalog_sip_hashes_match_native_reference_including_alignment_and_rejections() {
        let reference: Value =
            serde_json::from_slice(include_bytes!("../tests/data/native-sip-hashes.ref.json")).expect("native SIP matrix");
        let cases = reference["cases"].as_array().expect("native cases");
        assert_eq!(cases.len(), 17);
        for case in cases {
            let bytes = variant(case);
            assert_eq!(aa_core::sha256_hex(&bytes), case["input_sha256"], "{}", case["case"]);
            let sha1 = Pe::parse(&bytes).map_err(|_| "unreadable PE").and_then(|pe| pe_digest::<sha1::Sha1>(&pe));
            let sha256 = Pe::parse(&bytes).map_err(|_| "unreadable PE").and_then(|pe| pe_digest::<sha2::Sha256>(&pe));
            for (algorithm, calculated) in [("sha1", sha1), ("sha256", sha256)] {
                if let Some(expected) = case[algorithm].as_str() {
                    assert_eq!(hex::encode(calculated.expect("native-accepted profile")), expected, "{} {algorithm}", case["case"]);
                } else {
                    assert!(calculated.is_err(), "native rejected {} {algorithm}", case["case"]);
                }
            }
        }
    }
}
