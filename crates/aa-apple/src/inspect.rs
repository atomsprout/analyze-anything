//! The file pass: what one file says on its own. A Mach-O's slices, encryption and code
//! signature (parsed and checked against the file's own bytes), a disk image's layout, and a
//! xar archive's signature. The results are facts; the tree pass turns them into findings
//! once it knows which bundle each file belongs to.

use serde_json::{Map, Value, json};

use crate::certs::{self, Hash, Verdict};
use crate::codesign::{self, SLOT_ENTITLEMENTS, SLOT_ENTITLEMENTS_DER, SLOT_INFO_PLIST, SLOT_REQUIREMENTS};
use crate::disk::udif;
use crate::util::slice;
use crate::{macho, pkg};

/// Slices of a universal binary examined in full.
const MAX_SLICES: usize = 8;
/// Linked libraries listed per slice.
const MAX_LIBRARIES: usize = 300;

fn hash_name(hash: Hash, truncated: bool) -> &'static str {
    if truncated { "sha256-truncated" } else { hash.name() }
}

/// Classifies a signature from its signer's certificate. The labels are stable ids.
pub fn signing_type(adhoc: bool, linker_signed: bool, has_cms: bool, leaf: Option<&certs::CertInfo>) -> &'static str {
    if linker_signed {
        return "adhoc-linker";
    }
    if adhoc || !has_cms {
        return "adhoc";
    }
    let Some(name) = leaf.and_then(|leaf| leaf.common_name.as_deref()) else { return "other" };
    let starts = |prefixes: &[&str]| prefixes.iter().any(|prefix| name.starts_with(prefix));
    if starts(&["Developer ID Application:"]) {
        "developer-id"
    } else if starts(&["Developer ID Installer:"]) {
        "developer-id-installer"
    } else if starts(&["Apple Development:", "iPhone Developer:", "Mac Developer:"]) {
        "development"
    } else if starts(&["Apple Distribution:", "iPhone Distribution:", "3rd Party Mac Developer Application:"]) {
        "distribution"
    } else if starts(&["3rd Party Mac Developer Installer:"]) {
        "distribution-installer"
    } else if name == "Apple Mac OS Application Signing" {
        "mac-app-store"
    } else if name == "Apple iPhone OS Application Signing" {
        "ios-app-store"
    } else if name == "Software Signing" {
        "apple-system"
    } else {
        "other"
    }
}

fn signature_fact(code: &[u8], parsed: &macho::MachO, offset: u32, size: u32) -> Result<Value, String> {
    let bytes = slice(code, offset as usize, size as usize).ok_or("the signature lies outside the file")?;
    let signature = codesign::parse(bytes)?;
    let best = signature.best();
    let encrypted = parsed.encryption.filter(|e| e.id != 0).map(|e| (e.offset as u64, e.size as u64));
    let embedded_plist = parsed.info_plist.as_ref().and_then(|section| slice(code, section.offset as usize, section.size as usize));

    let mut directories = Vec::new();
    for directory in &signature.directories {
        let pages = signature.check_pages(directory, code, encrypted);
        let mut special = Map::new();
        for slot in 1..=directory.special_slots.min(16) {
            if let Some(hash) = signature.special_hash(directory, slot) {
                special.insert(slot.to_string(), json!(hex::encode(hash)));
            }
        }
        let mut slots = Map::new();
        let checks = [
            ("requirements", SLOT_REQUIREMENTS, signature.blob(SLOT_REQUIREMENTS)),
            ("entitlements", SLOT_ENTITLEMENTS, signature.blob(SLOT_ENTITLEMENTS)),
            ("entitlements_der", SLOT_ENTITLEMENTS_DER, signature.blob(SLOT_ENTITLEMENTS_DER)),
        ];
        for (name, slot, data) in checks {
            if let Some(check) = signature.check_special(directory, slot, data) {
                slots.insert(name.to_string(), json!(check.label()));
            }
        }
        if let Some(plist) = embedded_plist
            && let Some(check) = signature.check_special(directory, SLOT_INFO_PLIST, Some(plist))
        {
            slots.insert("embedded_info_plist".to_string(), json!(check.label()));
        }
        directories.push(json!({
            "slot": directory.slot,
            "version": format!("{:#x}", directory.version),
            "hash_type": hash_name(directory.hash, directory.truncated_hash),
            "hash_size": directory.hash_size,
            "cdhash": hex::encode(&directory.cdhash),
            "code_slots": directory.code_slots,
            "code_limit": directory.code_limit,
            "page_size": directory.page_size,
            "special": special,
            "slots": slots,
            "pages": {
                "pages": pages.pages,
                "checked": pages.checked,
                "mismatched": pages.mismatched,
                "skipped_encrypted": pages.skipped,
                "first_mismatches": pages.first_mismatches,
                "error": pages.error,
            },
        }));
    }

    let mut fact = json!({
        "offset": offset,
        "size": size,
        "identifier": best.identifier,
        "team_id": best.team_id,
        "flags": best.flags,
        "flag_names": codesign::flag_names(best.flags),
        "adhoc": best.flags & codesign::FLAG_ADHOC != 0,
        "linker_signed": best.flags & codesign::FLAG_LINKER_SIGNED != 0,
        "hardened_runtime": best.flags & codesign::FLAG_RUNTIME != 0,
        "runtime_version": best.runtime_version.map(|v| format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)),
        "exec_segment_flags": best.exec_segment_flags,
        "hash_type": hash_name(best.hash, best.truncated_hash),
        "cdhash": hex::encode(&best.cdhash),
        "directories": directories,
        "requirements": signature.requirements().map(|(count, size)| json!({ "count": count, "size": size })),
    });

    if let Some(xml) = signature.entitlements_xml() {
        match plist::Value::from_reader(std::io::Cursor::new(xml)) {
            Ok(value) if value.as_dictionary().is_some() => fact["entitlements"] = codesign::plist_to_json(&value),
            Ok(_) => fact["entitlements_error"] = json!("the entitlements are not a dictionary"),
            Err(error) => fact["entitlements_error"] = json!(error.to_string()),
        }
    }
    if let Some(der) = signature.entitlements_der() {
        match codesign::der_entitlements(der) {
            Some(decoded) => {
                // Both forms must grant the same things; the kernel reads one, older tools the other.
                if let Some(xml) = fact.get("entitlements") {
                    let keys = |value: &Value| value.as_object().map(|map| map.keys().cloned().collect::<Vec<_>>()).unwrap_or_default();
                    fact["entitlements_der_same_keys"] = json!(keys(xml) == keys(&decoded));
                } else {
                    fact["entitlements"] = decoded.clone();
                }
                fact["entitlements_der"] = decoded;
            }
            None => fact["entitlements_der_error"] = json!("the DER entitlements could not be decoded"),
        }
    }

    let mut leaf = None;
    match signature.check_cms() {
        None => {}
        Some(Err(error)) => fact["cms_error"] = json!(error),
        Some(Ok(check)) => {
            let mut cms = check.json();
            // Alternate directories are bound to the signature through the signed list of hashes.
            if let Some(listed) = &check.cdhashes {
                cms["cdhashes_bound"] = json!(signature.directories.iter().all(|d| listed.contains(&d.cdhash)));
            }
            if let (Some(leaf), Some((_, time))) = (check.leaf(), &check.signing_time) {
                cms["signed_within_validity"] = json!(leaf.validity.0 <= *time && *time <= leaf.validity.1);
            }
            cms["verified"] = json!(check.digest_matches == Some(true) && check.signature == Verdict::Valid);
            cms["anchored"] = json!(check.chain.as_ref().is_some_and(certs::Chain::anchored));
            fact["cms"] = cms;
            leaf = check.leaf().cloned();
        }
    }
    let has_cms = signature.cms().is_some();
    fact["signing_type"] =
        json!(signing_type(best.flags & codesign::FLAG_ADHOC != 0, best.flags & codesign::FLAG_LINKER_SIGNED != 0, has_cms, leaf.as_ref()));
    Ok(fact)
}

/// The `apple.macho` fact of a file, or `None` when it is not a Mach-O.
pub fn macho_fact(bytes: &[u8]) -> Option<Value> {
    let slices = macho::slices(bytes)?;
    let mut out = Vec::new();
    for part in slices.iter().take(MAX_SLICES) {
        let code = slice(bytes, part.offset, part.size)?;
        let mut fact = json!({ "offset": part.offset, "size": part.size });
        match macho::parse(code) {
            Err(error) => fact["error"] = json!(error),
            Ok(parsed) => {
                fact["arch"] = json!(parsed.arch());
                fact["kind"] = json!(parsed.file_kind());
                if let Some((platform, minimum, sdk)) = &parsed.build {
                    fact["platform"] = json!(platform);
                    fact["min_os"] = json!(minimum);
                    fact["sdk"] = json!(sdk);
                }
                fact["libraries"] = json!(parsed.libraries.iter().take(MAX_LIBRARIES).collect::<Vec<_>>());
                if parsed.libraries.len() > MAX_LIBRARIES {
                    fact["libraries_truncated"] = json!(true);
                }
                fact["embedded_info_plist"] = json!(parsed.info_plist.is_some());
                if let Some(encryption) = parsed.encryption {
                    fact["encryption"] = json!({
                        "command_offset": part.offset + encryption.command_offset,
                        "offset": encryption.offset,
                        "size": encryption.size,
                        "id": encryption.id,
                    });
                }
                match parsed.code_signature {
                    None => fact["signature"] = Value::Null,
                    Some((offset, size, command)) => {
                        fact["signature_command_offset"] = json!(part.offset + command);
                        match signature_fact(code, &parsed, offset, size) {
                            Ok(signature) => fact["signature"] = signature,
                            Err(error) => fact["signature_error"] = json!(error),
                        }
                    }
                }
            }
        }
        out.push(fact);
    }
    Some(json!({ "slices": out, "slices_total": slices.len(), "truncated": slices.len() > MAX_SLICES }))
}

/// The `apple.dmg` fact: the layout of a UDIF image, without decompressing anything.
pub fn dmg_fact(bytes: &[u8]) -> Option<Value> {
    if let Some(scheme) = udif::encryption(bytes) {
        return Some(json!({ "encrypted": true, "encryption_version": if scheme == udif::Encryption::V2 { 2 } else { 1 } }));
    }
    let koly = udif::koly(bytes)?;
    let mut fact = json!({
        "encrypted": false,
        "udif_version": koly.version,
        "flags": koly.flags,
        "sectors": koly.sector_count,
        "trailer_offset": koly.offset,
    });
    match udif::tables(bytes, &koly) {
        Ok(tables) => {
            let mut methods = std::collections::BTreeSet::new();
            let partitions: Vec<Value> = tables
                .iter()
                .map(|table| {
                    let mut chunks = Map::new();
                    for (kind, count) in table.chunk_kinds() {
                        let name = udif::chunk_name(kind).map(str::to_string).unwrap_or_else(|| format!("{kind:#x}"));
                        if !matches!(name.as_str(), "zero" | "raw") {
                            methods.insert(name.clone());
                        }
                        *chunks.entry(name).or_insert(json!(0)) = json!(chunks.get(&name).and_then(Value::as_u64).unwrap_or(0) + count);
                    }
                    json!({ "name": table.name, "first_sector": table.first_sector, "sectors": table.sectors, "chunks": chunks })
                })
                .collect();
            fact["partitions"] = json!(partitions);
            fact["compression"] = json!(methods);
        }
        Err(error) => fact["error"] = json!(error),
    }
    Some(fact)
}

/// The `apple.xar` fact: the archive's checksum and signature, checked.
pub fn xar_fact(bytes: &[u8]) -> Option<Value> {
    let archive = pkg::xar(bytes).ok()?;
    let mut fact = json!({
        "version": archive.version,
        "files": archive.files.len(),
        "is_package": archive.files.iter().any(|f| matches!(f.path.rsplit('/').next(), Some("PackageInfo" | "Distribution"))),
    });
    // The checksum covers the table of contents as stored; the signature covers the checksum.
    let mut checksum_value: Option<(Hash, Vec<u8>)> = None;
    if let Some((style, offset, size)) = &archive.checksum {
        let hash = match style.as_str() {
            "sha1" => Some(Hash::Sha1),
            "sha256" => Some(Hash::Sha256),
            "sha512" => Some(Hash::Sha512),
            _ => None,
        };
        let stored = archive.heap_slice(bytes, *offset, *size);
        let toc = slice(bytes, archive.toc_range.0, archive.toc_range.1);
        fact["toc_checksum"] = match (hash, stored, toc) {
            (Some(hash), Some(stored), Some(toc)) => {
                let matches = hash.digest(toc) == stored;
                if matches {
                    checksum_value = Some((hash, stored.to_vec()));
                }
                json!({ "algorithm": style, "matches": matches })
            }
            _ => json!({ "algorithm": style, "matches": Value::Null }),
        };
    }
    let mut signatures = Vec::new();
    for signature in &archive.signatures {
        let certificates = certs::parse_certificates(&signature.certificates);
        let chain = certs::chain(&certificates, 0);
        let mut entry = json!({
            "style": signature.style,
            "certificates_listed": signature.certificates.len(),
            "chain": chain.as_ref().map(certs::Chain::json),
            "anchored": chain.as_ref().is_some_and(certs::Chain::anchored),
        });
        let stored = archive.heap_slice(bytes, signature.offset, signature.size);
        let verdict = match (signature.style.as_str(), certificates.first(), stored, &checksum_value) {
            ("RSA", Some(leaf), Some(stored), Some((hash, digest))) => {
                use rsa::pkcs1::DecodeRsaPublicKey;
                // An RSA signature directly over the checksum, which already is a digest.
                match rsa::RsaPublicKey::from_pkcs1_der(leaf.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes()) {
                    Ok(key) => {
                        let scheme = match hash {
                            Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                            Hash::Sha256 => rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                            Hash::Sha384 => rsa::Pkcs1v15Sign::new::<sha2::Sha384>(),
                            Hash::Sha512 => rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        };
                        if key.verify(scheme, digest, stored).is_ok() { Verdict::Valid } else { Verdict::Invalid }
                    }
                    Err(_) => Verdict::Unchecked("the signer's key is not an RSA key".into()),
                }
            }
            ("CMS", _, Some(stored), Some((_, digest))) => match certs::Signed::parse(stored).and_then(|signed| signed.check(Some(digest)))
            {
                Ok(check) => {
                    entry["cms"] = check.json();
                    if check.digest_matches == Some(true) { check.signature.clone() } else { Verdict::Invalid }
                }
                Err(error) => Verdict::Unchecked(error),
            },
            (_, _, None, _) => Verdict::Unchecked("the signature lies outside the file".into()),
            (_, _, _, None) => {
                Verdict::Unchecked("the table-of-contents checksum did not verify, so there is nothing to check against".into())
            }
            (style, _, _, _) => Verdict::Unchecked(format!("signature style {style} is not supported")),
        };
        entry["signature"] = json!(verdict.label());
        entry["signing_type"] = json!(signing_type(false, false, true, chain.as_ref().and_then(|c| c.certificates.first())));
        signatures.push(entry);
    }
    fact["signatures"] = json!(signatures);
    Some(fact)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::codesign::tests::sign;
    use crate::macho::tests::build;

    /// A Mach-O whose signature covers everything before it.
    pub fn signed_macho(code: &[u8], identifier: &str, entitlements: &[u8], flags: u32, crypt_id: u32) -> Vec<u8> {
        // The signature's size is needed before the header it covers can be hashed.
        let placeholder = sign(&[], identifier, entitlements, flags);
        let pages = (144 + code.len()).div_ceil(4096);
        let size = placeholder.len() + pages * 32;
        let unsigned = build(code, &vec![0u8; size], crypt_id);
        let covered = &unsigned[..144 + code.len()];
        let signature = sign(covered, identifier, entitlements, flags);
        assert_eq!(signature.len(), size);
        let mut out = covered.to_vec();
        out.extend(signature);
        out
    }

    #[test]
    fn macho_fact_reports_signature_and_integrity() {
        let entitlements = b"<plist><dict><key>get-task-allow</key><true/></dict></plist>";
        let file = signed_macho(&[0x1f; 9000], "com.example.tool", entitlements, codesign::FLAG_ADHOC, 0);
        let fact = macho_fact(&file).expect("mach-o");
        let slice = &fact["slices"][0];
        assert_eq!(slice["arch"], "arm64");
        let signature = &slice["signature"];
        assert_eq!(signature["identifier"], "com.example.tool");
        assert_eq!(signature["team_id"], "TEAM");
        assert_eq!(signature["signing_type"], "adhoc");
        assert_eq!(signature["entitlements"]["get-task-allow"], true);
        assert_eq!(signature["directories"][0]["pages"]["mismatched"], 0);
        assert_eq!(signature["directories"][0]["pages"]["checked"], 3);
        assert_eq!(signature["directories"][0]["slots"]["entitlements"], "match");

        let mut tampered = file.clone();
        tampered[200] ^= 0xff;
        let fact = macho_fact(&tampered).expect("mach-o");
        assert_eq!(fact["slices"][0]["signature"]["directories"][0]["pages"]["mismatched"], 1);

        // Encrypted: the pages holding ciphertext are skipped, not reported as modified.
        let encrypted = signed_macho(&[0x1f; 9000], "com.example.tool", entitlements, 0, 1);
        let fact = macho_fact(&encrypted).expect("mach-o");
        assert_eq!(fact["slices"][0]["encryption"]["id"], 1);
        let pages = &fact["slices"][0]["signature"]["directories"][0]["pages"];
        assert_eq!(
            (pages["checked"].as_u64(), pages["skipped_encrypted"].as_u64(), pages["mismatched"].as_u64()),
            (Some(0), Some(3), Some(0))
        );

        for cut in (0..file.len()).step_by(7) {
            let _ = macho_fact(&file[..cut]);
        }
        assert!(macho_fact(b"not a mach-o").is_none());
    }

    #[test]
    fn signing_types_from_common_names() {
        let leaf = |name: &str| certs::CertInfo {
            subject: String::new(),
            common_name: Some(name.to_string()),
            organizational_unit: None,
            organization: None,
            issuer: String::new(),
            issuer_common_name: None,
            serial: String::new(),
            not_before: String::new(),
            not_after: String::new(),
            validity: (0, 0),
            sha256: String::new(),
            is_ca: None,
            self_issued: false,
            apple_extensions: Vec::new(),
            key: String::new(),
        };
        assert_eq!(signing_type(false, false, true, Some(&leaf("Developer ID Application: Example (ABCDE12345)"))), "developer-id");
        assert_eq!(signing_type(false, false, true, Some(&leaf("Apple Development: Jo (X)"))), "development");
        assert_eq!(signing_type(false, false, true, Some(&leaf("iPhone Distribution: Example"))), "distribution");
        assert_eq!(signing_type(false, false, true, Some(&leaf("Apple iPhone OS Application Signing"))), "ios-app-store");
        assert_eq!(signing_type(false, false, true, Some(&leaf("Someone Else"))), "other");
        assert_eq!(signing_type(true, false, true, None), "adhoc");
        assert_eq!(signing_type(true, true, false, None), "adhoc-linker");
        assert_eq!(signing_type(false, false, false, None), "adhoc");
    }
}
