//! APK Signature Scheme v1: JAR signing, verified.
//!
//! Three links are checked, as Android before 7.0 does: (1) the digest of every file in the
//! archive against `META-INF/MANIFEST.MF`; (2) the manifest against the signature file (`.SF`),
//! by the whole-manifest digest or else section by section; (3) the PKCS #7 signature over the
//! `.SF` with the signer's certificate.

use std::collections::BTreeMap;

use base64::Engine;
use sha2::Digest;

use crate::crypto::{self, Hash, Outcome, Scheme};
use crate::der::{self, Tlv};
use crate::sigblock::Check;
use crate::x509::{self, Certificate};
use crate::zipraw::{self, Archive};

const MAX_MANIFEST: u64 = 64 * 1024 * 1024;
const MAX_SIGNATURE_FILE: u64 = 64 * 1024 * 1024;
const MAX_BLOCK: u64 = 4 * 1024 * 1024;
const MAX_ENTRY: u64 = 4 * 1024 * 1024 * 1024;
const MAX_LISTED: usize = 20;

/// One section of a manifest: its attributes and the exact bytes it occupies.
#[derive(Debug, Clone, PartialEq)]
pub struct Section<'a> {
    pub attributes: Vec<(String, String)>,
    pub raw: &'a [u8],
}

impl Section<'_> {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attributes.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Splits a manifest into sections: the main one first, then one per `Name:`.
pub fn parse_manifest(data: &[u8]) -> Vec<Section<'_>> {
    let mut sections = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let start = pos;
        let mut attributes: Vec<(String, String)> = Vec::new();
        let mut any_line = false;
        loop {
            // One line, without its terminator.
            let line_start = pos;
            while pos < data.len() && data[pos] != b'\n' && data[pos] != b'\r' {
                pos += 1;
            }
            let line = &data[line_start..pos];
            if pos < data.len() && data[pos] == b'\r' {
                pos += 1;
            }
            if pos < data.len() && data[pos] == b'\n' {
                pos += 1;
            }
            if line.is_empty() {
                break;
            }
            any_line = true;
            if line[0] == b' ' {
                // Continuation of the previous value.
                if let Some((_, value)) = attributes.last_mut() {
                    value.push_str(&String::from_utf8_lossy(&line[1..]));
                }
            } else if let Some(colon) = line.iter().position(|b| *b == b':') {
                let key = String::from_utf8_lossy(&line[..colon]).into_owned();
                let value = String::from_utf8_lossy(line.get(colon + 1..).unwrap_or_default());
                attributes.push((key, value.strip_prefix(' ').unwrap_or(&value).to_string()));
            }
            if pos >= data.len() {
                break;
            }
        }
        if any_line {
            sections.push(Section { attributes, raw: &data[start..pos] });
        }
        if sections.len() > zipraw::MAX_ENTRIES {
            break;
        }
    }
    sections
}

const DIGEST_PREFERENCE: [(Hash, &str); 5] =
    [(Hash::Sha512, "SHA-512"), (Hash::Sha384, "SHA-384"), (Hash::Sha256, "SHA-256"), (Hash::Sha1, "SHA1"), (Hash::Sha1, "SHA-1")];

/// The strongest digest attribute `<ALG>-Digest<suffix>` in a section.
fn best_digest(section: &Section, suffix: &str) -> Option<(Hash, Vec<u8>)> {
    for (hash, name) in DIGEST_PREFERENCE {
        if let Some(value) = section.get(&format!("{name}-Digest{suffix}")) {
            let decoded = base64::engine::general_purpose::STANDARD.decode(value.trim()).ok()?;
            return Some((hash, decoded));
        }
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub struct V1Signer {
    /// Name of the signature file, e.g. `META-INF/CERT.SF`.
    pub signature_file: String,
    pub block_file: String,
    pub certificates: Vec<Certificate>,
    /// The certificate the signature was made with.
    pub signer_certificate: Option<Certificate>,
    pub digest_algorithm: Option<String>,
    pub signature_algorithm: Option<String>,
    /// PKCS #7 signature over the signature file.
    pub signature: Check,
    /// Signature file to manifest.
    pub manifest_link: Check,
    /// Scheme ids listed in `X-Android-APK-Signed`.
    pub also_signed_with: Vec<u32>,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V1Result {
    pub signers: Vec<V1Signer>,
    /// Manifest to files.
    pub entries: Check,
    pub entries_checked: usize,
    pub digest_mismatches: Vec<String>,
    /// Files in the archive that the manifest does not list.
    pub unsigned_entries: Vec<String>,
    /// Manifest entries with no file in the archive.
    pub missing_entries: Vec<String>,
    pub manifest_digest_algorithms: Vec<String>,
}

impl V1Result {
    pub fn verified(&self) -> bool {
        !self.signers.is_empty() && self.entries.passed() && self.signers.iter().all(|s| s.signature.passed() && s.manifest_link.passed())
    }
}

struct SignerInfo<'a> {
    issuer: &'a [u8],
    serial: &'a [u8],
    digest_oid: String,
    signed_attrs: Option<Tlv<'a>>,
    signature_oid: String,
    signature: &'a [u8],
}

struct Pkcs7<'a> {
    certificates: Vec<&'a [u8]>,
    signers: Vec<SignerInfo<'a>>,
}

fn parse_pkcs7(data: &[u8]) -> Option<Pkcs7<'_>> {
    let (content_info, _) = der::read(data)?;
    let mut fields = der::items(content_info.value);
    let oid = fields.next().filter(|t| t.tag == der::OID)?;
    if der::oid_string(oid.value) != "1.2.840.113549.1.7.2" {
        return None;
    }
    let wrapper = fields.next().filter(|t| t.tag == 0xa0)?;
    let (signed_data, _) = der::read(wrapper.value)?;
    let mut certificates = Vec::new();
    let mut signers = Vec::new();
    for (index, item) in der::items(signed_data.value).enumerate() {
        match item.tag {
            // [0] IMPLICIT certificates (index 0 is the version INTEGER, never this tag).
            0xa0 if index >= 3 => certificates.extend(der::items(item.value).filter(|c| c.tag == der::SEQUENCE).take(64).map(|c| c.raw)),
            der::SET if index >= 3 => {
                for info in der::items(item.value).take(16) {
                    let mut f = der::items(info.value);
                    let _version = f.next()?;
                    let identifier = f.next()?;
                    let mut id_fields = der::items(identifier.value);
                    let (issuer, serial) = match identifier.tag {
                        der::SEQUENCE => (id_fields.next()?.raw, id_fields.next()?.value),
                        _ => (&[][..], &[][..]),
                    };
                    let digest_algorithm = f.next()?;
                    let digest_oid = der::items(digest_algorithm.value).next().map(|t| der::oid_string(t.value))?;
                    let mut next = f.next()?;
                    let signed_attrs = if next.tag == 0xa0 {
                        let attrs = next;
                        next = f.next()?;
                        Some(attrs)
                    } else {
                        None
                    };
                    let signature_oid = der::items(next.value).next().map(|t| der::oid_string(t.value))?;
                    let signature = f.next().filter(|t| t.tag == der::OCTET_STRING)?.value;
                    signers.push(SignerInfo { issuer, serial, digest_oid, signed_attrs, signature_oid, signature });
                }
            }
            _ => {}
        }
    }
    Some(Pkcs7 { certificates, signers })
}

/// The scheme named by a PKCS #7 signature algorithm, which may or may not include the hash.
fn pkcs7_scheme(signature_oid: &str, digest: Hash, key: &x509::KeyAlgorithm) -> Option<Scheme> {
    match signature_oid {
        "1.2.840.113549.1.1.1" => Some(Scheme::RsaPkcs1(digest)),
        "1.2.840.10045.2.1" => Some(Scheme::Ecdsa(digest)),
        "1.2.840.10040.4.1" => Some(Scheme::Dsa(digest)),
        other => match crypto::scheme_from_signature_oid(other) {
            // The digest algorithm field decides which hash was actually used.
            Some(Scheme::RsaPkcs1(_)) => Some(Scheme::RsaPkcs1(digest)),
            Some(Scheme::Ecdsa(_)) => Some(Scheme::Ecdsa(digest)),
            Some(Scheme::Dsa(_)) => Some(Scheme::Dsa(digest)),
            Some(other) => Some(other),
            None => match key {
                x509::KeyAlgorithm::Rsa { .. } => None,
                _ => None,
            },
        },
    }
}

fn verify_pkcs7(block: &[u8], signature_file: &[u8], signer: &mut V1Signer) {
    let Some(pkcs7) = parse_pkcs7(block) else {
        signer.signature = Check::Failed("the signature block is not a readable PKCS #7 SignedData".into());
        return;
    };
    signer.certificates = pkcs7.certificates.iter().filter_map(|c| x509::parse(c)).collect();
    let Some(info) = pkcs7.signers.first() else {
        signer.signature = Check::Failed("the signature block has no signer".into());
        return;
    };
    let certificate = signer
        .certificates
        .iter()
        .find(|c| c.issuer_raw == info.issuer && der::unsigned(&c.serial_raw) == der::unsigned(info.serial))
        .or(if signer.certificates.len() == 1 && info.issuer.is_empty() { signer.certificates.first() } else { None })
        .cloned();
    let Some(certificate) = certificate else {
        signer.signature = Check::Failed("the signer's certificate is not in the signature block".into());
        return;
    };
    let Some(digest) = Hash::from_oid(&info.digest_oid) else {
        signer.signer_certificate = Some(certificate);
        signer.signature = Check::NotChecked(format!("digest algorithm {} is not supported", info.digest_oid));
        return;
    };
    signer.digest_algorithm = Some(digest.name().to_string());
    let scheme = pkcs7_scheme(&info.signature_oid, digest, &certificate.key);
    signer.signature_algorithm = Some(match scheme {
        Some(Scheme::RsaPkcs1(h)) => format!("RSA PKCS #1 v1.5 with {}", h.name()),
        Some(Scheme::RsaPss(h)) => format!("RSASSA-PSS with {}", h.name()),
        Some(Scheme::Ecdsa(h)) => format!("ECDSA with {}", h.name()),
        Some(Scheme::Dsa(h)) => format!("DSA with {}", h.name()),
        None => format!("OID {}", info.signature_oid),
    });
    let spki = certificate.spki.clone();
    signer.signer_certificate = Some(certificate);
    let Some(scheme) = scheme else {
        signer.signature = Check::NotChecked(format!("signature algorithm {} is not supported", info.signature_oid));
        return;
    };
    // With signed attributes the signature covers them (re-tagged as a SET), and they carry
    // the digest of the signature file.
    let message: Vec<u8> = match &info.signed_attrs {
        Some(attrs) => {
            let mut message_digest = None;
            for attribute in der::items(attrs.value).take(32) {
                let mut f = der::items(attribute.value);
                if f.next().map(|t| der::oid_string(t.value)).as_deref() == Some("1.2.840.113549.1.9.4") {
                    message_digest = f.next().and_then(|set| der::items(set.value).next()).map(|t| t.value);
                }
            }
            if message_digest != Some(digest.digest(signature_file).as_slice()) {
                signer.signature = Check::Failed("the digest in the signed attributes is not the digest of the signature file".into());
                return;
            }
            let mut message = attrs.raw.to_vec();
            message[0] = der::SET;
            message
        }
        None => signature_file.to_vec(),
    };
    signer.signature = match crypto::verify(&spki, scheme, &message, info.signature) {
        Outcome::Valid => Check::Passed,
        Outcome::Invalid => Check::Failed("the PKCS #7 signature over the signature file does not verify".into()),
        Outcome::Unsupported(why) => Check::NotChecked(why),
    };
}

fn check_manifest_link(sf: &[Section], manifest_bytes: &[u8], manifest: &[Section]) -> Check {
    let Some(main) = sf.first() else { return Check::Failed("the signature file is empty".into()) };
    if let Some((hash, expected)) = best_digest(main, "-Manifest") {
        if hash.digest(manifest_bytes) == expected {
            return Check::Passed;
        }
        // Fall through: tools that rewrap the manifest leave a stale whole-file digest but valid sections.
    }
    let mut by_name: BTreeMap<&str, &Section> = BTreeMap::new();
    for section in manifest.iter().skip(1) {
        if let Some(name) = section.get("Name") {
            by_name.insert(name, section);
        }
    }
    if let (Some((hash, expected)), Some(manifest_main)) = (best_digest(main, "-Manifest-Main-Attributes"), manifest.first())
        && hash.digest(manifest_main.raw) != expected
    {
        return Check::Failed("the digest of the manifest's main attributes does not match".into());
    }
    let mut checked = 0;
    for section in sf.iter().skip(1) {
        let Some(name) = section.get("Name") else { continue };
        let Some((hash, expected)) = best_digest(section, "") else {
            return Check::Failed(format!("the signature file has no usable digest for {name}"));
        };
        let Some(target) = by_name.get(name) else {
            return Check::Failed(format!("the signature file lists {name}, the manifest does not"));
        };
        if hash.digest(target.raw) != expected {
            return Check::Failed(format!("the manifest section of {name} does not match the signature file"));
        }
        checked += 1;
    }
    if checked == 0 || checked < by_name.len() {
        return Check::Failed("the signature file does not cover the manifest".into());
    }
    Check::Passed
}

fn is_signature_related(name: &str) -> bool {
    let Some(file) = name.strip_prefix("META-INF/") else { return false };
    if file.contains('/') {
        return false;
    }
    let upper = file.to_ascii_uppercase();
    upper == "MANIFEST.MF" || upper.ends_with(".SF") || upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC") || upper.starts_with("SIG-")
}

enum AnyHasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

fn digest_entry(data: &[u8], entry: &zipraw::Entry, hash: Hash) -> Result<Vec<u8>, String> {
    let mut hasher = match hash {
        Hash::Sha1 => AnyHasher::Sha1(sha1::Sha1::new()),
        Hash::Sha256 => AnyHasher::Sha256(sha2::Sha256::new()),
        Hash::Sha384 => AnyHasher::Sha384(sha2::Sha384::new()),
        Hash::Sha512 => AnyHasher::Sha512(sha2::Sha512::new()),
        other => return Err(format!("{} digests are not accepted", other.name())),
    };
    zipraw::stream_entry(data, entry, MAX_ENTRY, |piece| match &mut hasher {
        AnyHasher::Sha1(h) => h.update(piece),
        AnyHasher::Sha256(h) => h.update(piece),
        AnyHasher::Sha384(h) => h.update(piece),
        AnyHasher::Sha512(h) => h.update(piece),
    })?;
    Ok(match hasher {
        AnyHasher::Sha1(h) => h.finalize().to_vec(),
        AnyHasher::Sha256(h) => h.finalize().to_vec(),
        AnyHasher::Sha384(h) => h.finalize().to_vec(),
        AnyHasher::Sha512(h) => h.finalize().to_vec(),
    })
}

/// Verifies the JAR signature of the archive. `None` when there is no signature file at all.
pub fn verify(data: &[u8], archive: &Archive) -> Option<V1Result> {
    let mut signature_files: Vec<&zipraw::Entry> = archive
        .entries
        .iter()
        .filter(|e| e.name.starts_with("META-INF/") && !e.name["META-INF/".len()..].contains('/') && e.name.to_ascii_uppercase().ends_with(".SF"))
        .collect();
    signature_files.sort_by(|a, b| a.name.cmp(&b.name));
    signature_files.dedup_by(|a, b| a.name == b.name);
    if signature_files.is_empty() {
        return None;
    }
    let mut result = V1Result {
        signers: Vec::new(),
        entries: Check::NotChecked("META-INF/MANIFEST.MF is missing".into()),
        entries_checked: 0,
        digest_mismatches: Vec::new(),
        unsigned_entries: Vec::new(),
        missing_entries: Vec::new(),
        manifest_digest_algorithms: Vec::new(),
    };
    let manifest_bytes = archive.entry("META-INF/MANIFEST.MF").and_then(|e| zipraw::read_entry(data, e, MAX_MANIFEST).ok());
    let manifest = manifest_bytes.as_deref().map(parse_manifest).unwrap_or_default();

    for sf_entry in signature_files.into_iter().take(16) {
        let stem = &sf_entry.name[..sf_entry.name.len() - 2];
        let block_entry = ["RSA", "DSA", "EC"].iter().find_map(|ext| {
            archive.entries.iter().rev().find(|e| e.name.len() == stem.len() + ext.len() && e.name[..stem.len()] == *stem && e.name[stem.len()..].eq_ignore_ascii_case(ext))
        });
        let mut signer = V1Signer {
            signature_file: sf_entry.name.clone(),
            block_file: block_entry.map(|e| e.name.clone()).unwrap_or_default(),
            certificates: Vec::new(),
            signer_certificate: None,
            digest_algorithm: None,
            signature_algorithm: None,
            signature: Check::NotChecked("no signature block (.RSA, .DSA or .EC) beside the signature file".into()),
            manifest_link: Check::NotChecked("the signature file or the manifest could not be read".into()),
            also_signed_with: Vec::new(),
            created_by: None,
        };
        let sf_bytes = zipraw::read_entry(data, archive.entry(&sf_entry.name).unwrap_or(sf_entry), MAX_SIGNATURE_FILE);
        match (&sf_bytes, block_entry.map(|e| zipraw::read_entry(data, e, MAX_BLOCK))) {
            (Ok(sf_bytes), Some(Ok(block))) => verify_pkcs7(&block, sf_bytes, &mut signer),
            (Err(error), _) => signer.signature = Check::NotChecked(format!("the signature file could not be read: {error}")),
            (_, Some(Err(error))) => signer.signature = Check::NotChecked(format!("the signature block could not be read: {error}")),
            (_, None) => {}
        }
        if let (Ok(sf_bytes), Some(manifest_bytes)) = (&sf_bytes, &manifest_bytes) {
            let sf = parse_manifest(sf_bytes);
            if let Some(main) = sf.first() {
                signer.created_by = main.get("Created-By").map(str::to_string);
                signer.also_signed_with =
                    main.get("X-Android-APK-Signed").map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect()).unwrap_or_default();
            }
            signer.manifest_link = check_manifest_link(&sf, manifest_bytes, &manifest);
        }
        result.signers.push(signer);
    }

    if manifest_bytes.is_some() {
        let mut by_name: BTreeMap<&str, &Section> = BTreeMap::new();
        for section in manifest.iter().skip(1) {
            if let Some(name) = section.get("Name") {
                by_name.insert(name, section);
            }
        }
        let mut algorithms: Vec<String> = Vec::new();
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        let mut unreadable = Vec::new();
        for entry in &archive.entries {
            if entry.name.ends_with('/') || is_signature_related(&entry.name) || !seen.insert(entry.name.as_str()) {
                continue;
            }
            // With duplicate names Android reads the last record.
            let entry = archive.entry(&entry.name).unwrap_or(entry);
            let Some(section) = by_name.get(entry.name.as_str()) else {
                result.unsigned_entries.push(entry.name.clone());
                continue;
            };
            let Some((hash, expected)) = best_digest(section, "") else {
                result.unsigned_entries.push(entry.name.clone());
                continue;
            };
            if !algorithms.iter().any(|a| a == hash.name()) {
                algorithms.push(hash.name().to_string());
            }
            match digest_entry(data, entry, hash) {
                Ok(actual) if actual == expected => result.entries_checked += 1,
                Ok(_) => result.digest_mismatches.push(entry.name.clone()),
                Err(error) => unreadable.push(format!("{}: {error}", entry.name)),
            }
        }
        for name in by_name.keys() {
            if !seen.contains(name) {
                result.missing_entries.push((*name).to_string());
            }
        }
        algorithms.sort();
        result.manifest_digest_algorithms = algorithms;
        let listed = |names: &[String]| names.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
        result.entries = if !result.digest_mismatches.is_empty() {
            Check::Failed(format!("{} files do not match their digest in the manifest ({})", result.digest_mismatches.len(), listed(&result.digest_mismatches)))
        } else if !result.unsigned_entries.is_empty() {
            Check::Failed(format!("{} files are not listed in the manifest ({})", result.unsigned_entries.len(), listed(&result.unsigned_entries)))
        } else if !result.missing_entries.is_empty() {
            Check::Failed(format!("{} files listed in the manifest are not in the archive ({})", result.missing_entries.len(), listed(&result.missing_entries)))
        } else if !unreadable.is_empty() {
            Check::NotChecked(format!("{} files could not be read ({})", unreadable.len(), listed(&unreadable)))
        } else {
            Check::Passed
        };
        result.digest_mismatches.truncate(MAX_LISTED);
        result.unsigned_entries.truncate(MAX_LISTED);
        result.missing_entries.truncate(MAX_LISTED);
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sections_and_continuations() {
        let text = b"Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\nName: a/very/long/name/that/wraps/across/lines/in/the/manifest/file/\r\n because.txt\r\nSHA-256-Digest: AAAA\r\n\r\nName: b\nSHA1-Digest: BBBB\n\n";
        let sections = parse_manifest(text);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].get("Created-By"), Some("test"));
        assert_eq!(sections[1].get("Name"), Some("a/very/long/name/that/wraps/across/lines/in/the/manifest/file/because.txt"));
        assert!(sections[1].raw.starts_with(b"Name: a/very") && sections[1].raw.ends_with(b"AAAA\r\n\r\n"));
        assert_eq!(sections[2].get("name"), Some("b"));
        assert_eq!(best_digest(&sections[2], "").map(|(h, _)| h), Some(Hash::Sha1));
        // The raw pieces cover the file exactly.
        let total: usize = sections.iter().map(|s| s.raw.len()).sum();
        assert_eq!(total, text.len());
    }

    #[test]
    fn garbage_does_not_panic() {
        assert!(parse_manifest(b"").is_empty());
        let _ = parse_manifest(b"\n\n\n \n:\n: \nNoColon\n continuation");
        let _ = parse_manifest(&[0xff; 100]);
        assert!(parse_pkcs7(&[]).is_none());
        assert!(parse_pkcs7(&[0x30, 0x80, 0x06, 0x09]).is_none());
        let zip = zipraw::tests::build_zip(b"", &[("META-INF/X.SF", b"junk"), ("META-INF/X.RSA", &[0x30, 0x03, 1, 2, 3]), ("a", b"1")]);
        let archive = zipraw::parse(&zip).expect("zip");
        let result = verify(&zip, &archive).expect("v1");
        assert!(!result.verified());
        assert!(result.signers[0].signature.failed());
    }

    #[test]
    fn unsigned_archive_has_no_v1_result() {
        let zip = zipraw::tests::build_zip(b"", &[("a", b"1")]);
        assert!(verify(&zip, &zipraw::parse(&zip).expect("zip")).is_none());
    }

    #[test]
    fn signature_related_names() {
        assert!(is_signature_related("META-INF/MANIFEST.MF"));
        assert!(is_signature_related("META-INF/cert.rsa"));
        assert!(!is_signature_related("META-INF/services/x.SF"));
        assert!(!is_signature_related("res/a.SF"));
    }
}
