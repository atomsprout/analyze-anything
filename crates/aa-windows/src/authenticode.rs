//! Authenticode: the PKCS#7 signature embedded in a PE file's certificate table, or kept in a
//! stream of an MSI package.
//!
//! What is checked here, offline, for every signature (primary and nested):
//!
//! 1. **File digest** — the Authenticode hash of the PE file is recomputed and compared with the
//!    digest inside the signed `SpcIndirectDataContent`. A mismatch means the file changed after
//!    it was signed.
//! 2. **Content digest** — the `messageDigest` signed attribute equals the hash of the signed
//!    content.
//! 3. **Signature** — the signer's RSA (PKCS#1 v1.5) or ECDSA (P-256 / P-384) signature over the
//!    signed attributes verifies with the public key of the signer's embedded certificate.
//! 4. **Chain** — each embedded certificate from the signer upwards is signed by the next one.
//! 5. **Timestamp** — an RFC 3161 token or legacy countersignature covers the signature value,
//!    and the timestamp authority's own signature verifies.
//!
//! The same checks are made for the signature of an MSI package (`analyze_blob`, used by
//! `msisig`), where only the way the file digest is computed differs.
//!
//! What is not checked: whether the root is trusted by Windows, revocation, certificate
//! policies, extended key usage rules, and whether a certificate has expired today.

use md5::Md5;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::der::{self, Reader, TAG_INTEGER, TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, Tlv};
use crate::pe::{Pe, u16_at, u32_at};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
const OID_SIGNING_TIME: &str = "1.2.840.113549.1.9.5";
const OID_COUNTERSIGNATURE: &str = "1.2.840.113549.1.9.6";
const OID_SPC_INDIRECT_DATA: &str = "1.3.6.1.4.1.311.2.1.4";
const OID_SPC_SP_OPUS_INFO: &str = "1.3.6.1.4.1.311.2.1.12";
const OID_NESTED_SIGNATURE: &str = "1.3.6.1.4.1.311.2.4.1";
const OID_RFC3161_TIMESTAMP: &str = "1.3.6.1.4.1.311.3.3.1";
const OID_TST_INFO: &str = "1.2.840.113549.1.9.16.1.4";
const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC_KEY: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";

/// Nested signatures followed before giving up.
const MAX_NESTING: u32 = 4;
/// Signatures reported for one file.
const MAX_SIGNATURES: usize = 16;
/// Certificates read from one SignedData.
const MAX_CERTIFICATES: usize = 64;

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Passed,
    Failed,
    /// The check could not be made; the text says why.
    NotChecked(String),
}

impl Check {
    pub fn passed(&self) -> bool {
        *self == Check::Passed
    }

    pub fn failed(&self) -> bool {
        *self == Check::Failed
    }

    pub fn json(&self) -> Value {
        match self {
            Check::Passed => json!("passed"),
            Check::Failed => json!("failed"),
            Check::NotChecked(why) => json!({ "not_checked": why }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(oid: &str) -> Option<Hash> {
        Some(match oid {
            "1.2.840.113549.2.5" => Hash::Md5,
            "1.3.14.3.2.26" => Hash::Sha1,
            "2.16.840.1.101.3.4.2.1" => Hash::Sha256,
            "2.16.840.1.101.3.4.2.2" => Hash::Sha384,
            "2.16.840.1.101.3.4.2.3" => Hash::Sha512,
            _ => return None,
        })
    }

    /// The hash a certificate signature algorithm implies.
    fn from_signature_oid(oid: &str) -> Option<Hash> {
        Some(match oid {
            "1.2.840.113549.1.1.4" => Hash::Md5,
            "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" | "1.2.840.10045.4.1" => Hash::Sha1,
            "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => Hash::Sha256,
            "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Hash::Sha384,
            "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Hash::Sha512,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Hash::Md5 => "MD5",
            Hash::Sha1 => "SHA-1",
            Hash::Sha256 => "SHA-256",
            Hash::Sha384 => "SHA-384",
            Hash::Sha512 => "SHA-512",
        }
    }

    /// True for algorithms with practical collision attacks.
    pub fn weak(self) -> bool {
        matches!(self, Hash::Md5 | Hash::Sha1)
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Md5 => Md5::digest(data).to_vec(),
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    /// A running hash, for data that is not in one piece.
    pub fn hasher(self) -> Hasher {
        match self {
            Hash::Md5 => Hasher::Md5(Md5::new()),
            Hash::Sha1 => Hasher::Sha1(Sha1::new()),
            Hash::Sha256 => Hasher::Sha256(Sha256::new()),
            Hash::Sha384 => Hasher::Sha384(Sha384::new()),
            Hash::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }

    fn pe_digest(self, pe: &Pe) -> Option<Vec<u8>> {
        match self {
            Hash::Md5 => pe.authenticode_digest::<Md5>(),
            Hash::Sha1 => pe.authenticode_digest::<Sha1>(),
            Hash::Sha256 => pe.authenticode_digest::<Sha256>(),
            Hash::Sha384 => pe.authenticode_digest::<Sha384>(),
            Hash::Sha512 => pe.authenticode_digest::<Sha512>(),
        }
    }

    /// The DER `DigestInfo` header PKCS#1 v1.5 puts before the hash.
    fn pkcs1_prefix(self) -> &'static [u8] {
        match self {
            Hash::Md5 => &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10],
            Hash::Sha1 => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14],
            Hash::Sha256 => {
                &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
            }
            Hash::Sha384 => {
                &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
            }
            Hash::Sha512 => {
                &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
            }
        }
    }
}

/// A hash being computed with one of the algorithms of [`Hash`].
pub enum Hasher {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Md5(h) => h.update(data),
            Hasher::Sha1(h) => h.update(data),
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha384(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Hasher::Md5(h) => h.finalize().to_vec(),
            Hasher::Sha1(h) => h.finalize().to_vec(),
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha384(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}

/// Computes the digest of the signed file with the algorithm a signature names, or says why
/// that cannot be done. The second argument is the digest inside the signature, for formats
/// whose digest can be computed in more than one way.
pub type FileDigest<'f> = dyn Fn(Hash, &[u8]) -> Result<Vec<u8>, String> + 'f;

/// A public key this module can verify with.
#[derive(Debug, Clone)]
enum Key<'a> {
    Rsa { modulus: &'a [u8], exponent: &'a [u8] },
    P256(&'a [u8]),
    P384(&'a [u8]),
    Other(String),
}

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub subject: String,
    pub issuer: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub serial: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub key_description: String,
    pub signature_algorithm: String,
    pub sha1: String,
    pub sha256: String,
    raw_subject: &'a [u8],
    raw_issuer: &'a [u8],
    raw_serial: &'a [u8],
    tbs: &'a [u8],
    signature_oid: String,
    signature: &'a [u8],
    key: Key<'a>,
    subject_key_id: Option<Vec<u8>>,
}

impl Certificate<'_> {
    pub fn self_issued(&self) -> bool {
        self.raw_subject == self.raw_issuer
    }

    /// The name to show for this certificate: the common name, else the whole subject.
    pub fn display_name(&self) -> &str {
        self.common_name.as_deref().unwrap_or(&self.subject)
    }

    pub fn json(&self) -> Value {
        json!({
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "organization": self.organization,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "key": self.key_description,
            "signature_algorithm": self.signature_algorithm,
            "sha1": self.sha1,
            "sha256": self.sha256,
        })
    }
}

/// A timestamp over a signature.
#[derive(Debug, Clone)]
pub struct Timestamp {
    /// `rfc3161` or `countersignature`.
    pub kind: &'static str,
    pub time: Option<String>,
    pub authority: Option<Value>,
    pub authority_name: Option<String>,
    /// The timestamp covers this signature's value.
    pub covers_signature: Check,
    /// The token's own content digest and signature.
    pub content_digest: Check,
    pub signature: Check,
    pub chain: Vec<Value>,
    pub chain_check: Check,
}

impl Timestamp {
    pub fn verified(&self) -> bool {
        self.covers_signature.passed() && self.content_digest.passed() && self.signature.passed()
    }

    fn json(&self) -> Value {
        json!({
            "kind": self.kind,
            "time": self.time,
            "authority": self.authority,
            "covers_signature": self.covers_signature.json(),
            "content_digest": self.content_digest.json(),
            "signature": self.signature.json(),
            "issuers": self.chain.iter().skip(1).map(|c| c.get("subject").cloned().unwrap_or_default()).collect::<Vec<_>>(),
            "chain_check": self.chain_check.json(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Signature {
    /// True for a signature found inside another one's unsigned attributes.
    pub nested: bool,
    /// File offset of the PKCS#7 blob this signature (or its outermost parent) lives in.
    pub offset: usize,
    pub length: usize,
    pub digest_algorithm: Option<Hash>,
    pub digest_algorithm_name: String,
    /// The file digest the signer signed, hex.
    pub signed_digest: Option<String>,
    /// The file digest computed now, hex.
    pub computed_digest: Option<String>,
    pub file_digest: Check,
    pub content_digest: Check,
    pub signature: Check,
    pub signer: Option<Value>,
    pub signer_name: Option<String>,
    pub signer_subject: Option<String>,
    pub signer_self_issued: bool,
    pub signer_validity: Option<(String, String)>,
    /// Signer first, then each issuer found among the embedded certificates.
    pub chain: Vec<Value>,
    pub chain_check: Check,
    /// The chain ends in a self-issued certificate that is embedded in the signature.
    pub chain_reaches_root: bool,
    pub program_name: Option<String>,
    pub more_info_url: Option<String>,
    /// The signer's own claim, not a trusted time.
    pub signing_time: Option<String>,
    pub timestamps: Vec<Timestamp>,
    pub certificates: usize,
}

impl Signature {
    /// The time of the first verified timestamp.
    pub fn trusted_time(&self) -> Option<&str> {
        self.timestamps.iter().find(|t| t.verified()).and_then(|t| t.time.as_deref())
    }

    /// Whether the signer's certificate was within its validity period at the timestamp.
    /// `None` without a verified timestamp or validity dates.
    pub fn valid_at_timestamp(&self) -> Option<bool> {
        let time = self.trusted_time()?;
        let (not_before, not_after) = self.signer_validity.as_ref()?;
        Some(not_before.as_str() <= time && time <= not_after.as_str())
    }

    pub fn json(&self) -> Value {
        json!({
            "nested": self.nested,
            "digest_algorithm": self.digest_algorithm_name,
            "signed_digest": self.signed_digest,
            "computed_digest": self.computed_digest,
            "checks": {
                "file_digest": self.file_digest.json(),
                "content_digest": self.content_digest.json(),
                "signature": self.signature.json(),
                "chain": self.chain_check.json(),
            },
            "signer": self.signer,
            // The certificates above the signer, nearest first.
            "issuers": self.chain.iter().skip(1).collect::<Vec<_>>(),
            "chain_reaches_embedded_root": self.chain_reaches_root,
            "program_name": self.program_name,
            "more_info_url": self.more_info_url,
            "signing_time_claimed": self.signing_time,
            "timestamps": self.timestamps.iter().map(Timestamp::json).collect::<Vec<_>>(),
            "valid_at_timestamp": self.valid_at_timestamp(),
            "certificates_embedded": self.certificates,
        })
    }
}

/// Everything read from a PE file's certificate table.
#[derive(Debug, Clone, Default)]
pub struct Authenticode {
    /// `(file offset, size)` of the certificate table.
    pub table: Option<(usize, usize)>,
    pub signatures: Vec<Signature>,
    /// Entries that could not be parsed, with the reason.
    pub errors: Vec<String>,
    /// Bytes inside the certificate table that belong to no signature: `(offset, length)`.
    pub extra_in_table: Vec<(usize, usize)>,
    /// Bytes after the certificate table: `(offset, length)`.
    pub after_table: Option<(usize, usize)>,
}

impl Authenticode {
    pub fn json(&self) -> Value {
        json!({
            "table_offset": self.table.map(|t| t.0),
            "table_size": self.table.map(|t| t.1),
            "signatures": self.signatures.iter().map(Signature::json).collect::<Vec<_>>(),
            "errors": self.errors,
            "extra_bytes_in_table": self.extra_in_table.iter().map(|(o, l)| json!({ "offset": o, "length": l })).collect::<Vec<_>>(),
            "bytes_after_table": self.after_table.map(|(o, l)| json!({ "offset": o, "length": l })),
        })
    }
}

/// Reads and checks the embedded signatures of `pe`. `None` when the file has no certificate table.
pub fn analyze(pe: &Pe) -> Option<Authenticode> {
    let (dir_offset, dir_size) = pe.directory(crate::pe::DIR_SECURITY)?;
    let mut out = Authenticode::default();
    let Some((table, size)) = pe.certificate_table() else {
        out.errors.push(format!("the certificate table ({dir_size} bytes at offset {dir_offset}) lies outside the file"));
        return Some(out);
    };
    out.table = Some((table, size));
    let end = table + size;
    if end < pe.data.len() {
        out.after_table = Some((end, pe.data.len() - end));
    }
    let digest =
        |hash: Hash, _: &[u8]| hash.pe_digest(pe).ok_or_else(|| "the PE headers do not allow the file digest to be computed".to_string());
    let mut position = table;
    while position + 8 <= end && out.signatures.len() < MAX_SIGNATURES {
        let length = u32_at(pe.data, position).unwrap_or(0) as usize;
        let kind = u16_at(pe.data, position + 6).unwrap_or(0);
        if length < 8 || position + length > end {
            out.errors.push(format!("certificate entry at offset {position} declares {length} bytes, which does not fit the table"));
            break;
        }
        let blob_offset = position + 8;
        let blob = &pe.data[blob_offset..position + length];
        // WIN_CERT_TYPE_PKCS_SIGNED_DATA
        if kind == 2 {
            match der::parse_prefix(blob) {
                Ok((content_info, rest)) => {
                    // Entries are padded to 8 bytes; anything more, or anything not zero, is extra data.
                    if rest.len() >= 8 || rest.iter().any(|&b| b != 0) {
                        out.extra_in_table.push((blob_offset + content_info.raw.len(), rest.len()));
                    }
                    let before = out.signatures.len();
                    if let Err(error) = read_signed_data(&digest, content_info, blob_offset, false, 0, &mut out.signatures) {
                        out.errors.push(format!("signature at offset {blob_offset}: {error}"));
                        out.signatures.truncate(before);
                    }
                }
                Err(error) => out.errors.push(format!("signature at offset {blob_offset}: {error}")),
            }
        } else {
            out.errors.push(format!("certificate entry at offset {position} has unsupported type {kind}"));
        }
        position += length.div_ceil(8) * 8;
    }
    if position < end && pe.data[position..end].iter().any(|&b| b != 0) {
        out.extra_in_table.push((position, end - position));
    }
    Some(out)
}

/// Reads and checks an Authenticode signature kept outside a PE certificate table (the
/// `DigitalSignature` stream of an MSI): one PKCS#7 blob, whose signed digest is compared with
/// what `file_digest_of` computes. Offsets in the result are relative to `blob`.
pub fn analyze_blob(blob: &[u8], file_digest_of: &FileDigest) -> Authenticode {
    let mut out = Authenticode::default();
    match der::parse_prefix(blob) {
        Ok((content_info, rest)) => {
            if !rest.is_empty() {
                out.extra_in_table.push((content_info.raw.len(), rest.len()));
            }
            if let Err(error) = read_signed_data(file_digest_of, content_info, 0, false, 0, &mut out.signatures) {
                out.errors.push(error);
                out.signatures.clear();
            }
        }
        Err(error) => out.errors.push(error),
    }
    out
}

/// Catalog CMS verification reuses the cryptographic primitives, not PE file hashing.
/// The caller bounds and validates the ASN.1 tree before entering this function.
pub(super) fn catalog_envelope(blob: &[u8]) -> Result<(Vec<u8>, Vec<Value>), String> {
    const CTL: &str = "1.3.6.1.4.1.311.10.1";
    let (outer, rest) = der::parse_prefix(blob)?;
    if !rest.is_empty() {
        return Err("bytes follow the catalog ContentInfo".into());
    }
    let declared_hashes = catalog_shape(outer)?;
    let data = parse_signed_data(outer)?;
    if data.content_type != CTL {
        return Err("the signed content is not a Microsoft CTL".into());
    }
    if data.signer_infos.len() > MAX_SIGNATURES {
        return Err("catalog signer count exceeds the budget".into());
    }
    let content = data.content.ok_or("catalog content is missing")?;
    let ctl = match content.tag {
        TAG_SEQUENCE => content.raw.to_vec(),
        TAG_OCTET_STRING => content.content.to_vec(),
        _ => return Err("catalog content is neither a sequence nor a primitive octet string".into()),
    };
    let signed_bytes = signed_content(&content);
    let mut signatures = Vec::new();
    for (index, element) in data.signer_infos.iter().enumerate() {
        let info = match parse_signer_info(*element) {
            Ok(info) => info,
            Err(reason) => {
                signatures.push(json!({"index": index, "unreadable": reason}));
                continue;
            }
        };
        let (signer, candidates) = catalog_find_signer(&info, &data.certificates);
        let attributes = catalog_attributes(&info);
        let claimed_digest = if attributes.passed() { attributes_list_message_digest(&info).map(hex::encode) } else { None };
        let computed_digest = Hash::from_oid(&info.digest_oid).map(|hash| hex::encode(hash.digest(&signed_bytes)));
        let algorithms = if candidates > 1 {
            Check::NotChecked("catalog signer certificate identifier is ambiguous".into())
        } else if declared_hashes.contains(&info.digest_oid) {
            catalog_algorithm(&info, signer)
        } else {
            Check::NotChecked("catalog signer digest is absent from digestAlgorithms".into())
        };
        let (digest, signature) = if attributes.passed() && algorithms.passed() {
            check_signer_info(&info, signer, Some(&signed_bytes))
        } else {
            let why = "catalog signed attributes or algorithms were not established".to_string();
            (Check::NotChecked(why.clone()), Check::NotChecked(why))
        };
        let (chain, chain_check, root) = match signer {
            Some(signer) => build_chain(signer, &data.certificates),
            None => (Vec::new(), Check::NotChecked("catalog signer certificate is absent or ambiguous".into()), false),
        };
        signatures.push(json!({
            "index": index,
            "digest_algorithm": info.digest_oid,
            "signature_algorithm": info.signature_oid,
            "message_digest_claimed": claimed_digest,
            "content_digest_computed": computed_digest,
            "signature_sha256": hex::encode(Sha256::digest(&info.signature)),
            "checks": {"signed_attributes": attributes.json(), "algorithms": algorithms.json(),
                "content_digest": digest.json(), "signature": signature.json(), "embedded_chain": chain_check.json()},
            "signer": signer.map(Certificate::json),
            "signer_certificate_candidates": candidates,
            "issuers": chain.iter().skip(1).map(|c| c.json()).collect::<Vec<_>>(),
            "chain_reaches_embedded_root": root,
            "unsigned_attributes_present": info.unsigned_attributes.is_some(),
        }));
    }
    Ok((ctl, signatures))
}

fn attributes_list_message_digest(info: &SignerInfo) -> Option<Vec<u8>> {
    attributes(info.signed_attributes)
        .iter()
        .find(|(oid, _)| oid == OID_MESSAGE_DIGEST)
        .and_then(|(_, values)| values.children().any().ok())
        .and_then(|value| value.octet_string())
}

fn catalog_find_signer<'c, 'a>(info: &SignerInfo, certificates: &'c [Certificate<'a>]) -> (Option<&'c Certificate<'a>>, usize) {
    let mut candidates = std::collections::BTreeMap::new();
    for certificate in certificates {
        let matches = match (info.issuer, info.serial, info.key_id) {
            (Some(issuer), Some(serial), _) => certificate.raw_issuer == issuer && certificate.raw_serial == serial,
            (_, _, Some(key)) => certificate.subject_key_id.as_deref() == Some(key),
            _ => false,
        };
        if matches {
            candidates.entry(&certificate.sha256).or_insert(certificate);
        }
    }
    let count = candidates.len();
    (if count == 1 { candidates.values().next().copied() } else { None }, count)
}

fn catalog_shape(outer: Tlv<'_>) -> Result<std::collections::BTreeSet<String>, String> {
    let finish = |mut fields: Reader<'_>| -> Result<(), String> {
        if fields.next().is_some() { Err("extra catalog CMS fields".into()) } else { Ok(()) }
    };
    if outer.tag != TAG_SEQUENCE {
        return Err("catalog ContentInfo is not a sequence".into());
    }
    let mut ci = outer.children();
    if ci.expect(TAG_OID)?.oid().as_deref() != Some(OID_SIGNED_DATA) {
        return Err("catalog is not SignedData".into());
    }
    let mut wrapper = ci.expect(0xa0)?.children();
    finish(ci)?;
    let mut body = wrapper.expect(TAG_SEQUENCE)?.children();
    finish(wrapper)?;
    if !matches!(body.expect(TAG_INTEGER)?.integer_bytes(), Some([1] | [3])) {
        return Err("unsupported catalog SignedData version".into());
    }
    let mut hashes = std::collections::BTreeSet::new();
    for (index, algorithm) in body.expect(TAG_SET)?.children().enumerate() {
        if index >= MAX_SIGNATURES {
            return Err("catalog digest algorithm count exceeds the budget".into());
        }
        hashes.insert(catalog_hash_identifier(algorithm?)?);
    }
    let mut encapsulated = body.expect(TAG_SEQUENCE)?.children();
    encapsulated.expect(TAG_OID)?;
    let mut content = encapsulated.expect(0xa0)?.children();
    content.any()?;
    finish(content)?;
    finish(encapsulated)?;
    if let Some(certificates) = body.optional(0xa0) {
        if certificates.content.len() > 1024 * 1024 {
            return Err("catalog certificate bag exceeds the byte budget".into());
        }
        for (index, certificate) in certificates.children().enumerate() {
            let certificate = certificate?;
            if index >= MAX_CERTIFICATES || certificate.raw.len() > 64 * 1024 {
                return Err("catalog certificate count or size exceeds the budget".into());
            }
            parse_certificate(certificate)?;
        }
    }
    body.optional(0xa1);
    for (index, signer) in body.expect(TAG_SET)?.children().enumerate() {
        if index >= MAX_SIGNATURES {
            return Err("catalog signer count exceeds the budget".into());
        }
        let signer = signer?;
        if signer.tag != TAG_SEQUENCE {
            return Err("catalog SignerInfo is not a sequence".into());
        }
        let mut fields = signer.children();
        let version = fields.expect(TAG_INTEGER)?;
        let identifier = fields.any()?;
        match (version.integer_bytes(), identifier.tag) {
            (Some([1]), TAG_SEQUENCE) => {
                let mut issuer = identifier.children();
                issuer.expect(TAG_SEQUENCE)?;
                let serial = issuer.expect(TAG_INTEGER)?;
                if serial.content.is_empty() || serial.content.len() > 64 {
                    return Err("catalog signer serial is unsupported".into());
                }
                finish(issuer)?;
            }
            (Some([3]), 0x80) if !identifier.content.is_empty() && identifier.content.len() <= 64 => {}
            _ => return Err("catalog signer version or identifier form is unsupported".into()),
        }
        catalog_hash_identifier(fields.expect(TAG_SEQUENCE)?)?;
        fields.optional(0xa0);
        let mut algorithm = fields.expect(TAG_SEQUENCE)?.children();
        let oid = algorithm.expect(TAG_OID)?.oid().ok_or("invalid catalog signature OID")?;
        if let Some(parameter) = algorithm.next() {
            let parameter = parameter?;
            if parameter.tag != 0x05 || !parameter.content.is_empty() || oid.starts_with("1.2.840.10045.") {
                return Err("catalog signature parameters are unsupported".into());
            }
        }
        finish(algorithm)?;
        fields.expect(TAG_OCTET_STRING)?;
        fields.optional(0xa1);
        finish(fields)?;
    }
    finish(body)?;
    Ok(hashes)
}

fn catalog_hash_identifier(node: Tlv<'_>) -> Result<String, String> {
    if node.tag != TAG_SEQUENCE {
        return Err("catalog hash identifier is not a sequence".into());
    }
    let mut fields = node.children();
    let oid = fields.expect(TAG_OID)?.oid().ok_or("invalid catalog hash OID")?;
    if let Some(parameter) = fields.next() {
        let parameter = parameter?;
        if parameter.tag != 0x05 || !parameter.content.is_empty() {
            return Err("catalog hash parameters are unsupported".into());
        }
    }
    if fields.next().is_some() {
        return Err("extra catalog hash identifier fields".into());
    }
    Ok(oid)
}

fn catalog_attributes(info: &SignerInfo) -> Check {
    let verify = || -> Result<(), String> {
        let set = info.signed_attributes.ok_or("catalog signed attributes are absent")?;
        let mut seen = std::collections::BTreeSet::new();
        let mut content_type = false;
        let mut digest = false;
        let mut previous = None;
        for (index, attribute) in set.children().enumerate() {
            if index >= 64 {
                return Err("catalog signed attribute count exceeds the budget".into());
            }
            let attribute = attribute?;
            if previous.is_some_and(|raw: &[u8]| raw > attribute.raw) {
                return Err("catalog signed attributes are not DER ordered".into());
            }
            previous = Some(attribute.raw);
            if attribute.tag != TAG_SEQUENCE {
                return Err("signed attribute is not a sequence".into());
            }
            let mut fields = attribute.children();
            let oid = fields.expect(TAG_OID)?.oid().ok_or("invalid signed attribute OID")?;
            if !seen.insert(oid.clone()) {
                return Err("duplicate catalog signed attribute".into());
            }
            let values = fields.expect(TAG_SET)?;
            if fields.next().is_some() {
                return Err("extra signed attribute fields".into());
            }
            if matches!(oid.as_str(), "1.2.840.113549.1.9.3" | OID_MESSAGE_DIGEST) {
                let mut values = values.children();
                let value = values.any()?;
                if values.next().is_some() {
                    return Err("ambiguous catalog signed attribute values".into());
                }
                if oid == OID_MESSAGE_DIGEST {
                    if value.tag != TAG_OCTET_STRING || value.content.len() > 64 {
                        return Err("invalid catalog messageDigest".into());
                    }
                    digest = true;
                } else {
                    if value.oid().as_deref() != Some("1.3.6.1.4.1.311.10.1") {
                        return Err("catalog signed contentType differs".into());
                    }
                    content_type = true;
                }
            }
        }
        if !content_type || !digest {
            return Err("catalog contentType or messageDigest is absent".into());
        }
        Ok(())
    };
    match verify() {
        Ok(()) => Check::Passed,
        Err(reason) => Check::NotChecked(reason),
    }
}

fn catalog_algorithm(info: &SignerInfo, signer: Option<&Certificate>) -> Check {
    let Some(hash) = Hash::from_oid(&info.digest_oid) else {
        return Check::NotChecked("unsupported catalog digest algorithm".into());
    };
    let Some(signer) = signer else {
        return Check::NotChecked("catalog signer certificate is absent".into());
    };
    let oid = info.signature_oid.as_str();
    let compatible = match &signer.key {
        Key::Rsa { .. } => oid == OID_RSA || (oid.starts_with("1.2.840.113549.1.1.") && Hash::from_signature_oid(oid) == Some(hash)),
        Key::P256(_) | Key::P384(_) => oid.starts_with("1.2.840.10045.4.") && Hash::from_signature_oid(oid) == Some(hash),
        Key::Other(_) => false,
    };
    if compatible { Check::Passed } else { Check::NotChecked("unsupported or inconsistent catalog signature algorithm".into()) }
}

struct SignedData<'a> {
    content_type: String,
    /// The element inside `[0] EXPLICIT`, when content is present.
    content: Option<Tlv<'a>>,
    certificates: Vec<Certificate<'a>>,
    signer_infos: Vec<Tlv<'a>>,
}

fn parse_signed_data<'a>(content_info: Tlv<'a>) -> Result<SignedData<'a>, String> {
    if content_info.tag != TAG_SEQUENCE {
        return Err("not a PKCS#7 ContentInfo".into());
    }
    let mut outer = content_info.children();
    let kind = outer.expect(TAG_OID)?.oid().unwrap_or_default();
    if kind != OID_SIGNED_DATA {
        return Err(format!("content type {kind} is not SignedData"));
    }
    let mut body = outer.expect(0xa0)?.children().expect(TAG_SEQUENCE)?.children();
    body.expect(TAG_INTEGER)?;
    body.expect(TAG_SET)?;
    let mut encapsulated = body.expect(TAG_SEQUENCE)?.children();
    let content_type = encapsulated.expect(TAG_OID)?.oid().unwrap_or_default();
    let content = match encapsulated.optional(0xa0) {
        Some(wrapper) => Some(wrapper.children().any()?),
        None => None,
    };
    let mut certificates = Vec::new();
    if let Some(bag) = body.optional(0xa0) {
        for element in bag.children() {
            let element = element?;
            if element.tag == TAG_SEQUENCE
                && certificates.len() < MAX_CERTIFICATES
                && let Ok(certificate) = parse_certificate(element)
            {
                certificates.push(certificate);
            }
        }
    }
    body.optional(0xa1);
    let signer_infos = body.expect(TAG_SET)?.children().collect::<Result<Vec<_>, _>>()?;
    Ok(SignedData { content_type, content, certificates, signer_infos })
}

/// The bytes a SignedData's message digest covers: the content octets of the encapsulated element.
fn signed_content(content: &Tlv) -> Vec<u8> {
    content.octet_string().unwrap_or_else(|| content.content.to_vec())
}

struct SignerInfo<'a> {
    issuer: Option<&'a [u8]>,
    serial: Option<&'a [u8]>,
    key_id: Option<&'a [u8]>,
    digest_oid: String,
    signed_attributes: Option<Tlv<'a>>,
    signature_oid: String,
    signature: Vec<u8>,
    unsigned_attributes: Option<Tlv<'a>>,
}

fn parse_signer_info<'a>(info: Tlv<'a>) -> Result<SignerInfo<'a>, String> {
    if info.tag != TAG_SEQUENCE {
        return Err("not a SignerInfo".into());
    }
    let mut fields = info.children();
    fields.expect(TAG_INTEGER)?;
    let (mut issuer, mut serial, mut key_id) = (None, None, None);
    let identifier = fields.any()?;
    if identifier.tag == TAG_SEQUENCE {
        let mut parts = identifier.children();
        issuer = Some(parts.expect(TAG_SEQUENCE)?.raw);
        serial = parts.expect(TAG_INTEGER)?.integer_bytes();
    } else if identifier.is_context(0) {
        key_id = Some(identifier.content);
    } else {
        return Err("unknown signer identifier".into());
    }
    let digest_oid = fields.expect(TAG_SEQUENCE)?.children().expect(TAG_OID)?.oid().unwrap_or_default();
    let signed_attributes = fields.optional(0xa0);
    let signature_oid = fields.expect(TAG_SEQUENCE)?.children().expect(TAG_OID)?.oid().unwrap_or_default();
    let signature = fields.any()?.octet_string().ok_or("the signature is not an OCTET STRING")?;
    let unsigned_attributes = fields.optional(0xa1);
    Ok(SignerInfo { issuer, serial, key_id, digest_oid, signed_attributes, signature_oid, signature, unsigned_attributes })
}

/// `(attribute type, value set)` for each attribute in a signed or unsigned attribute set.
fn attributes<'a>(set: Option<Tlv<'a>>) -> Vec<(String, Tlv<'a>)> {
    let mut list = Vec::new();
    let Some(set) = set else { return list };
    for attribute in set.children().flatten().take(64) {
        let mut parts = attribute.children();
        if let (Ok(oid), Ok(values)) = (parts.expect(TAG_OID), parts.expect(TAG_SET))
            && let Some(oid) = oid.oid()
        {
            list.push((oid, values));
        }
    }
    list
}

fn find_signer<'c, 'a>(info: &SignerInfo, certificates: &'c [Certificate<'a>]) -> Option<&'c Certificate<'a>> {
    certificates.iter().find(|c| match (info.issuer, info.serial, info.key_id) {
        (Some(issuer), Some(serial), _) => c.raw_issuer == issuer && c.raw_serial == serial,
        (_, _, Some(key_id)) => c.subject_key_id.as_deref() == Some(key_id),
        _ => false,
    })
}

/// The checks every CMS SignerInfo allows: its `messageDigest` against `content`, and its
/// signature against the signer's certificate.
fn check_signer_info(info: &SignerInfo, signer: Option<&Certificate>, content: Option<&[u8]>) -> (Check, Check) {
    let Some(hash) = Hash::from_oid(&info.digest_oid) else {
        let why = format!("digest algorithm {} is not supported", info.digest_oid);
        return (Check::NotChecked(why.clone()), Check::NotChecked(why));
    };
    let signed = attributes(info.signed_attributes);
    let content_digest = match (content, info.signed_attributes) {
        (None, _) => Check::NotChecked("the signed content is not present".into()),
        (Some(_), None) => Check::NotChecked("the signature has no signed attributes; it covers the content directly".into()),
        (Some(content), Some(_)) => {
            let claimed = signed.iter().find(|(oid, _)| oid == OID_MESSAGE_DIGEST).and_then(|(_, v)| v.children().any().ok());
            match claimed.and_then(|v| v.octet_string()) {
                Some(claimed) if claimed == hash.digest(content) => Check::Passed,
                Some(_) => Check::Failed,
                None => Check::NotChecked("no messageDigest attribute".into()),
            }
        }
    };
    let Some(signer) = signer else {
        return (content_digest, Check::NotChecked("the signer's certificate is not embedded".into()));
    };
    // The attributes are signed as a DER SET, though they are stored with an implicit [0] tag.
    let message: Vec<u8> = match (info.signed_attributes, content) {
        (Some(attrs), _) => {
            let mut bytes = attrs.raw.to_vec();
            if let Some(first) = bytes.first_mut() {
                *first = TAG_SET;
            }
            bytes
        }
        (None, Some(content)) => content.to_vec(),
        (None, None) => return (content_digest, Check::NotChecked("nothing to verify the signature against".into())),
    };
    let signature = verify(&signer.key, &info.signature_oid, hash, &message, &info.signature);
    (content_digest, signature)
}

/// Verifies `signature` over `message` hashed with `hash`.
fn verify(key: &Key, signature_oid: &str, hash: Hash, message: &[u8], signature: &[u8]) -> Check {
    if signature_oid == "1.2.840.113549.1.1.10" {
        return Check::NotChecked("RSA-PSS signatures are not supported".into());
    }
    let digest = hash.digest(message);
    match key {
        Key::Rsa { modulus, exponent } => {
            if modulus.len() > 2048 || exponent.len() > 8 {
                return Check::NotChecked("RSA key too large".into());
            }
            let n = rsa::BigUint::from_bytes_be(modulus);
            let e = rsa::BigUint::from_bytes_be(exponent);
            let Ok(key) = rsa::RsaPublicKey::new_with_max_size(n, e, 16384) else {
                return Check::NotChecked("the RSA public key is not valid".into());
            };
            let scheme = rsa::Pkcs1v15Sign { hash_len: Some(digest.len()), prefix: hash.pkcs1_prefix().into() };
            if key.verify(scheme, &digest, signature).is_ok() { Check::Passed } else { Check::Failed }
        }
        Key::P256(point) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let (Ok(key), Ok(signature)) = (p256::ecdsa::VerifyingKey::from_sec1_bytes(point), p256::ecdsa::Signature::from_der(signature))
            else {
                return Check::NotChecked("the ECDSA key or signature is not well formed".into());
            };
            if key.verify_prehash(&digest, &signature).is_ok() { Check::Passed } else { Check::Failed }
        }
        Key::P384(point) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let (Ok(key), Ok(signature)) = (p384::ecdsa::VerifyingKey::from_sec1_bytes(point), p384::ecdsa::Signature::from_der(signature))
            else {
                return Check::NotChecked("the ECDSA key or signature is not well formed".into());
            };
            if key.verify_prehash(&digest, &signature).is_ok() { Check::Passed } else { Check::Failed }
        }
        Key::Other(name) => Check::NotChecked(format!("public key type {name} is not supported")),
    }
}

/// Follows issuers from `signer` through `bag`. Returns the chain (signer first), whether every
/// link's signature verified, and whether the chain ends in an embedded self-issued certificate.
fn build_chain<'c, 'a>(signer: &'c Certificate<'a>, bag: &'c [Certificate<'a>]) -> (Vec<&'c Certificate<'a>>, Check, bool) {
    let mut chain = vec![signer];
    let mut check = Check::Passed;
    let mut current = signer;
    let note = |result: Check, check: &mut Check| match result {
        Check::Passed => {}
        Check::Failed => *check = Check::Failed,
        Check::NotChecked(why) => {
            if !check.failed() {
                *check = Check::NotChecked(why);
            }
        }
    };
    for _ in 0..12 {
        let link = |issuer: &Certificate| match Hash::from_signature_oid(&current.signature_oid) {
            Some(hash) => verify(&issuer.key, &current.signature_oid, hash, current.tbs, current.signature),
            None => Check::NotChecked(format!("certificate signature algorithm {} is not supported", current.signature_oid)),
        };
        if current.self_issued() {
            note(link(current), &mut check);
            return (chain, check, true);
        }
        let candidates: Vec<&Certificate> = bag.iter().filter(|c| c.raw_subject == current.raw_issuer).collect();
        // Prefer the issuer whose key actually verifies (cross-signed roots share a name).
        let Some(issuer) = candidates.iter().find(|c| link(c).passed()).or(candidates.first()).copied() else {
            return (chain, check, false);
        };
        note(link(issuer), &mut check);
        if chain.iter().any(|c| std::ptr::eq(*c, issuer)) {
            return (chain, check, false);
        }
        chain.push(issuer);
        current = issuer;
    }
    (chain, check, false)
}

fn read_signed_data<'a>(
    file_digest_of: &FileDigest,
    content_info: Tlv<'a>,
    offset: usize,
    nested: bool,
    depth: u32,
    out: &mut Vec<Signature>,
) -> Result<(), String> {
    let data = parse_signed_data(content_info)?;
    if data.content_type != OID_SPC_INDIRECT_DATA {
        return Err(format!("signed content type {} is not SpcIndirectDataContent", data.content_type));
    }
    let content = data.content.ok_or("the signed content is missing")?;
    // SpcIndirectDataContent ::= SEQUENCE { data, messageDigest DigestInfo }
    let mut indirect = content.children();
    indirect.expect(TAG_SEQUENCE)?;
    let mut digest_info = indirect.expect(TAG_SEQUENCE)?.children();
    let digest_oid = digest_info.expect(TAG_SEQUENCE)?.children().expect(TAG_OID)?.oid().unwrap_or_default();
    let signed_digest = digest_info.expect(TAG_OCTET_STRING)?.content;
    let hash = Hash::from_oid(&digest_oid);
    let (computed, file_digest) = match hash.map(|h| file_digest_of(h, signed_digest)) {
        None => (None, Check::NotChecked(format!("digest algorithm {digest_oid} is not supported"))),
        Some(Err(why)) => (None, Check::NotChecked(why)),
        Some(Ok(computed)) => {
            let check = if computed.as_slice() == signed_digest { Check::Passed } else { Check::Failed };
            (Some(computed), check)
        }
    };
    let content_bytes = signed_content(&content);

    let first = data.signer_infos.first().copied().ok_or("the signature has no SignerInfo")?;
    let info = parse_signer_info(first)?;
    let signer = find_signer(&info, &data.certificates);
    let (content_digest, signature) = check_signer_info(&info, signer, Some(&content_bytes));
    let (chain, chain_check, reaches_root) = match signer {
        Some(signer) => build_chain(signer, &data.certificates),
        None => (Vec::new(), Check::NotChecked("the signer's certificate is not embedded".into()), false),
    };

    let (mut program_name, mut more_info_url, mut signing_time) = (None, None, None);
    for (oid, values) in attributes(info.signed_attributes) {
        let Ok(value) = values.children().any() else { continue };
        match oid.as_str() {
            OID_SIGNING_TIME => signing_time = value.time(),
            OID_SPC_SP_OPUS_INFO => (program_name, more_info_url) = opus_info(value),
            _ => {}
        }
    }

    let mut timestamps = Vec::new();
    let mut nested_blobs = Vec::new();
    for (oid, values) in attributes(info.unsigned_attributes) {
        for value in values.children().flatten().take(8) {
            match oid.as_str() {
                OID_COUNTERSIGNATURE => timestamps.push(legacy_timestamp(value, &info.signature, &data.certificates)),
                OID_RFC3161_TIMESTAMP => timestamps.push(rfc3161_timestamp(value, &info.signature)),
                OID_NESTED_SIGNATURE => nested_blobs.push(value),
                _ => {}
            }
        }
    }

    out.push(Signature {
        nested,
        offset,
        length: content_info.raw.len(),
        digest_algorithm: hash,
        digest_algorithm_name: hash.map(|h| h.name().to_string()).unwrap_or(digest_oid),
        signed_digest: Some(hex::encode(signed_digest)),
        computed_digest: computed.map(hex::encode),
        file_digest,
        content_digest,
        signature,
        signer: signer.map(Certificate::json),
        signer_name: signer.map(|c| c.display_name().to_string()),
        signer_subject: signer.map(|c| c.subject.clone()),
        signer_self_issued: signer.is_some_and(Certificate::self_issued),
        signer_validity: signer.and_then(|c| Some((c.not_before.clone()?, c.not_after.clone()?))),
        chain: chain.iter().map(|c| c.json()).collect(),
        chain_check,
        chain_reaches_root: reaches_root,
        program_name,
        more_info_url,
        signing_time,
        timestamps,
        certificates: data.certificates.len(),
    });
    if depth < MAX_NESTING {
        for blob in nested_blobs {
            if out.len() >= MAX_SIGNATURES {
                break;
            }
            // A nested signature that cannot be read does not invalidate the one holding it.
            let before = out.len();
            if read_signed_data(file_digest_of, blob, offset, true, depth + 1, out).is_err() {
                out.truncate(before);
            }
        }
    }
    Ok(())
}

/// `SpcSpOpusInfo ::= SEQUENCE { programName [0] EXPLICIT SpcString, moreInfo [1] EXPLICIT SpcLink }`.
fn opus_info(value: Tlv) -> (Option<String>, Option<String>) {
    let (mut name, mut url) = (None, None);
    for field in value.children().flatten().take(4) {
        let Ok(inner) = field.children().any() else { continue };
        if field.is_context(0) {
            // SpcString: [0] IMPLICIT BMPString or [1] IMPLICIT IA5String
            name = if inner.is_context(0) {
                let units: Vec<u16> = inner.content.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(String::from_utf16_lossy(&units))
            } else {
                Some(String::from_utf8_lossy(inner.content).into_owned())
            };
        } else if field.is_context(1) && inner.is_context(0) {
            // SpcLink: url [0] IMPLICIT IA5String
            url = Some(String::from_utf8_lossy(inner.content).into_owned());
        }
    }
    (name.filter(|n| !n.is_empty()), url.filter(|u| !u.is_empty()))
}

/// A PKCS#9 countersignature: a SignerInfo whose content is the parent's signature value.
fn legacy_timestamp(value: Tlv, parent_signature: &[u8], bag: &[Certificate]) -> Timestamp {
    let mut stamp = Timestamp {
        kind: "countersignature",
        time: None,
        authority: None,
        authority_name: None,
        covers_signature: Check::NotChecked("the countersignature could not be read".into()),
        content_digest: Check::NotChecked("the countersignature could not be read".into()),
        signature: Check::NotChecked("the countersignature could not be read".into()),
        chain: Vec::new(),
        chain_check: Check::NotChecked("the countersignature could not be read".into()),
    };
    let Ok(info) = parse_signer_info(value) else { return stamp };
    let signer = find_signer(&info, bag);
    let (covers, signature) = check_signer_info(&info, signer, Some(parent_signature));
    stamp.time = attributes(info.signed_attributes)
        .iter()
        .find(|(oid, _)| oid == OID_SIGNING_TIME)
        .and_then(|(_, values)| values.children().any().ok())
        .and_then(|v| v.time());
    // For a countersignature the content digest is the coverage of the parent's signature.
    stamp.content_digest = covers.clone();
    stamp.covers_signature = covers;
    stamp.signature = signature;
    stamp_authority(&mut stamp, signer, bag);
    stamp
}

/// A Microsoft RFC 3161 timestamp attribute: a SignedData over a TSTInfo.
fn rfc3161_timestamp(value: Tlv, parent_signature: &[u8]) -> Timestamp {
    let unread = |why: &str| Check::NotChecked(why.to_string());
    let mut stamp = Timestamp {
        kind: "rfc3161",
        time: None,
        authority: None,
        authority_name: None,
        covers_signature: unread("the timestamp token could not be read"),
        content_digest: unread("the timestamp token could not be read"),
        signature: unread("the timestamp token could not be read"),
        chain: Vec::new(),
        chain_check: unread("the timestamp token could not be read"),
    };
    let Ok(data) = parse_signed_data(value) else { return stamp };
    let Some(content) = data.content.filter(|_| data.content_type == OID_TST_INFO) else { return stamp };
    let tst_bytes = signed_content(&content);
    // TSTInfo ::= SEQUENCE { version, policy, messageImprint { algorithm, hash }, serial, genTime, ... }
    let imprint = (|| {
        let (tst, _) = der::parse_prefix(&tst_bytes).ok()?;
        let mut fields = tst.children();
        fields.expect(TAG_INTEGER).ok()?;
        fields.expect(TAG_OID).ok()?;
        let mut imprint = fields.expect(TAG_SEQUENCE).ok()?.children();
        let oid = imprint.expect(TAG_SEQUENCE).ok()?.children().expect(TAG_OID).ok()?.oid()?;
        let hashed = imprint.expect(TAG_OCTET_STRING).ok()?.content.to_vec();
        fields.expect(TAG_INTEGER).ok()?;
        let time = fields.expect(0x18).ok()?.time();
        Some((oid, hashed, time))
    })();
    if let Some((oid, hashed, time)) = imprint {
        stamp.time = time;
        stamp.covers_signature = match Hash::from_oid(&oid) {
            Some(hash) if hash.digest(parent_signature) == hashed => Check::Passed,
            Some(_) => Check::Failed,
            None => Check::NotChecked(format!("digest algorithm {oid} is not supported")),
        };
    }
    let Some(info) = data.signer_infos.first().and_then(|i| parse_signer_info(*i).ok()) else { return stamp };
    let signer = find_signer(&info, &data.certificates);
    (stamp.content_digest, stamp.signature) = check_signer_info(&info, signer, Some(&tst_bytes));
    stamp_authority(&mut stamp, signer, &data.certificates);
    stamp
}

fn stamp_authority(stamp: &mut Timestamp, signer: Option<&Certificate>, bag: &[Certificate]) {
    match signer {
        Some(signer) => {
            let (chain, check, _) = build_chain(signer, bag);
            stamp.authority = Some(signer.json());
            stamp.authority_name = Some(signer.display_name().to_string());
            stamp.chain = chain.iter().map(|c| c.json()).collect();
            stamp.chain_check = check;
        }
        None => stamp.chain_check = Check::NotChecked("the timestamp authority's certificate is not embedded".into()),
    }
}

/// The short name of a distinguished-name attribute type.
fn attribute_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.15" => "businessCategory",
        "2.5.4.17" => "postalCode",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return None,
    })
}

/// A distinguished name as `C=XX, O=Example, CN=Name`, in the order stored, with the common
/// name and organization picked out.
fn name(name: Tlv) -> (String, Option<String>, Option<String>) {
    let mut parts = Vec::new();
    let (mut common_name, mut organization) = (None, None);
    for rdn in name.children().flatten().take(32) {
        for pair in rdn.children().flatten().take(8) {
            let mut fields = pair.children();
            let (Ok(kind), Ok(value)) = (fields.any(), fields.any()) else { continue };
            let Some(oid) = kind.oid() else { continue };
            let text = value.text().unwrap_or_else(|| hex::encode(value.content));
            match oid.as_str() {
                "2.5.4.3" => common_name = Some(text.clone()),
                "2.5.4.10" => organization = Some(text.clone()),
                _ => {}
            }
            parts.push(format!("{}={text}", attribute_name(&oid).unwrap_or(&oid)));
        }
    }
    (parts.join(", "), common_name, organization)
}

fn parse_certificate<'a>(certificate: Tlv<'a>) -> Result<Certificate<'a>, String> {
    let mut outer = certificate.children();
    let tbs = outer.expect(TAG_SEQUENCE)?;
    let signature_oid = outer.expect(TAG_SEQUENCE)?.children().expect(TAG_OID)?.oid().unwrap_or_default();
    let signature = outer.any()?.bit_string().ok_or("certificate signature is not a BIT STRING")?;
    let mut fields = tbs.children();
    fields.optional(0xa0);
    let serial = fields.expect(TAG_INTEGER)?;
    fields.expect(TAG_SEQUENCE)?;
    let issuer = fields.expect(TAG_SEQUENCE)?;
    let mut validity = fields.expect(TAG_SEQUENCE)?.children();
    let not_before = validity.any().ok().and_then(|t| t.time());
    let not_after = validity.any().ok().and_then(|t| t.time());
    let subject = fields.expect(TAG_SEQUENCE)?;
    let mut spki = fields.expect(TAG_SEQUENCE)?.children();
    let mut algorithm = spki.expect(TAG_SEQUENCE)?.children();
    let key_oid = algorithm.expect(TAG_OID)?.oid().unwrap_or_default();
    let key_bits = spki.any()?.bit_string().ok_or("public key is not a BIT STRING")?;
    let (key, key_description) = match key_oid.as_str() {
        OID_RSA => {
            let mut numbers = Reader::new(key_bits).expect(TAG_SEQUENCE)?.children();
            let modulus = numbers.expect(TAG_INTEGER)?.integer_bytes().unwrap_or_default();
            let exponent = numbers.expect(TAG_INTEGER)?.integer_bytes().unwrap_or_default();
            let bits = modulus.len() * 8 - modulus.first().map_or(0, |b| b.leading_zeros() as usize).min(modulus.len() * 8);
            (Key::Rsa { modulus, exponent }, format!("RSA {bits}"))
        }
        OID_EC_KEY => match algorithm.any().ok().and_then(|c| c.oid()).as_deref() {
            Some(OID_P256) => (Key::P256(key_bits), "ECDSA P-256".to_string()),
            Some(OID_P384) => (Key::P384(key_bits), "ECDSA P-384".to_string()),
            other => {
                let curve = format!("EC curve {}", other.unwrap_or("unknown"));
                (Key::Other(curve.clone()), curve)
            }
        },
        other => (Key::Other(other.to_string()), other.to_string()),
    };
    // Extensions: only the subject key identifier, which CMS may use to name the signer.
    let mut subject_key_id = None;
    for field in fields.flatten() {
        if field.tag != 0xa3 {
            continue;
        }
        let Ok(list) = field.children().expect(TAG_SEQUENCE) else { continue };
        for extension in list.children().flatten().take(64) {
            let mut parts = extension.children();
            if parts.any().ok().and_then(|o| o.oid()).as_deref() != Some("2.5.29.14") {
                continue;
            }
            if let Some(Ok(value)) = parts.last()
                && value.tag == TAG_OCTET_STRING
                && let Ok(inner) = Reader::new(value.content).expect(TAG_OCTET_STRING)
            {
                subject_key_id = Some(inner.content.to_vec());
            }
        }
    }
    let (subject_text, common_name, organization) = name(subject);
    let (issuer_text, _, _) = name(issuer);
    let signature_algorithm = match signature_oid.as_str() {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        other => other,
    }
    .to_string();
    Ok(Certificate {
        subject: subject_text,
        issuer: issuer_text,
        common_name,
        organization,
        serial: hex::encode(serial.integer_bytes().unwrap_or_default()),
        not_before,
        not_after,
        key_description,
        signature_algorithm,
        sha1: hex::encode(Sha1::digest(certificate.raw)),
        sha256: hex::encode(Sha256::digest(certificate.raw)),
        raw_subject: subject.raw,
        raw_issuer: issuer.raw,
        raw_serial: serial.integer_bytes().unwrap_or_default(),
        tbs: tbs.raw,
        signature_oid,
        signature,
        key,
        subject_key_id,
    })
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if bytes.len() < 128 {
            result.push(bytes.len() as u8);
        } else {
            let length = bytes.len().to_be_bytes();
            let length = &length[length.iter().position(|b| *b != 0).expect("nonzero length")..];
            result.push(0x80 | length.len() as u8);
            result.extend_from_slice(length);
        }
        result.extend_from_slice(bytes);
        result
    }

    fn root() -> Tlv<'static> {
        der::parse_prefix(include_bytes!("../tests/data/native-catalog-v2.cat")).expect("native catalog").0
    }

    fn replace_body(index: usize, replacement: &[u8]) -> Vec<u8> {
        let outer = root().children().collect::<Result<Vec<_>, _>>().expect("ContentInfo");
        let body = outer[1].children().expect(TAG_SEQUENCE).expect("SignedData");
        let fields = body.children().collect::<Result<Vec<_>, _>>().expect("SignedData fields");
        let mut content = Vec::new();
        for (at, field) in fields.iter().enumerate() {
            content.extend_from_slice(if at == index { replacement } else { field.raw });
        }
        tlv(TAG_SEQUENCE, &[outer[0].raw, &tlv(0xa0, &tlv(TAG_SEQUENCE, &content))].concat())
    }

    #[test]
    fn catalog_signed_attribute_ambiguity_and_missing_algorithm_declarations_do_not_pass() {
        let data = parse_signed_data(root()).expect("native envelope");
        let mut info = parse_signer_info(data.signer_infos[0]).expect("native signer");
        assert!(catalog_attributes(&info).passed());
        let attrs = info.signed_attributes.expect("native signed attributes");
        let mut values = attrs.children().map(|v| v.expect("attribute").raw.to_vec()).collect::<Vec<_>>();
        values.push(values[0].clone());
        values.sort();
        let bytes = tlv(0xa0, &values.concat());
        info.signed_attributes = Some(der::parse_prefix(&bytes).expect("duplicate attribute set").0);
        assert!(matches!(catalog_attributes(&info), Check::NotChecked(reason) if reason.contains("duplicate")));
        info.signed_attributes = None;
        assert!(!catalog_attributes(&info).passed());
        let mut attrs = Vec::new();
        for index in 0..65u8 {
            attrs.extend(tlv(TAG_SEQUENCE, &[tlv(TAG_OID, &[42, 3, index]), tlv(TAG_SET, &tlv(0x05, &[]))].concat()));
        }
        let bytes = tlv(0xa0, &attrs);
        info.signed_attributes = Some(der::parse_prefix(&bytes).expect("attribute budget").0);
        assert!(matches!(catalog_attributes(&info), Check::NotChecked(reason) if reason.contains("budget")));
        let bytes = replace_body(1, &tlv(TAG_SET, &[]));
        let (_, signatures) = catalog_envelope(&bytes).expect("missing declared hash remains an explicit check");
        assert!(signatures[0]["checks"]["algorithms"]["not_checked"].as_str().expect("reason").contains("digestAlgorithms"));
    }

    #[test]
    fn catalog_signer_and_certificate_caps_are_checked_before_verification() {
        let outer = root().children().collect::<Result<Vec<_>, _>>().expect("ContentInfo");
        let fields =
            outer[1].children().expect(TAG_SEQUENCE).expect("SignedData").children().collect::<Result<Vec<_>, _>>().expect("fields");
        let signer = fields.last().expect("signer set").children().any().expect("signer");
        let oversized = tlv(TAG_SET, &signer.raw.repeat(MAX_SIGNATURES + 1));
        assert!(catalog_envelope(&replace_body(fields.len() - 1, &oversized)).is_err());
        let signer_fields = signer.children().collect::<Result<Vec<_>, _>>().expect("signer fields");
        let mut changed = tlv(TAG_INTEGER, &[2]);
        for field in signer_fields.iter().skip(1) {
            changed.extend_from_slice(field.raw);
        }
        let changed = tlv(TAG_SET, &tlv(TAG_SEQUENCE, &changed));
        assert!(catalog_envelope(&replace_body(fields.len() - 1, &changed)).is_err(), "unknown signer version is unsupported");
        let bag = fields.iter().position(|f| f.tag == 0xa0).expect("certificate bag");
        let certificate = fields[bag].children().any().expect("certificate");
        let oversized = tlv(0xa0, &certificate.raw.repeat(MAX_CERTIFICATES + 1));
        assert!(catalog_envelope(&replace_body(bag, &oversized)).is_err());
    }

    #[test]
    fn catalog_signer_certificate_identity_is_not_chosen_from_ambiguous_candidates() {
        let outer = root().children().collect::<Result<Vec<_>, _>>().expect("ContentInfo");
        let fields =
            outer[1].children().expect(TAG_SEQUENCE).expect("SignedData").children().collect::<Result<Vec<_>, _>>().expect("fields");
        let bag = fields.iter().position(|f| f.tag == 0xa0).expect("certificate bag");
        let certificate = fields[bag].children().any().expect("certificate");
        let duplicated = tlv(0xa0, &certificate.raw.repeat(2));
        let (_, signatures) = catalog_envelope(&replace_body(bag, &duplicated)).expect("identical embedded certificates");
        assert_eq!(signatures[0]["signer_certificate_candidates"], 1);
        assert_eq!(signatures[0]["checks"]["signature"], "passed");
        let mut changed = certificate.raw.to_vec();
        *changed.last_mut().expect("certificate signature") ^= 1;
        let ambiguous = tlv(0xa0, &[certificate.raw, &changed].concat());
        let (_, signatures) = catalog_envelope(&replace_body(bag, &ambiguous)).expect("ambiguous embedded certificate identity");
        assert_eq!(signatures[0]["signer_certificate_candidates"], 2);
        assert!(signatures[0]["signer"].is_null());
        assert!(signatures[0]["checks"]["algorithms"]["not_checked"].as_str().expect("ambiguity reason").contains("ambiguous"));
    }
}
