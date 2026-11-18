//! The APK Signing Block: signature schemes v2, v3 and v3.1, verified.
//!
//! What "verified" covers, per signer: (1) the content digests in the signed data equal the
//! digests recomputed over the file (1 MiB chunks over the entries section, the central
//! directory, and the end record with its central-directory offset pointing at the block);
//! (2) every signature of a supported algorithm verifies over the signed data with the signer's
//! public key; (3) that key is the key of the signer's first certificate. This is what Android
//! does at install, minus trust decisions that need a device (rollback of a newer install).

use sha2::Digest;

use crate::crypto::{self, Hash, Outcome, Scheme};
use crate::reader::{Reader, slice_at, u32_at, u64_at};
use crate::x509::{self, Certificate};
use crate::zipraw::Archive;

pub const MAGIC: &[u8; 16] = b"APK Sig Block 42";
pub const ID_V2: u32 = 0x7109_871a;
pub const ID_V3: u32 = 0xf053_68c0;
pub const ID_V31: u32 = 0x1b93_ad61;
const ATTR_STRIPPING_PROTECTION: u32 = 0xbeef_f00d;
const ATTR_PROOF_OF_ROTATION: u32 = 0x3ba0_6f8c;
const ATTR_ROTATION_MIN_SDK: u32 = 0x559f_8b02;
const ATTR_ROTATION_ON_DEV_RELEASE: u32 = 0xc2a6_b3ba;
const CHUNK: usize = 1024 * 1024;
const MAX_SIGNERS: usize = 16;
const MAX_ITEMS: usize = 64;

/// What a block id is known to hold.
pub fn block_name(id: u32) -> &'static str {
    match id {
        ID_V2 => "APK Signature Scheme v2",
        ID_V3 => "APK Signature Scheme v3",
        ID_V31 => "APK Signature Scheme v3.1",
        0x6dff_800d => "source stamp v2",
        0x2b09_189e => "source stamp v1",
        0x4272_6577 => "verity padding",
        0x2146_444e => "Google Play frosting (metadata added by Google Play)",
        0x504b_4453 => "dependency info (written by the Android Gradle plugin)",
        0x7177_7777 => "channel block (Meituan Walle and similar tools)",
        _ => "",
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block<'a> {
    /// Offset of the block's first size field.
    pub start: u64,
    /// Size of the whole block, both size fields and magic included.
    pub size: u64,
    pub pairs: Vec<(u32, &'a [u8], u64)>,
}

/// Why no usable signing block was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Absent {
    /// There is no block magic before the central directory.
    None,
    /// A block magic is there, but its structure is broken; the text says how.
    Malformed(String),
}

pub fn find<'a>(data: &'a [u8], archive: &Archive) -> Result<Block<'a>, Absent> {
    let Ok(cd) = usize::try_from(archive.cd_offset) else { return Err(Absent::None) };
    if cd < 32 || slice_at(data, cd - 16, 16) != Some(MAGIC) {
        return Err(Absent::None);
    }
    let malformed = |why: &str| Absent::Malformed(why.to_string());
    let footer_size = u64_at(data, cd - 24).ok_or_else(|| malformed("size field is cut short"))?;
    let total = footer_size.checked_add(8).ok_or_else(|| malformed("size overflows"))?;
    if footer_size < 24 || total > cd as u64 {
        return Err(malformed("size field points outside the file"));
    }
    let start = cd - total as usize;
    if u64_at(data, start) != Some(footer_size) {
        return Err(malformed("the two size fields differ"));
    }
    let mut pairs = Vec::new();
    let body = &data[start + 8..cd - 24];
    let mut reader = Reader::new(body);
    while !reader.is_empty() {
        let Some(length) = reader.u64() else { return Err(malformed("id-value pair is cut short")) };
        let Ok(length) = usize::try_from(length) else { return Err(malformed("id-value pair is too long")) };
        let offset = (start + 8 + reader.pos) as u64;
        let Some(pair) = reader.bytes(length) else { return Err(malformed("id-value pair runs past the block")) };
        let Some(id) = u32_at(pair, 0) else { return Err(malformed("id-value pair has no id")) };
        if pairs.len() >= 4096 {
            return Err(malformed("too many id-value pairs"));
        }
        pairs.push((id, &pair[4..], offset + 4));
    }
    Ok(Block { start: start as u64, size: total, pairs })
}

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Passed,
    Failed(String),
    NotChecked(String),
}

impl Check {
    pub fn as_str(&self) -> &'static str {
        match self {
            Check::Passed => "passed",
            Check::Failed(_) => "failed",
            Check::NotChecked(_) => "not_checked",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Check::Passed => None,
            Check::Failed(d) | Check::NotChecked(d) => Some(d),
        }
    }

    pub fn passed(&self) -> bool {
        matches!(self, Check::Passed)
    }

    pub fn failed(&self) -> bool {
        matches!(self, Check::Failed(_))
    }
}

/// A signature algorithm id of the v2/v3 schemes.
pub fn algorithm(id: u32) -> Option<(&'static str, Option<Scheme>, ContentDigest)> {
    Some(match id {
        0x0101 => ("RSASSA-PSS with SHA2-256", Some(Scheme::RsaPss(Hash::Sha256)), ContentDigest::ChunkedSha256),
        0x0102 => ("RSASSA-PSS with SHA2-512", Some(Scheme::RsaPss(Hash::Sha512)), ContentDigest::ChunkedSha512),
        0x0103 => ("RSASSA-PKCS1-v1_5 with SHA2-256", Some(Scheme::RsaPkcs1(Hash::Sha256)), ContentDigest::ChunkedSha256),
        0x0104 => ("RSASSA-PKCS1-v1_5 with SHA2-512", Some(Scheme::RsaPkcs1(Hash::Sha512)), ContentDigest::ChunkedSha512),
        0x0201 => ("ECDSA with SHA2-256", Some(Scheme::Ecdsa(Hash::Sha256)), ContentDigest::ChunkedSha256),
        0x0202 => ("ECDSA with SHA2-512", Some(Scheme::Ecdsa(Hash::Sha512)), ContentDigest::ChunkedSha512),
        0x0301 => ("DSA with SHA2-256", Some(Scheme::Dsa(Hash::Sha256)), ContentDigest::ChunkedSha256),
        0x0421 => ("RSASSA-PKCS1-v1_5 with SHA2-256 (verity digest)", Some(Scheme::RsaPkcs1(Hash::Sha256)), ContentDigest::Verity),
        0x0423 => ("ECDSA with SHA2-256 (verity digest)", Some(Scheme::Ecdsa(Hash::Sha256)), ContentDigest::Verity),
        0x0425 => ("DSA with SHA2-256 (verity digest)", Some(Scheme::Dsa(Hash::Sha256)), ContentDigest::Verity),
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContentDigest {
    ChunkedSha256,
    ChunkedSha512,
    /// fs-verity Merkle tree root; not recomputed here.
    Verity,
}

/// One step of a v3 key rotation history.
#[derive(Debug, Clone, PartialEq)]
pub struct LineageNode {
    pub certificate: Option<Certificate>,
    pub flags: u32,
    /// Whether the previous key's signature over this node verifies. `None` for the first node.
    pub signed_by_previous: Option<Check>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Signer {
    pub certificates: Vec<Certificate>,
    /// Certificates that could not be parsed.
    pub unparsed_certificates: usize,
    /// Names of the signature algorithms present.
    pub algorithms: Vec<String>,
    pub min_sdk: Option<u32>,
    pub max_sdk: Option<u32>,
    pub digest: Check,
    pub signature: Check,
    /// Structural problems apksigner also rejects (key/certificate mismatch and the like).
    pub problems: Vec<String>,
    pub lineage: Vec<LineageNode>,
    /// The v2 attribute saying the APK was also signed with a newer scheme.
    pub stripping_protection: Option<u32>,
    pub rotation_min_sdk: Option<u32>,
    pub additional_attributes: Vec<u32>,
}

impl Signer {
    pub fn verified(&self) -> bool {
        self.digest.passed() && self.signature.passed() && self.problems.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SchemeResult {
    pub id: u32,
    pub signers: Vec<Signer>,
    /// Set when the scheme's block could not be parsed at all.
    pub malformed: Option<String>,
    /// Offset of the scheme's value in the file.
    pub offset: u64,
}

impl SchemeResult {
    pub fn name(&self) -> &'static str {
        match self.id {
            ID_V2 => "v2",
            ID_V3 => "v3",
            _ => "v3.1",
        }
    }

    pub fn verified(&self) -> bool {
        self.malformed.is_none() && !self.signers.is_empty() && self.signers.iter().all(Signer::verified)
    }
}

/// Recomputes the content digests of the file as the v2+ schemes define them.
pub struct ContentDigests<'a> {
    data: &'a [u8],
    block_start: usize,
    cd: usize,
    eocd: usize,
    sha256: Option<Vec<u8>>,
    sha512: Option<Vec<u8>>,
}

impl<'a> ContentDigests<'a> {
    pub fn new(data: &'a [u8], archive: &Archive, block_start: u64) -> Option<Self> {
        let (block_start, cd, eocd) =
            (usize::try_from(block_start).ok()?, usize::try_from(archive.cd_offset).ok()?, usize::try_from(archive.eocd_offset).ok()?);
        (block_start <= cd && cd <= eocd && eocd + 22 <= data.len()).then_some(ContentDigests {
            data,
            block_start,
            cd,
            eocd,
            sha256: None,
            sha512: None,
        })
    }

    fn compute<D: Digest>(&self) -> Vec<u8> {
        // The end record as the verifier sees it: its central-directory offset points at the block.
        let mut eocd = self.data[self.eocd..].to_vec();
        eocd[16..20].copy_from_slice(&(self.block_start as u32).to_le_bytes());
        let sections: [&[u8]; 3] = [&self.data[..self.block_start], &self.data[self.cd..self.eocd], &eocd];
        let chunk_count: usize = sections.iter().map(|s| s.len().div_ceil(CHUNK)).sum();
        let mut top = D::new();
        top.update([0x5a]);
        top.update((chunk_count as u32).to_le_bytes());
        for section in sections {
            for chunk in section.chunks(CHUNK) {
                let mut hasher = D::new();
                hasher.update([0xa5]);
                hasher.update((chunk.len() as u32).to_le_bytes());
                hasher.update(chunk);
                top.update(hasher.finalize());
            }
        }
        top.finalize().to_vec()
    }

    pub fn get(&mut self, kind: ContentDigest) -> Option<&[u8]> {
        match kind {
            ContentDigest::ChunkedSha256 => {
                if self.sha256.is_none() {
                    self.sha256 = Some(self.compute::<sha2::Sha256>());
                }
                self.sha256.as_deref()
            }
            ContentDigest::ChunkedSha512 => {
                if self.sha512.is_none() {
                    self.sha512 = Some(self.compute::<sha2::Sha512>());
                }
                self.sha512.as_deref()
            }
            ContentDigest::Verity => None,
        }
    }
}

fn lp_items(data: &[u8]) -> Option<Vec<&[u8]>> {
    let mut reader = Reader::new(data);
    let mut items = Vec::new();
    while !reader.is_empty() {
        if items.len() >= MAX_ITEMS {
            return None;
        }
        items.push(reader.lp32()?);
    }
    Some(items)
}

/// Verifies every `(algorithm id, signature)` over `message` with `public_key`.
fn check_signatures(signatures: &[(u32, &[u8])], public_key: &[u8], message: &[u8]) -> Check {
    if signatures.is_empty() {
        return Check::Failed("the signer has no signatures".into());
    }
    let mut verified = 0;
    let mut unsupported = Vec::new();
    for (id, signature) in signatures {
        let Some((name, Some(scheme), _)) = algorithm(*id) else {
            unsupported.push(format!("algorithm 0x{id:04x} is unknown"));
            continue;
        };
        match crypto::verify(public_key, scheme, message, signature) {
            Outcome::Valid => verified += 1,
            Outcome::Invalid => return Check::Failed(format!("the {name} signature does not verify")),
            Outcome::Unsupported(why) => unsupported.push(why),
        }
    }
    if verified > 0 { Check::Passed } else { Check::NotChecked(unsupported.join("; ")) }
}

fn parse_lineage(value: &[u8]) -> Option<Vec<LineageNode>> {
    let mut reader = Reader::new(value);
    let _version = reader.u32()?;
    let mut nodes: Vec<LineageNode> = Vec::new();
    let mut previous: Option<(Vec<u8>, u32)> = None; // (public key, algorithm it signs the next node with)
    while !reader.is_empty() {
        if nodes.len() >= MAX_ITEMS {
            return None;
        }
        let mut node = Reader::new(reader.lp32()?);
        let signed = node.lp32()?;
        let flags = node.u32()?;
        let next_algorithm = node.u32()?;
        let signature = node.lp32()?;
        let mut signed_reader = Reader::new(signed);
        let encoded = signed_reader.lp32()?;
        let signed_algorithm = signed_reader.u32()?;
        let certificate = x509::parse(encoded);
        let signed_by_previous = previous.as_ref().map(|(key, algorithm_id)| {
            if *algorithm_id != signed_algorithm {
                return Check::Failed("the algorithm in the signed data differs from the one the previous node names".into());
            }
            check_signatures(&[(*algorithm_id, signature)], key, signed)
        });
        previous = certificate.as_ref().map(|c| (c.spki.clone(), next_algorithm));
        nodes.push(LineageNode { certificate, flags, signed_by_previous });
        if previous.is_none() {
            break;
        }
    }
    Some(nodes)
}

fn parse_signer(raw: &[u8], v3: bool, digests: &mut Option<ContentDigests>) -> Option<Signer> {
    let mut reader = Reader::new(raw);
    let signed_data = reader.lp32()?;
    let (min_sdk, max_sdk) = if v3 { (Some(reader.u32()?), Some(reader.u32()?)) } else { (None, None) };
    let signatures_raw = reader.lp32()?;
    let public_key = reader.lp32()?;

    let mut signatures = Vec::new();
    for item in lp_items(signatures_raw)? {
        let mut r = Reader::new(item);
        signatures.push((r.u32()?, r.lp32()?));
    }
    let mut signed = Reader::new(signed_data);
    let digests_raw = signed.lp32()?;
    let certificates_raw = signed.lp32()?;
    let signed_sdks = if v3 { Some((signed.u32()?, signed.u32()?)) } else { None };
    // Attributes are optional at the end of v2 signed data written by old tools.
    let attributes_raw = if signed.is_empty() { &[][..] } else { signed.lp32()? };

    let mut problems = Vec::new();
    let mut content = Vec::new();
    for item in lp_items(digests_raw)? {
        let mut r = Reader::new(item);
        content.push((r.u32()?, r.lp32()?));
    }
    let mut certificates = Vec::new();
    let mut unparsed_certificates = 0;
    let mut first_key: Option<Vec<u8>> = None;
    for (index, encoded) in lp_items(certificates_raw)?.into_iter().enumerate() {
        match x509::parse(encoded) {
            Some(certificate) => {
                if index == 0 {
                    first_key = Some(certificate.spki.clone());
                }
                certificates.push(certificate);
            }
            None => unparsed_certificates += 1,
        }
    }
    if certificates.is_empty() && unparsed_certificates == 0 {
        problems.push("the signer has no certificates".into());
    } else if first_key.as_deref() != Some(public_key) {
        problems.push("the signer's public key is not the key of its first certificate".into());
    }
    let signature_ids: Vec<u32> = signatures.iter().map(|(id, _)| *id).collect();
    let digest_ids: Vec<u32> = content.iter().map(|(id, _)| *id).collect();
    if signature_ids != digest_ids {
        problems.push("the algorithms of the signatures and of the digests differ".into());
    }
    if let (Some((signed_min, signed_max)), Some(min), Some(max)) = (signed_sdks, min_sdk, max_sdk)
        && (signed_min != min || signed_max != max)
    {
        problems.push("the SDK range in the signed data differs from the signer's".into());
    }

    let mut lineage = Vec::new();
    let mut stripping_protection = None;
    let mut rotation_min_sdk = None;
    let mut additional_attributes = Vec::new();
    for item in lp_items(attributes_raw).unwrap_or_default() {
        let Some(id) = u32_at(item, 0) else { continue };
        let value = &item[4..];
        additional_attributes.push(id);
        match id {
            ATTR_STRIPPING_PROTECTION => stripping_protection = u32_at(value, 0),
            ATTR_ROTATION_MIN_SDK => rotation_min_sdk = u32_at(value, 0),
            ATTR_ROTATION_ON_DEV_RELEASE => {}
            ATTR_PROOF_OF_ROTATION => match parse_lineage(value) {
                Some(nodes) => {
                    if nodes.iter().any(|n| n.signed_by_previous.as_ref().is_some_and(Check::failed)) {
                        problems.push("a link of the key rotation history does not verify".into());
                    }
                    let last = nodes.last().and_then(|n| n.certificate.as_ref()).map(|c| c.sha256.clone());
                    if last != certificates.first().map(|c| c.sha256.clone()) {
                        problems.push("the key rotation history does not end at the signing certificate".into());
                    }
                    lineage = nodes;
                }
                None => problems.push("the key rotation history is malformed".into()),
            },
            _ => {}
        }
    }

    // Content digests: every digest of a known kind must equal the recomputed one.
    let mut digest = Check::NotChecked("no digest of a supported kind".into());
    for (id, expected) in &content {
        let Some((_, _, kind)) = algorithm(*id) else { continue };
        if kind == ContentDigest::Verity {
            if !digest.passed() {
                digest = Check::NotChecked("only an fs-verity digest is present; it is not recomputed".into());
            }
            continue;
        }
        match digests.as_mut().and_then(|d| d.get(kind)) {
            Some(actual) if actual == *expected => {
                if !digest.failed() {
                    digest = Check::Passed;
                }
            }
            Some(actual) => {
                digest = Check::Failed(format!(
                    "the file's {} digest is {}, the signed data says {}",
                    if kind == ContentDigest::ChunkedSha256 { "chunked SHA-256" } else { "chunked SHA-512" },
                    hex::encode(actual),
                    hex::encode(&expected[..expected.len().min(64)])
                ));
            }
            None => digest = Check::NotChecked("the file layout does not allow recomputing the digest".into()),
        }
    }
    let signature = check_signatures(&signatures, public_key, signed_data);
    let algorithms = signatures
        .iter()
        .map(|(id, _)| algorithm(*id).map(|(name, _, _)| name.to_string()).unwrap_or_else(|| format!("unknown 0x{id:04x}")))
        .collect();
    Some(Signer {
        certificates,
        unparsed_certificates,
        algorithms,
        min_sdk,
        max_sdk,
        digest,
        signature,
        problems,
        lineage,
        stripping_protection,
        rotation_min_sdk,
        additional_attributes,
    })
}

/// Parses and verifies one scheme's value from the signing block.
pub fn verify_scheme(id: u32, value: &[u8], offset: u64, digests: &mut Option<ContentDigests>) -> SchemeResult {
    let mut result = SchemeResult { id, signers: Vec::new(), malformed: None, offset };
    let signers = Reader::new(value).lp32().and_then(lp_items);
    let Some(signers) = signers else {
        result.malformed = Some("the signer list is malformed".into());
        return result;
    };
    if signers.is_empty() {
        result.malformed = Some("no signers".into());
    }
    for raw in signers.into_iter().take(MAX_SIGNERS) {
        match parse_signer(raw, id != ID_V2, digests) {
            Some(signer) => result.signers.push(signer),
            None => {
                result.malformed = Some("a signer is malformed".into());
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zipraw;

    fn with_block(pairs: &[(u32, &[u8])]) -> Vec<u8> {
        let zip = zipraw::tests::build_zip(b"", &[("a", b"data")]);
        let archive = zipraw::parse(&zip).expect("zip");
        let cd = archive.cd_offset as usize;
        let mut body = Vec::new();
        for (id, value) in pairs {
            body.extend_from_slice(&((value.len() + 4) as u64).to_le_bytes());
            body.extend_from_slice(&id.to_le_bytes());
            body.extend_from_slice(value);
        }
        let size = (body.len() + 24) as u64;
        let mut block = size.to_le_bytes().to_vec();
        block.extend(body);
        block.extend_from_slice(&size.to_le_bytes());
        block.extend_from_slice(MAGIC);
        let mut out = zip[..cd].to_vec();
        out.extend(&block);
        out.extend(&zip[cd..]);
        // Fix the central directory offset in the end record.
        let eocd = out.len() - 22;
        out[eocd + 16..eocd + 20].copy_from_slice(&((cd + block.len()) as u32).to_le_bytes());
        out
    }

    #[test]
    fn finds_the_block_and_its_pairs() {
        let apk = with_block(&[(ID_V2, &[1, 2, 3]), (0x4272_6577, &[0; 8])]);
        let archive = zipraw::parse(&apk).expect("zip");
        let block = find(&apk, &archive).expect("block");
        assert_eq!(block.pairs.len(), 2);
        assert_eq!(block.pairs[0].0, ID_V2);
        assert_eq!(block.pairs[0].1, &[1, 2, 3]);
        assert_eq!(block.start + block.size, archive.cd_offset);
        let plain = zipraw::tests::build_zip(b"", &[("a", b"data")]);
        assert_eq!(find(&plain, &zipraw::parse(&plain).expect("zip")), Err(Absent::None));
    }

    #[test]
    fn malformed_blocks_are_reported_not_trusted() {
        let apk = with_block(&[(ID_V2, &[1, 2, 3])]);
        let archive = zipraw::parse(&apk).expect("zip");
        let block = find(&apk, &archive).expect("block");
        let start = block.start as usize;
        // Break the first size field, then a pair length.
        let mut bad = apk.clone();
        bad[start] ^= 1;
        assert!(matches!(find(&bad, &archive), Err(Absent::Malformed(_))));
        let mut bad = apk.clone();
        bad[start + 8..start + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(find(&bad, &archive), Err(Absent::Malformed(_))));
        // A v2 value of garbage gives a malformed scheme, not a panic.
        let mut none = None;
        for value in [&[][..], &[0xff; 3], &[0xff; 64], &[4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]] {
            let result = verify_scheme(ID_V2, value, 0, &mut none);
            assert!(result.malformed.is_some());
            assert!(!result.verified());
        }
        for v in [0u8, 0xff] {
            for i in 0..apk.len() {
                let mut bad = apk.clone();
                bad[i] = v;
                if let Some(archive) = zipraw::parse(&bad)
                    && let Ok(block) = find(&bad, &archive)
                {
                    let mut digests = ContentDigests::new(&bad, &archive, block.start);
                    for (id, value, offset) in &block.pairs {
                        let _ = verify_scheme(*id, value, *offset, &mut digests);
                    }
                }
            }
        }
    }

    #[test]
    fn lineage_parser_is_bounded() {
        assert!(parse_lineage(&[]).is_none());
        assert!(parse_lineage(&[1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f]).is_none());
        assert_eq!(parse_lineage(&[1, 0, 0, 0]).map(|n| n.len()), Some(0));
    }
}
