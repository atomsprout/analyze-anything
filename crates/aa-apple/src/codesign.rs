//! Embedded code signatures: the SuperBlob a Mach-O's `LC_CODE_SIGNATURE` points at, its code
//! directories, entitlements, requirements and CMS signature, and the checks that can be made
//! from the file alone.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::certs::{self, Hash, SignatureCheck};
use crate::util::{be32, be64, slice};

const MAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const MAGIC_CODE_DIRECTORY: u32 = 0xfade_0c02;
const MAGIC_REQUIREMENTS: u32 = 0xfade_0c01;
const MAGIC_ENTITLEMENTS: u32 = 0xfade_7171;
const MAGIC_ENTITLEMENTS_DER: u32 = 0xfade_7172;
const MAGIC_BLOB_WRAPPER: u32 = 0xfade_0b01;

pub const SLOT_CODE_DIRECTORY: u32 = 0;
pub const SLOT_INFO_PLIST: u32 = 1;
pub const SLOT_REQUIREMENTS: u32 = 2;
pub const SLOT_RESOURCES: u32 = 3;
pub const SLOT_ENTITLEMENTS: u32 = 5;
pub const SLOT_ENTITLEMENTS_DER: u32 = 7;
const SLOT_ALTERNATE_DIRECTORIES: u32 = 0x1000;
const SLOT_ALTERNATE_LIMIT: u32 = 0x1005;
const SLOT_CMS: u32 = 0x10000;

const MAX_BLOBS: u32 = 64;
/// Mismatching pages listed by index before only the count is kept.
const LISTED_PAGES: usize = 8;

pub const FLAG_ADHOC: u32 = 0x2;
pub const FLAG_RUNTIME: u32 = 0x1_0000;
pub const FLAG_LINKER_SIGNED: u32 = 0x2_0000;
const FLAGS: &[(u32, &str)] = &[
    (0x1, "host"),
    (0x2, "adhoc"),
    (0x100, "hard"),
    (0x200, "kill"),
    (0x400, "expires"),
    (0x800, "restrict"),
    (0x1000, "enforcement"),
    (0x2000, "library-validation"),
    (0x1_0000, "runtime"),
    (0x2_0000, "linker-signed"),
];

/// The names of the flags set in a code directory, as `codesign` prints them.
pub fn flag_names(flags: u32) -> Vec<&'static str> {
    FLAGS.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, name)| *name).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeDirectory {
    pub slot: u32,
    /// The whole blob, header included: what the CMS signature and the cdhash cover.
    pub blob: (usize, usize),
    pub version: u32,
    pub flags: u32,
    pub identifier: String,
    pub team_id: Option<String>,
    pub hash: Hash,
    pub hash_size: usize,
    /// Truncated SHA-256, which still counts as SHA-256 here.
    pub truncated_hash: bool,
    pub hash_offset: usize,
    pub special_slots: u32,
    pub code_slots: u32,
    pub code_limit: u64,
    /// Bytes per page; zero means one hash covers everything.
    pub page_size: u64,
    pub platform: u8,
    pub exec_segment_flags: Option<u64>,
    /// Minimum runtime version, set with the hardened runtime.
    pub runtime_version: Option<u32>,
    /// The first 20 bytes of the blob's hash: the identity of the code.
    pub cdhash: Vec<u8>,
}

/// The outcome of comparing page hashes with the file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PageCheck {
    pub pages: u32,
    pub checked: u32,
    pub mismatched: u32,
    /// Pages left out because they overlap a FairPlay-encrypted range.
    pub skipped: u32,
    pub first_mismatches: Vec<u32>,
    /// Set when the check could not run at all.
    pub error: Option<String>,
}

/// The outcome of comparing one special slot with what it should cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotCheck {
    Match,
    Mismatch,
    /// The directory has no hash for the slot (or all zeros), though the data exists.
    Unbound,
    /// The directory has a hash but the data it covers is not there.
    DataMissing,
}

impl SlotCheck {
    pub fn label(self) -> &'static str {
        match self {
            SlotCheck::Match => "match",
            SlotCheck::Mismatch => "mismatch",
            SlotCheck::Unbound => "unbound",
            SlotCheck::DataMissing => "data-missing",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Signature<'a> {
    bytes: &'a [u8],
    /// Slot -> `(magic, offset, length)` of each blob.
    pub blobs: BTreeMap<u32, (u32, usize, usize)>,
    /// The primary directory first, then the alternates.
    pub directories: Vec<CodeDirectory>,
}

fn code_directory(bytes: &[u8], slot: u32, offset: usize, length: usize) -> Result<CodeDirectory, String> {
    let blob = slice(bytes, offset, length).ok_or("the code directory lies outside the signature")?;
    let short = || "the code directory is truncated".to_string();
    let word = |at: usize| be32(blob, at).ok_or_else(short);
    let version = word(8)?;
    let flags = word(12)?;
    let hash_offset = word(16)? as usize;
    let ident_offset = word(20)? as usize;
    let special_slots = word(24)?;
    let code_slots = word(28)?;
    let mut code_limit = word(32)? as u64;
    let sizes = slice(blob, 36, 4).ok_or_else(short)?;
    let (hash_size, hash_type, platform, page_shift) = (sizes[0] as usize, sizes[1], sizes[2], sizes[3]);
    let (hash, truncated_hash) = match hash_type {
        1 => (Hash::Sha1, false),
        2 => (Hash::Sha256, false),
        3 => (Hash::Sha256, true),
        4 => (Hash::Sha384, false),
        other => return Err(format!("code directory hash type {other} is not known")),
    };
    let expected = match (hash, truncated_hash) {
        (Hash::Sha1, _) | (_, true) => 20,
        (Hash::Sha256, _) => 32,
        (Hash::Sha384, _) => 48,
        (Hash::Sha512, _) => 64,
    };
    if hash_size != expected {
        return Err(format!("code directory hash size {hash_size} does not fit its hash type"));
    }
    if page_shift > 30 {
        return Err(format!("code directory page size 2^{page_shift} is not valid"));
    }
    let text = |at: usize| -> Option<String> { blob.get(at..).filter(|rest| rest.contains(&0)).map(crate::util::c_string) };
    let identifier = text(ident_offset).ok_or("the code directory's identifier is out of range")?;
    let team_id = if version >= 0x20200 { Some(word(48)? as usize).filter(|at| *at != 0).and_then(text) } else { None };
    if version >= 0x20300
        && let Some(limit) = be64(blob, 56).filter(|limit| *limit != 0)
    {
        code_limit = limit;
    }
    let exec_segment_flags = if version >= 0x20400 { be64(blob, 80) } else { None };
    let runtime_version = if version >= 0x20500 { be32(blob, 88).filter(|v| *v != 0) } else { None };
    // Every hash the directory claims must lie inside the blob.
    let special_bytes = (special_slots as usize).checked_mul(hash_size).ok_or_else(short)?;
    let code_bytes = (code_slots as usize).checked_mul(hash_size).ok_or_else(short)?;
    if hash_offset < special_bytes || hash_offset.checked_add(code_bytes).is_none_or(|end| end > blob.len()) {
        return Err("the code directory's hash slots lie outside it".into());
    }
    let mut cdhash = hash.digest(blob);
    cdhash.truncate(20);
    Ok(CodeDirectory {
        slot,
        blob: (offset, length),
        version,
        flags,
        identifier,
        team_id,
        hash,
        hash_size,
        truncated_hash,
        hash_offset,
        special_slots,
        code_slots,
        code_limit,
        page_size: if page_shift == 0 { 0 } else { 1u64 << page_shift },
        platform,
        exec_segment_flags,
        runtime_version,
        cdhash,
    })
}

/// Parses the signature SuperBlob in `bytes` (the range `LC_CODE_SIGNATURE` names).
pub fn parse(bytes: &[u8]) -> Result<Signature<'_>, String> {
    if be32(bytes, 0) != Some(MAGIC_EMBEDDED_SIGNATURE) {
        return Err("the signature does not start with the embedded-signature magic".into());
    }
    let short = || "the signature is truncated".to_string();
    let length = be32(bytes, 4).ok_or_else(short)? as usize;
    let count = be32(bytes, 8).ok_or_else(short)?;
    if length > bytes.len() || count > MAX_BLOBS {
        return Err(format!("the signature claims {length} bytes and {count} blobs"));
    }
    let bytes = &bytes[..length];
    let mut blobs = BTreeMap::new();
    for index in 0..count as usize {
        let slot = be32(bytes, 12 + index * 8).ok_or_else(short)?;
        let offset = be32(bytes, 16 + index * 8).ok_or_else(short)? as usize;
        let magic = be32(bytes, offset).ok_or_else(|| format!("blob {index} lies outside the signature"))?;
        let size = be32(bytes, offset + 4).ok_or_else(short)? as usize;
        if size < 8 || slice(bytes, offset, size).is_none() {
            return Err(format!("blob {index} lies outside the signature"));
        }
        blobs.insert(slot, (magic, offset, size));
    }
    let mut directories = Vec::new();
    for (&slot, &(magic, offset, size)) in &blobs {
        let is_directory_slot = slot == SLOT_CODE_DIRECTORY || (SLOT_ALTERNATE_DIRECTORIES..SLOT_ALTERNATE_LIMIT).contains(&slot);
        if is_directory_slot && magic == MAGIC_CODE_DIRECTORY {
            directories.push(code_directory(bytes, slot, offset, size)?);
        }
    }
    if directories.first().is_none_or(|d| d.slot != SLOT_CODE_DIRECTORY) {
        return Err("the signature has no code directory".into());
    }
    Ok(Signature { bytes, blobs, directories })
}

impl<'a> Signature<'a> {
    /// The whole blob in `slot`, header included.
    pub fn blob(&self, slot: u32) -> Option<&'a [u8]> {
        let &(_, offset, size) = self.blobs.get(&slot)?;
        slice(self.bytes, offset, size)
    }

    fn payload(&self, slot: u32, magic: u32) -> Option<&'a [u8]> {
        let &(found, offset, size) = self.blobs.get(&slot)?;
        if found != magic {
            return None;
        }
        slice(self.bytes, offset + 8, size - 8)
    }

    /// The directory with the strongest hash: the one `codesign` names the cdhash after.
    pub fn best(&self) -> &CodeDirectory {
        let rank = |d: &CodeDirectory| match (d.hash, d.truncated_hash) {
            (Hash::Sha1, _) => 1,
            (Hash::Sha256, true) => 2,
            (Hash::Sha256, false) => 3,
            (Hash::Sha384, _) => 4,
            (Hash::Sha512, _) => 5,
        };
        self.directories.iter().max_by_key(|d| rank(d)).unwrap_or(&self.directories[0])
    }

    /// The entitlements property list (XML), as stored.
    pub fn entitlements_xml(&self) -> Option<&'a [u8]> {
        self.payload(SLOT_ENTITLEMENTS, MAGIC_ENTITLEMENTS)
    }

    pub fn entitlements_der(&self) -> Option<&'a [u8]> {
        self.payload(SLOT_ENTITLEMENTS_DER, MAGIC_ENTITLEMENTS_DER)
    }

    /// The requirements blob: `(number of requirements, size in bytes)`.
    pub fn requirements(&self) -> Option<(u32, usize)> {
        let payload = self.payload(SLOT_REQUIREMENTS, MAGIC_REQUIREMENTS)?;
        Some((be32(payload, 0)?, payload.len() + 8))
    }

    /// The CMS signature in DER; `None` when there is none or it is empty (ad-hoc).
    pub fn cms(&self) -> Option<&'a [u8]> {
        self.payload(SLOT_CMS, MAGIC_BLOB_WRAPPER).filter(|payload| !payload.is_empty())
    }

    fn directory_blob(&self, directory: &CodeDirectory) -> &'a [u8] {
        slice(self.bytes, directory.blob.0, directory.blob.1).unwrap_or_default()
    }

    /// The stored hash of special slot `slot` (1 = Info.plist, …); `None` when the directory
    /// has no such slot or it is all zeros.
    pub fn special_hash(&self, directory: &CodeDirectory, slot: u32) -> Option<&'a [u8]> {
        if slot == 0 || slot > directory.special_slots {
            return None;
        }
        let at = directory.hash_offset.checked_sub(slot as usize * directory.hash_size)?;
        slice(self.directory_blob(directory), at, directory.hash_size).filter(|hash| hash.iter().any(|b| *b != 0))
    }

    /// Compares special slot `slot` of `directory` with `data`, the bytes it should cover.
    pub fn check_special(&self, directory: &CodeDirectory, slot: u32, data: Option<&[u8]>) -> Option<SlotCheck> {
        match (self.special_hash(directory, slot), data) {
            (None, None) => None,
            (None, Some(_)) => Some(SlotCheck::Unbound),
            (Some(_), None) => Some(SlotCheck::DataMissing),
            (Some(stored), Some(data)) => {
                let mut digest = directory.hash.digest(data);
                digest.truncate(directory.hash_size);
                Some(if digest == stored { SlotCheck::Match } else { SlotCheck::Mismatch })
            }
        }
    }

    /// Compares every page hash of `directory` with `code`, the Mach-O slice the signature is
    /// in. Pages overlapping `encrypted` (offset, length) are skipped: on disk they hold
    /// ciphertext, and which form the hashes cover cannot be told from the file.
    pub fn check_pages(&self, directory: &CodeDirectory, code: &[u8], encrypted: Option<(u64, u64)>) -> PageCheck {
        let mut check = PageCheck { pages: directory.code_slots, ..PageCheck::default() };
        if directory.code_limit > code.len() as u64 {
            check.error = Some(format!("the signature covers {} bytes but the file has {}", directory.code_limit, code.len()));
            return check;
        }
        let blob = self.directory_blob(directory);
        let page_size = if directory.page_size == 0 { directory.code_limit.max(1) } else { directory.page_size };
        let needed = directory.code_limit.div_ceil(page_size);
        if needed != directory.code_slots as u64 {
            check.error = Some(format!("{} page hashes for {needed} pages", directory.code_slots));
            return check;
        }
        for page in 0..directory.code_slots {
            let start = page as u64 * page_size;
            let end = (start + page_size).min(directory.code_limit);
            if let Some((from, length)) = encrypted
                && length > 0
                && start < from.saturating_add(length)
                && end > from
            {
                check.skipped += 1;
                continue;
            }
            let (Some(stored), Some(data)) = (
                slice(blob, directory.hash_offset + page as usize * directory.hash_size, directory.hash_size),
                slice(code, start as usize, (end - start) as usize),
            ) else {
                check.error = Some(format!("page {page} is out of range"));
                return check;
            };
            let mut digest = directory.hash.digest(data);
            digest.truncate(directory.hash_size);
            check.checked += 1;
            if digest != stored {
                check.mismatched += 1;
                if check.first_mismatches.len() < LISTED_PAGES {
                    check.first_mismatches.push(page);
                }
            }
        }
        check
    }

    /// Checks the CMS signature against the primary code directory.
    pub fn check_cms(&self) -> Option<Result<SignatureCheck, String>> {
        let der = self.cms()?;
        let primary = self.directory_blob(&self.directories[0]);
        Some(certs::Signed::parse(der).and_then(|signed| signed.check(Some(primary))))
    }
}

/// Converts a property-list value to JSON. Data becomes hex, dates their text form.
pub fn plist_to_json(value: &plist::Value) -> Value {
    match value {
        plist::Value::Array(items) => Value::Array(items.iter().map(plist_to_json).collect()),
        plist::Value::Dictionary(dictionary) => Value::Object(dictionary.iter().map(|(k, v)| (k.clone(), plist_to_json(v))).collect()),
        plist::Value::Boolean(flag) => json!(flag),
        plist::Value::Data(data) => {
            json!({ "data_hex": hex::encode(data.iter().take(64).copied().collect::<Vec<u8>>()), "length": data.len() })
        }
        plist::Value::Date(date) => json!(date.to_xml_format()),
        plist::Value::Real(number) => json!(number),
        plist::Value::Integer(number) => {
            number.as_signed().map(|n| json!(n)).or_else(|| number.as_unsigned().map(|n| json!(n))).unwrap_or(Value::Null)
        }
        plist::Value::String(text) => json!(text),
        plist::Value::Uid(uid) => json!(uid.get()),
        _ => Value::Null,
    }
}

/// One DER element: `(tag, content, rest after it)`.
fn der_element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return None;
        }
        let digits = rest.get(..count)?;
        (digits.iter().fold(0usize, |total, digit| (total << 8) | *digit as usize), &rest[count..])
    };
    Some((tag, rest.get(..length)?, &rest[length..]))
}

fn der_value(tag: u8, content: &[u8], depth: usize) -> Option<Value> {
    if depth > 32 {
        return None;
    }
    Some(match tag {
        0x01 => json!(content.first().is_some_and(|b| *b != 0)),
        0x02 => {
            if content.is_empty() || content.len() > 8 {
                return None;
            }
            let negative = content[0] & 0x80 != 0;
            let value = content.iter().fold(if negative { -1i64 } else { 0 }, |total, byte| (total << 8) | *byte as i64);
            json!(value)
        }
        0x0c => json!(std::str::from_utf8(content).ok()?),
        0x04 => json!({ "data_hex": hex::encode(content.iter().take(64).copied().collect::<Vec<u8>>()), "length": content.len() }),
        // SEQUENCE: an array.
        0x30 => {
            let mut items = Vec::new();
            let mut rest = content;
            while !rest.is_empty() {
                let (tag, inner, next) = der_element(rest)?;
                items.push(der_value(tag, inner, depth + 1)?);
                rest = next;
            }
            Value::Array(items)
        }
        // [16] or SET: a dictionary of SEQUENCE { key, value }.
        0xb0 | 0x31 => {
            let mut map = serde_json::Map::new();
            let mut rest = content;
            while !rest.is_empty() {
                let (tag, pair, next) = der_element(rest)?;
                if tag != 0x30 {
                    return None;
                }
                let (key_tag, key, after_key) = der_element(pair)?;
                let (value_tag, value, _) = der_element(after_key)?;
                if key_tag != 0x0c {
                    return None;
                }
                map.insert(std::str::from_utf8(key).ok()?.to_string(), der_value(value_tag, value, depth + 1)?);
                rest = next;
            }
            Value::Object(map)
        }
        _ => return None,
    })
}

/// Decodes DER entitlements to JSON. Current tools write `APPLICATION 16 { version, [16] { … } }`;
/// older ones wrote the bare `SET` of key-value pairs.
pub fn der_entitlements(bytes: &[u8]) -> Option<Value> {
    let (tag, content, _) = der_element(bytes)?;
    let (tag, dictionary) = match tag {
        0x70 => {
            let (version_tag, _, rest) = der_element(content)?;
            if version_tag != 0x02 {
                return None;
            }
            let (tag, dictionary, _) = der_element(rest)?;
            (tag, dictionary)
        }
        0x31 | 0xb0 => (tag, content),
        _ => return None,
    };
    der_value(tag, dictionary, 0).filter(Value::is_object)
}

#[cfg(test)]
pub(crate) mod tests {
    use sha2::Digest;

    use super::*;

    fn blob(magic: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = magic.to_be_bytes().to_vec();
        out.extend(((payload.len() + 8) as u32).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// An ad-hoc SHA-256 signature over `code` (which must start at offset 0 of the slice),
    /// with an identifier, a team id, entitlements and requirements.
    pub fn sign(code: &[u8], identifier: &str, entitlements: &[u8], flags: u32) -> Vec<u8> {
        let requirements = blob(MAGIC_REQUIREMENTS, &0u32.to_be_bytes());
        let entitlements = blob(MAGIC_ENTITLEMENTS, entitlements);
        let page = 4096usize;
        let pages: Vec<&[u8]> = code.chunks(page).collect();
        let special = 5usize;
        let header = 96usize;
        let ident_at = header;
        let team_at = ident_at + identifier.len() + 1;
        let hash_at = team_at + 5 + special * 32;
        let mut body = Vec::new();
        for value in [0x20500u32, flags, hash_at as u32, ident_at as u32, special as u32, pages.len() as u32, code.len() as u32] {
            body.extend(value.to_be_bytes());
        }
        body.extend([32u8, 2, 0, 12]);
        body.extend(0u32.to_be_bytes()); // spare2
        body.extend(0u32.to_be_bytes()); // scatter
        body.extend((team_at as u32).to_be_bytes());
        body.extend(0u32.to_be_bytes()); // spare3
        body.extend(0u64.to_be_bytes()); // code limit 64
        body.extend([0u8; 24]); // exec segment
        body.extend(0x000a_0000u32.to_be_bytes()); // runtime
        body.extend(0u32.to_be_bytes()); // pre-encrypt offset
        assert_eq!(body.len() + 8, header);
        body.extend_from_slice(identifier.as_bytes());
        body.push(0);
        body.extend_from_slice(b"TEAM\0");
        for slot in (1..=special).rev() {
            match slot {
                2 => body.extend(sha2::Sha256::digest(&requirements)),
                5 => body.extend(sha2::Sha256::digest(&entitlements)),
                _ => body.extend([0u8; 32]),
            }
        }
        for page in pages {
            body.extend(sha2::Sha256::digest(page));
        }
        let directory = blob(MAGIC_CODE_DIRECTORY, &body);
        let parts = [
            (SLOT_CODE_DIRECTORY, directory),
            (SLOT_REQUIREMENTS, requirements),
            (SLOT_ENTITLEMENTS, entitlements),
            (SLOT_CMS, blob(MAGIC_BLOB_WRAPPER, b"")),
        ];
        let mut index = Vec::new();
        let mut data = Vec::new();
        let first = 12 + parts.len() * 8;
        for (slot, part) in &parts {
            index.extend(slot.to_be_bytes());
            index.extend(((first + data.len()) as u32).to_be_bytes());
            data.extend_from_slice(part);
        }
        let mut out = MAGIC_EMBEDDED_SIGNATURE.to_be_bytes().to_vec();
        out.extend(((first + data.len()) as u32).to_be_bytes());
        out.extend((parts.len() as u32).to_be_bytes());
        out.extend(index);
        out.extend(data);
        out
    }

    const ENTITLEMENTS: &[u8] = b"<plist><dict><key>get-task-allow</key><true/></dict></plist>";

    #[test]
    fn parses_and_verifies_a_synthetic_signature() {
        let code: Vec<u8> = (0..10000u32).map(|i| (i % 253) as u8).collect();
        let bytes = sign(&code, "com.example.app", ENTITLEMENTS, FLAG_ADHOC | FLAG_RUNTIME);
        let signature = parse(&bytes).expect("valid");
        let directory = signature.best();
        assert_eq!(directory.identifier, "com.example.app");
        assert_eq!(directory.team_id.as_deref(), Some("TEAM"));
        assert_eq!(flag_names(directory.flags), ["adhoc", "runtime"]);
        assert_eq!(directory.code_slots, 3);
        assert_eq!(directory.cdhash.len(), 20);
        assert_eq!(signature.entitlements_xml(), Some(ENTITLEMENTS));
        assert_eq!(signature.requirements(), Some((0, 12)));
        assert_eq!(signature.cms(), None);
        let pages = signature.check_pages(directory, &code, None);
        assert_eq!((pages.checked, pages.mismatched, pages.error.clone()), (3, 0, None));
        assert_eq!(signature.check_special(directory, SLOT_REQUIREMENTS, signature.blob(SLOT_REQUIREMENTS)), Some(SlotCheck::Match));
        assert_eq!(signature.check_special(directory, SLOT_ENTITLEMENTS, signature.blob(SLOT_ENTITLEMENTS)), Some(SlotCheck::Match));
        assert_eq!(signature.check_special(directory, SLOT_INFO_PLIST, Some(b"x")), Some(SlotCheck::Unbound));
        assert_eq!(signature.check_special(directory, SLOT_ENTITLEMENTS, None), Some(SlotCheck::DataMissing));
        assert_eq!(signature.check_special(directory, SLOT_ENTITLEMENTS, Some(b"other")), Some(SlotCheck::Mismatch));
        assert_eq!(signature.check_special(directory, 9, None), None);

        // One changed byte in the second page is found, and only there.
        let mut tampered = code.clone();
        tampered[5000] ^= 1;
        let pages = signature.check_pages(directory, &tampered, None);
        assert_eq!((pages.mismatched, pages.first_mismatches.clone()), (1, vec![1]));
        // The same page skipped as encrypted is not counted either way.
        let pages = signature.check_pages(directory, &tampered, Some((4096, 100)));
        assert_eq!((pages.checked, pages.mismatched, pages.skipped), (2, 0, 1));
        // A file shorter than the signed range cannot be checked.
        assert!(signature.check_pages(directory, &code[..100], None).error.is_some());
    }

    #[test]
    fn malformed_signatures_are_errors_not_panics() {
        let code = vec![1u8; 5000];
        let bytes = sign(&code, "id", ENTITLEMENTS, 0);
        for cut in 0..bytes.len() {
            assert!(parse(&bytes[..cut]).is_err(), "cut at {cut}");
        }
        // Flip every byte of the header and code-directory header in turn: any outcome but a panic.
        for index in 0..200.min(bytes.len()) {
            for value in [0x00, 0xff, 0x7f] {
                let mut broken = bytes.clone();
                broken[index] = value;
                if let Ok(signature) = parse(&broken) {
                    for directory in &signature.directories {
                        let _ = signature.check_pages(directory, &code, None);
                        for slot in 0..10 {
                            let _ = signature.check_special(directory, slot, Some(b"x"));
                        }
                    }
                    let _ = (signature.entitlements_xml(), signature.requirements(), signature.cms(), signature.check_cms());
                }
            }
        }
        assert!(parse(&[]).is_err());
        assert!(parse(&[0xfa, 0xde, 0x0c, 0xc0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1]).is_err());
    }

    #[test]
    fn der_entitlements_decode() {
        // APPLICATION 16 { INTEGER 1, [16] { SEQ { "a", TRUE }, SEQ { "b", SEQ { "x" } }, SEQ { "n", 5 } } }
        let der = [
            0x70, 0x1f, 0x02, 0x01, 0x01, 0xb0, 0x1a, 0x30, 0x06, 0x0c, 0x01, b'a', 0x01, 0x01, 0xff, 0x30, 0x08, 0x0c, 0x01, b'b', 0x30,
            0x03, 0x0c, 0x01, b'x', 0x30, 0x06, 0x0c, 0x01, b'n', 0x02, 0x01, 0x05,
        ];
        assert_eq!(der_entitlements(&der), Some(json!({ "a": true, "b": ["x"], "n": 5 })));
        for cut in 0..der.len() {
            assert_eq!(der_entitlements(&der[..cut]), None, "cut at {cut}");
        }
        assert_eq!(der_entitlements(&[0x70, 0x84, 0xff, 0xff, 0xff, 0xff]), None);
        // The older form, as kitty 0.36.4 carries it: a bare SET of pairs, booleans as 0x01.
        let old = [0x31, 0x08, 0x30, 0x06, 0x0c, 0x01, b'k', 0x01, 0x01, 0x01];
        assert_eq!(der_entitlements(&old), Some(json!({ "k": true })));
    }
}
