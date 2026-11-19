//! The Authenticode signature of a Windows Installer file (MSI package, MSP patch, MST transform).
//!
//! The signature is a PKCS#7 blob in the root stream `\x05DigitalSignature`. Its
//! `SpcIndirectDataContent` holds a digest of the file computed like this (the algorithm of
//! Windows' MSI subject interface package, as osslsigncode and relic reproduce it):
//!
//! 1. the entries of a storage are sorted by their names as stored (UTF-16LE bytes compared
//!    like `memcmp`, a shorter name before a longer one that starts with it);
//! 2. in that order, the content of every non-empty stream is hashed, and every storage is
//!    hashed the same way, recursively; the two signature streams of the root are left out;
//! 3. after its entries, the CLSID of the storage itself is hashed.
//!
//! When the root also has the stream `\x05MsiDigitalSignatureEx`, the content of that stream
//! is hashed before everything else. It holds a hash of the metadata the content hash does not
//! cover: per entry the name, the size (streams) or CLSID (storages), the state bits and the
//! two timestamps (for the root storage only its CLSID and state bits).
//!
//! One case is not settled. osslsigncode (2.16) does not hash `MsiDigitalSignatureEx` first but
//! where its name sorts among the root's entries. The two readings give the same digest unless
//! a root entry sorts before that name, which the names in real packages almost never do. When
//! they differ and the signed digest matches only one of them, the digest is reported as not
//! checked, with the reason, rather than as matching or as modified.
//!
//! Checked here: the content digest against the signed one, the metadata hash against the
//! `MsiDigitalSignatureEx` stream, and then everything `authenticode` checks for any signature
//! (signed-attribute digest, signature value, embedded chain, timestamps).
//!
//! Outside the hash, and therefore changeable without breaking the signature: the layout of
//! the compound file (sector order, free sectors, slack after short streams, bytes after the
//! last sector), directory entries no storage links to, and, without `MsiDigitalSignatureEx`,
//! the names and timestamps of entries. None of this is inspected here.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::ID;
use crate::authenticode::{self, Check, Hash, Hasher, Signature};
use crate::compound::{self, Compound, Entry, Kind, Node};
use crate::pefile::signature_problems;

const SIGNATURE_STREAM: &str = "\u{5}DigitalSignature";
const METADATA_STREAM: &str = "\u{5}MsiDigitalSignatureEx";
/// How the two streams are named in evidence and messages.
const SIGNATURE_FIELD: &str = "\\x05DigitalSignature stream";
const METADATA_FIELD: &str = "\\x05MsiDigitalSignatureEx stream";
/// Largest signature stream read. Real ones are a few kilobytes.
const MAX_SIGNATURE: u64 = 16 * 1024 * 1024;

/// Root storage CLSIDs of the Windows Installer file types, as stored.
const CLSID_PACKAGE: [u8; 16] = [0x84, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const CLSID_PATCH: [u8; 16] = [0x86, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const CLSID_TRANSFORM: [u8; 16] = [0x82, 0x10, 0x0c, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];

fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, ID, rule, confidence, severity)
}

fn utf16le(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Where the content of `MsiDigitalSignatureEx` goes into the content hash.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MetadataPlace {
    /// The file has no such stream, or it is hashed ahead of the content by the caller.
    Apart,
    /// Hashed like any other stream of the root, where its name sorts.
    InOrder,
}

/// The entries of `storage` in the order they are hashed, without the root's signature streams.
fn hash_order<'n, 'a>(storage: &'n Node<'a>, is_root: bool, place: MetadataPlace) -> Vec<&'n Node<'a>> {
    let (signature, metadata) = (utf16le(SIGNATURE_STREAM), utf16le(METADATA_STREAM));
    let left_out =
        |entry: &Entry| is_root && (entry.name_bytes() == signature || (place == MetadataPlace::Apart && entry.name_bytes() == metadata));
    let mut entries: Vec<&Node> = storage.children.iter().filter(|c| !left_out(&c.entry)).collect();
    entries.sort_by(|a, b| a.entry.name_with_terminator().cmp(b.entry.name_with_terminator()));
    entries
}

fn hash_content(
    file: &Compound,
    storage: &Node,
    is_root: bool,
    place: MetadataPlace,
    hasher: &mut Hasher,
    budget: &mut u64,
) -> Result<(), String> {
    for node in hash_order(storage, is_root, place) {
        match node.entry.kind {
            Kind::Stream if node.entry.size == 0 => {}
            Kind::Stream => {
                // Honest streams do not overlap, so together they fit the file. Without this
                // limit a small file whose entries all claim the same sectors costs hours.
                *budget = budget.checked_sub(node.entry.size).ok_or("the streams together are larger than the file")?;
                file.read(&node.entry, &mut |piece| hasher.update(piece))?;
            }
            Kind::Storage | Kind::Root => hash_content(file, node, false, place, hasher, budget)?,
        }
    }
    hasher.update(storage.entry.clsid());
    Ok(())
}

/// The digest an MSI signature signs, with the content of `MsiDigitalSignatureEx` (`metadata`)
/// hashed first.
fn content_digest(file: &Compound, root: &Node, size: usize, hash: Hash, metadata: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut hasher = hash.hasher();
    if let Some(metadata) = metadata {
        hasher.update(metadata);
    }
    let mut budget = size as u64;
    hash_content(file, root, true, MetadataPlace::Apart, &mut hasher, &mut budget)?;
    Ok(hasher.finish())
}

/// The same digest with `MsiDigitalSignatureEx` hashed where its name sorts.
fn content_digest_in_order(file: &Compound, root: &Node, size: usize, hash: Hash) -> Result<Vec<u8>, String> {
    let mut hasher = hash.hasher();
    let mut budget = size as u64;
    hash_content(file, root, true, MetadataPlace::InOrder, &mut hasher, &mut budget)?;
    Ok(hasher.finish())
}

/// True when hashing `MsiDigitalSignatureEx` first and hashing it in name order differ:
/// something that is hashed sorts before it.
fn metadata_place_matters(root: &Node) -> bool {
    let metadata = utf16le(METADATA_STREAM);
    hash_order(root, true, MetadataPlace::InOrder)
        .iter()
        .take_while(|node| node.entry.name_bytes() != metadata)
        .any(|node| node.entry.kind != Kind::Stream || node.entry.size > 0)
}

/// The file digest to compare with `signed`, the digest inside the signature.
fn file_digest(file: &Compound, root: &Node, size: usize, hash: Hash, metadata: Option<&[u8]>, signed: &[u8]) -> Result<Vec<u8>, String> {
    let first = content_digest(file, root, size, hash, metadata)?;
    if metadata.is_none() || first == signed || !metadata_place_matters(root) {
        return Ok(first);
    }
    if content_digest_in_order(file, root, size, hash)? == signed {
        return Err("the signed digest matches only when MsiDigitalSignatureEx is hashed in name order (as osslsigncode does) \
                    and not when it is hashed first; which of the two Windows accepts for this package was not established"
            .into());
    }
    Ok(first)
}

fn hash_entry_metadata(entry: &Entry, hasher: &mut Hasher) {
    // Neither the name of the root entry nor its timestamps are hashed: Windows shows the file
    // name and the file's own times in their place.
    if entry.kind != Kind::Root {
        hasher.update(entry.name_bytes());
    }
    match entry.kind {
        Kind::Stream => hasher.update(entry.size_bytes()),
        Kind::Storage | Kind::Root => hasher.update(entry.clsid()),
    }
    hasher.update(entry.state_bits());
    if entry.kind != Kind::Root {
        hasher.update(entry.created());
        hasher.update(entry.modified());
    }
}

fn hash_metadata(storage: &Node, is_root: bool, hasher: &mut Hasher) {
    hash_entry_metadata(&storage.entry, hasher);
    for node in hash_order(storage, is_root, MetadataPlace::Apart) {
        match node.entry.kind {
            Kind::Stream => hash_entry_metadata(&node.entry, hasher),
            Kind::Storage | Kind::Root => hash_metadata(node, false, hasher),
        }
    }
}

/// What `MsiDigitalSignatureEx` should hold.
fn metadata_digest(root: &Node, hash: Hash) -> Vec<u8> {
    let mut hasher = hash.hasher();
    hash_metadata(root, true, &mut hasher);
    hasher.finish()
}

/// The content of the root stream called `name`. `Ok(None)` when the root has no such entry.
fn root_stream(file: &Compound, root: &Node, name: &str) -> Result<Option<Vec<u8>>, String> {
    let wanted = utf16le(name);
    let Some(node) = root.children.iter().find(|c| c.entry.name_bytes() == wanted) else { return Ok(None) };
    if node.entry.kind != Kind::Stream {
        return Err(format!("{:?} is a storage, not a stream", name.trim_start_matches('\u{5}')));
    }
    file.read_to_vec(&node.entry, MAX_SIGNATURE).map(Some)
}

/// Everything read from the signature streams of one file.
struct MsiSignature {
    /// `MSI`, `MSP`, `MST` or `compound file`.
    kind: &'static str,
    auth: authenticode::Authenticode,
    signature_length: usize,
    /// `(signed, computed, check)` for `MsiDigitalSignatureEx`, when the stream exists.
    metadata: Option<(String, Option<String>, Check)>,
}

fn file_kind(root: &Node) -> &'static str {
    let clsid = root.entry.clsid();
    if clsid == CLSID_PACKAGE {
        "MSI"
    } else if clsid == CLSID_PATCH {
        "MSP"
    } else if clsid == CLSID_TRANSFORM {
        "MST"
    } else {
        "compound file"
    }
}

/// Reads and checks the signature. `Ok(None)` when the file has no signature stream.
fn verify(file: &Compound, root: &Node, size: usize) -> Result<Option<MsiSignature>, String> {
    let Some(blob) = root_stream(file, root, SIGNATURE_STREAM)? else { return Ok(None) };
    let metadata_stream = root_stream(file, root, METADATA_STREAM)?;
    let digest = |hash: Hash, signed: &[u8]| file_digest(file, root, size, hash, metadata_stream.as_deref(), signed);
    let auth = authenticode::analyze_blob(&blob, &digest);
    let metadata = metadata_stream.map(|stored| {
        let (computed, check) = match auth.signatures.first().map(|s| s.digest_algorithm) {
            Some(Some(hash)) => {
                let computed = metadata_digest(root, hash);
                let check = if computed == stored { Check::Passed } else { Check::Failed };
                (Some(hex::encode(computed)), check)
            }
            Some(None) => (None, Check::NotChecked("the signature's digest algorithm is not supported".into())),
            None => (None, Check::NotChecked("the signature could not be read".into())),
        };
        (hex::encode(&stored), computed, check)
    });
    let mut signature = MsiSignature { kind: file_kind(root), auth, signature_length: blob.len(), metadata };
    // Zero padding after the PKCS#7 blob carries nothing; anything else is foreign data.
    signature.auth.extra_in_table.retain(|&(offset, length)| blob.get(offset..offset + length).is_some_and(|b| b.iter().any(|&x| x != 0)));
    Ok(Some(signature))
}

/// Checks the file's own signature when `bytes` is a compound file. `is_msi` says the file was
/// already recognised as an MSI package.
pub fn analyze(file: &Artifact, bytes: &[u8], is_msi: bool, out: &mut Output) {
    if !compound::is_compound(bytes) {
        return;
    }
    let unreadable = |error: String, out: &mut Output| out.limitation("windows.msi-signature-unreadable", Some(file), Some(error));
    let (compound, root) = match Compound::parse(bytes).and_then(|compound| compound.tree().map(|root| (compound, root))) {
        Ok(parsed) => parsed,
        Err(error) => {
            // Compound files are also old Office documents and the like. One that cannot be
            // read is only known to be an installer when the MSI reader said so.
            if is_msi {
                unreadable(error, out);
            }
            return;
        }
    };
    match verify(&compound, &root, bytes.len()) {
        Ok(Some(signature)) => report(file, &signature, out),
        Ok(None) => {
            // Transforms and other compound files are not expected to be signed.
            let kind = if is_msi { "MSI" } else { file_kind(&root) };
            if kind == "MSI" || kind == "MSP" {
                out.fact(file, "windows.msi-signature", json!({ "signed": false, "kind": kind }));
                out.finding(
                    finding(Section::Provenance, "windows.msi-unsigned", Confidence::Verified, Severity::Info)
                        .param("kind", kind)
                        .evidence(Evidence::field(file, SIGNATURE_FIELD, Value::Null)),
                );
            }
        }
        // Only a signature entry that exists can fail to be read.
        Err(error) => unreadable(error, out),
    }
}

fn report(file: &Artifact, msi: &MsiSignature, out: &mut Output) {
    let auth = &msi.auth;
    let mut fact = json!({
        "signed": !auth.signatures.is_empty(),
        "kind": msi.kind,
        "signature_stream_bytes": msi.signature_length,
        "signatures": auth.signatures.iter().map(Signature::json).collect::<Vec<_>>(),
        "errors": auth.errors,
        "extra_bytes_in_stream": auth.extra_in_table.iter().map(|(o, l)| json!({ "offset": o, "length": l })).collect::<Vec<_>>(),
        "metadata_stream": msi.metadata.is_some(),
    });
    if let (Some((signed, computed, check)), Some(object)) = (&msi.metadata, fact.as_object_mut()) {
        object.insert("signed_metadata_digest".into(), json!(signed));
        object.insert("computed_metadata_digest".into(), json!(computed));
        object.insert("metadata_digest".into(), check.json());
    }
    out.fact(file, "windows.msi-signature", fact);
    for error in &auth.errors {
        out.limitation("windows.msi-signature-unreadable", Some(file), Some(error.clone()));
    }
    let at = |value: Value| Evidence::field(file, SIGNATURE_FIELD, value);

    if let Some(primary) = auth.signatures.first() {
        // The checks made on the package as a whole, and what could not be checked.
        let mut checks: Vec<(&str, &Check)> = Vec::new();
        for signature in &auth.signatures {
            checks.extend([
                ("file digest", &signature.file_digest),
                ("signed-attribute digest", &signature.content_digest),
                ("signature value", &signature.signature),
                ("certificate chain", &signature.chain_check),
            ]);
        }
        if let Some((_, _, check)) = &msi.metadata {
            checks.push(("metadata digest", check));
        }
        let passed = checks.iter().filter(|(_, check)| check.passed()).count();
        let mut unchecked: Vec<String> = Vec::new();
        for (name, check) in &checks {
            if let Check::NotChecked(why) = check {
                unchecked.push(format!("{name}: {why}"));
            }
        }
        for stamp in auth.signatures.iter().flat_map(|s| &s.timestamps) {
            for (name, check) in [
                ("timestamp coverage", &stamp.covers_signature),
                ("timestamp content digest", &stamp.content_digest),
                ("timestamp signature", &stamp.signature),
                ("timestamp certificate chain", &stamp.chain_check),
            ] {
                if let Check::NotChecked(why) = check {
                    unchecked.push(format!("{name}: {why}"));
                }
            }
        }
        let stamp = primary.timestamps.first();
        out.finding(
            finding(
                Section::Provenance,
                "windows.msi-signature",
                Confidence::Verified,
                if passed == checks.len() { Severity::Info } else { Severity::Medium },
            )
            .param("kind", msi.kind)
            .param("signer", primary.signer_name.clone().unwrap_or_else(|| "?".into()))
            .param("issuer", primary.signer.as_ref().and_then(|s| s.get("issuer")).and_then(Value::as_str).unwrap_or("?"))
            .param("algorithm", primary.digest_algorithm_name.clone())
            .param("timestamp", stamp.and_then(|s| s.time.clone()).unwrap_or_else(|| "—".into()))
            .param("authority", stamp.and_then(|s| s.authority_name.clone()).unwrap_or_else(|| "—".into()))
            .param("passed", passed)
            .param("checks", checks.len())
            .evidence(at(json!({
                "signer": primary.signer_subject,
                "serial": primary.signer.as_ref().and_then(|s| s.get("serial")),
                "signed_digest": primary.signed_digest,
                "computed_digest": primary.computed_digest,
                "checks": checks.iter().map(|(name, check)| json!({ "check": name, "result": check.json() })).collect::<Vec<_>>(),
            }))),
        );
        if !unchecked.is_empty() {
            out.limitation("windows.msi-signature-not-checked", Some(file), Some(unchecked.join("; ")));
        }
        if let Some((signed, computed, check)) = &msi.metadata
            && check.failed()
        {
            out.finding(
                finding(Section::Provenance, "windows.msi-signature-metadata-mismatch", Confidence::Verified, Severity::High)
                    .param("signer", primary.signer_name.clone().unwrap_or_else(|| "?".into()))
                    .param("algorithm", primary.digest_algorithm_name.clone())
                    .param("signed", signed.clone())
                    .param("computed", computed.clone().unwrap_or_default())
                    .evidence(Evidence::field(file, METADATA_FIELD, json!({ "stored_digest": signed, "computed_digest": computed }))),
            );
        }
    }
    signature_problems(&auth.signatures, &|_, value| at(value), out);
    for &(offset, length) in &auth.extra_in_table {
        out.finding(
            finding(Section::Anomalies, "windows.msi-signature-extra-data", Confidence::Verified, Severity::Medium)
                .param("bytes", length)
                .param("offset", offset)
                .evidence(at(json!({ "offset_in_stream": offset, "bytes": length }))),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use sha2::{Digest, Sha256};

    use super::*;

    fn clsid(seed: u8) -> [u8; 16] {
        std::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    /// A compound file with nested storages, written by the `cfb` crate, and the bytes its
    /// content hash must cover, put together by hand in the documented order.
    fn sample(with_signature_streams: bool) -> (Vec<u8>, Vec<u8>) {
        let mut file = cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new())).expect("create");
        let data = |tag: u8, length: usize| -> Vec<u8> { (0..length).map(|i| (i as u8).wrapping_mul(13).wrapping_add(tag)).collect() };
        // U+4806 is stored as 06 48 and U+3B40 as 40 3B: by stored bytes the first sorts first,
        // by code unit it would sort last. "ab" sorts after its prefix "a".
        file.create_storage("/Zstorage").expect("storage");
        file.create_storage("/Zstorage/deep").expect("storage");
        let mut write = |path: &str, bytes: &[u8]| file.create_stream(path).expect("stream").write_all(bytes).expect("write");
        write("/\u{3b40}x", &data(1, 300));
        write("/\u{4806}y", &data(2, 5000));
        write("/ab", &data(3, 10));
        write("/a", &data(4, 4096));
        write("/empty", &[]);
        write("/Zstorage/n", &data(5, 77));
        write("/Zstorage/deep/m", &data(6, 4500));
        write("/Zstorage/\u{5}DigitalSignature", &data(7, 20));
        if with_signature_streams {
            write("/\u{5}DigitalSignature", &data(8, 900));
            write("/\u{5}MsiDigitalSignatureEx", &data(9, 32));
        }
        file.flush().expect("flush");
        let mut bytes = file.into_inner().into_inner();
        // Give the three storages distinct CLSIDs, written straight into their directory entries.
        let mut patches = Vec::new();
        {
            let parsed = Compound::parse(&bytes).expect("parse");
            let root = parsed.tree().expect("tree");
            let outer = root.children.iter().find(|c| c.entry.name() == "Zstorage").expect("storage");
            let deep = outer.children.iter().find(|c| c.entry.name() == "deep").expect("storage");
            for (entry, seed) in [(root.entry, 1), (outer.entry, 40), (deep.entry, 90)] {
                patches.push((entry.clsid().as_ptr() as usize - bytes.as_ptr() as usize, clsid(seed)));
            }
        }
        for (offset, value) in patches {
            bytes[offset..offset + 16].copy_from_slice(&value);
        }

        // Root, sorted by stored name bytes: U+4806 "y" (06 48), U+3B40 "x" (40 3b), "Zstorage"
        // (5a 00), "a" (61 00), "ab", "empty".
        let mut expected = Vec::new();
        expected.extend(data(2, 5000));
        expected.extend(data(1, 300));
        // Zstorage: its own signature-named stream is not special below the root. Stored names:
        // 05 00 "DigitalSignature", "deep", "n".
        expected.extend(data(7, 20));
        expected.extend(data(6, 4500));
        expected.extend(clsid(90));
        expected.extend(data(5, 77));
        expected.extend(clsid(40));
        expected.extend(data(4, 4096));
        expected.extend(data(3, 10));
        expected.extend(clsid(1));
        (bytes, expected)
    }

    #[test]
    fn content_digest_follows_the_documented_order() {
        for with_signature_streams in [false, true] {
            let (bytes, expected) = sample(with_signature_streams);
            let file = Compound::parse(&bytes).expect("parse");
            let root = file.tree().expect("tree");
            assert_eq!(root.entry.clsid(), clsid(1));
            let digest = content_digest(&file, &root, bytes.len(), Hash::Sha256, None).expect("digest");
            assert_eq!(hex::encode(digest), hex::encode(Sha256::digest(&expected)), "signature streams: {with_signature_streams}");
            // With MsiDigitalSignatureEx, its content is hashed first.
            let digest = content_digest(&file, &root, bytes.len(), Hash::Sha1, Some(b"prefix")).expect("digest");
            let prefixed = [b"prefix".as_slice(), &expected].concat();
            let mut hasher = Hash::Sha1.hasher();
            hasher.update(&prefixed);
            assert_eq!(digest, hasher.finish());
        }
    }

    /// Writes the sample as an unsigned package. `tests/data/make-fixtures.sh` signs it with
    /// osslsigncode to make `msi-nested-dse.msi`, the fixture that checks recursion and sort
    /// order against a reference tool.
    #[test]
    #[ignore = "run by tests/data/make-fixtures.sh with AA_NESTED_SAMPLE set"]
    fn write_nested_sample() {
        let path = std::env::var("AA_NESTED_SAMPLE").expect("AA_NESTED_SAMPLE names the file to write");
        let (mut bytes, _) = sample(false);
        let offset = {
            let parsed = Compound::parse(&bytes).expect("parse");
            parsed.tree().expect("tree").entry.clsid().as_ptr() as usize - bytes.as_ptr() as usize
        };
        bytes[offset..offset + 16].copy_from_slice(&CLSID_PACKAGE);
        std::fs::write(path, bytes).expect("write");
    }

    #[test]
    fn metadata_stream_position_is_not_guessed() {
        // Nothing in the sample sorts before MsiDigitalSignatureEx: hashing it first and hashing
        // it in name order are the same thing.
        let (bytes, _) = sample(true);
        let file = Compound::parse(&bytes).expect("parse");
        let root = file.tree().expect("tree");
        let stored = root_stream(&file, &root, METADATA_STREAM).expect("read").expect("present");
        assert!(!metadata_place_matters(&root));
        let first = content_digest(&file, &root, bytes.len(), Hash::Sha256, Some(&stored)).expect("digest");
        assert_eq!(first, content_digest_in_order(&file, &root, bytes.len(), Hash::Sha256).expect("digest"));

        // U+3B01 is stored as 01 3B and sorts before the 05 00 of the signature streams.
        let mut file = cfb::CompoundFile::create(Cursor::new(Vec::new())).expect("create");
        for (path, content) in [("/\u{3b01}early", &[1u8; 40][..]), ("/late", &[2; 50]), ("/\u{5}MsiDigitalSignatureEx", &[3; 32])] {
            file.create_stream(path).expect("stream").write_all(content).expect("write");
        }
        file.flush().expect("flush");
        let bytes = file.into_inner().into_inner();
        let file = Compound::parse(&bytes).expect("parse");
        let root = file.tree().expect("tree");
        assert!(metadata_place_matters(&root));
        let digest = |signed: &[u8]| file_digest(&file, &root, bytes.len(), Hash::Sha256, Some(&[3; 32]), signed);
        let first = Sha256::digest([&[3u8; 32][..], &[1; 40], &[2; 50], &[0; 16]].concat()).to_vec();
        let in_order = Sha256::digest([&[1u8; 40][..], &[3; 32], &[2; 50], &[0; 16]].concat()).to_vec();
        assert_eq!(digest(&first).expect("digest"), first);
        let error = digest(&in_order).expect_err("only the other reading matches");
        assert!(error.contains("was not established"), "{error}");
        // Neither reading matches: the file was modified, whichever is right.
        assert_eq!(digest(&[0; 32]).expect("digest"), first);
    }

    #[test]
    fn metadata_digest_changes_with_names_sizes_and_times() {
        let (bytes, _) = sample(true);
        let file = Compound::parse(&bytes).expect("parse");
        let root = file.tree().expect("tree");
        let original = metadata_digest(&root, Hash::Sha256);
        let entry = root.children.iter().find(|c| c.entry.name() == "ab").expect("entry").entry;
        let offset = entry.name_bytes().as_ptr() as usize - bytes.as_ptr() as usize;
        // A renamed stream ("ab" -> "ac"), a changed timestamp, changed state bits.
        for (at, value) in [(offset + 2, b'c'), (offset + 100, 1), (offset + 96, 1)] {
            let mut changed = bytes.clone();
            changed[at] = value;
            let file = Compound::parse(&changed).expect("parse");
            let root = file.tree().expect("tree");
            assert_ne!(metadata_digest(&root, Hash::Sha256), original, "offset {at}");
        }
        // The signature streams themselves are not part of it.
        let (unsigned, _) = sample(false);
        let file = Compound::parse(&unsigned).expect("parse");
        let root = file.tree().expect("tree");
        let without = metadata_digest(&root, Hash::Sha256);
        // (Timestamps of the storages differ between two files written at different moments,
        // so only the length is compared.)
        assert_eq!(without.len(), original.len());
    }

    #[test]
    fn overlapping_streams_are_refused() {
        let (bytes, _) = sample(false);
        let file = Compound::parse(&bytes).expect("parse");
        let root = file.tree().expect("tree");
        // A budget smaller than the streams stands in for entries that share sectors.
        let mut hasher = Hash::Sha256.hasher();
        let mut budget = 5000;
        let error = hash_content(&file, &root, true, MetadataPlace::Apart, &mut hasher, &mut budget).expect_err("over budget");
        assert!(error.contains("larger than the file"), "{error}");
    }

    #[test]
    fn a_signature_stream_that_is_not_pkcs7_is_an_error_not_a_panic() {
        let (bytes, _) = sample(true);
        let file = Compound::parse(&bytes).expect("parse");
        let root = file.tree().expect("tree");
        let signature = verify(&file, &root, bytes.len()).expect("verify").expect("stream present");
        assert!(signature.auth.signatures.is_empty());
        assert_eq!(signature.auth.errors.len(), 1);
        let (_, computed, check) = signature.metadata.expect("metadata stream");
        assert_eq!(computed, None);
        assert!(matches!(check, Check::NotChecked(_)));

        let (unsigned, _) = sample(false);
        let file = Compound::parse(&unsigned).expect("parse");
        let root = file.tree().expect("tree");
        assert!(verify(&file, &root, unsigned.len()).expect("verify").is_none());
        assert_eq!(file_kind(&root), "compound file");
    }
}
