//! End-to-end tests: the unpackers on the committed fixtures, and the analyzer on small trees
//! held in memory. `tests/data/README.md` says where each fixture comes from.

use std::collections::BTreeMap;
use std::io::Read;

use aa_core::plugin::{Analyzer, Bytes, Output, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Digests, Severity};
use serde_json::Value;
use sha1::Digest;

use crate::analyzer::Apple;
use crate::codesign;
use crate::disk::{self, Disk};
use crate::inspect::tests::signed_macho;
use crate::pkg::tests::{Collect, xar_archive};
use crate::unpack::{Dmg, Payload, XarArchive};

const TINY_DMG: &[u8] = include_bytes!("../tests/data/tiny.dmg");
const APFS_EMPTY_DMG: &[u8] = include_bytes!("../tests/data/apfs-empty.dmg");
const LAUNCH_AT_LOGIN: &[u8] = include_bytes!("../tests/data/LaunchAtLogin.macho");
const RECTANGLE_SIGNATURE: &[u8] = include_bytes!("../tests/data/rectangle-arm64.codesig");
const PKG_HEAD: &[u8] = include_bytes!("../tests/data/macfuse-pkg-head.xar");
const PROFILE: &[u8] = include_bytes!("../tests/data/synthetic.mobileprovision");

fn artifact(path: &str, bytes: &[u8], parent: Option<&str>) -> Artifact {
    Artifact {
        path: path.to_string(),
        parent: parent.map(str::to_string),
        size: bytes.len() as u64,
        digests: Some(Digests {
            md5: String::new(),
            sha1: hex::encode(sha1::Sha1::digest(bytes)),
            sha256: hex::encode(sha2::Sha256::digest(bytes)),
        }),
        detected: None,
        kind: None,
        entropy: None,
        unpacked_by: None,
        facts: BTreeMap::new(),
    }
}

struct MemoryTree {
    artifacts: Vec<Artifact>,
    data: BTreeMap<String, Vec<u8>>,
}

impl Tree for MemoryTree {
    fn artifacts(&self) -> &[Artifact] {
        &self.artifacts
    }

    fn read(&self, path: &str) -> std::io::Result<Bytes> {
        self.data.get(path).map(|bytes| Bytes::from_vec(bytes.clone())).ok_or_else(|| std::io::Error::other("no such artifact"))
    }
}

/// Runs both passes of the analyzer over `files`, the way the engine does. `setup` may adjust
/// the artifacts first (kinds an unpacker would have set, parents).
fn analyze_with(files: &[(&str, Vec<u8>)], setup: impl Fn(&mut Artifact)) -> (MemoryTree, Output) {
    let mut artifacts: Vec<Artifact> = files.iter().map(|(path, bytes)| artifact(path, bytes, None)).collect();
    artifacts.iter_mut().for_each(&setup);
    artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    let mut tree = MemoryTree { artifacts, data: files.iter().map(|(path, bytes)| (path.to_string(), bytes.clone())).collect() };
    let mut out = Output::default();
    for file in tree.artifacts.clone() {
        Apple.analyze_file(&tree, &file, &mut out);
    }
    for fact in std::mem::take(&mut out.facts) {
        let path = fact.artifact.as_deref().expect("file-pass facts belong to artifacts");
        let target = tree.artifacts.iter_mut().find(|a| a.path == path).expect("fact for a known artifact");
        target.facts.insert(fact.key, fact.value);
    }
    for (path, kind) in std::mem::take(&mut out.kinds) {
        tree.artifacts.iter_mut().find(|a| a.path == path).expect("kind for a known artifact").kind = Some(kind);
    }
    Apple.analyze_tree(&tree, &mut out);
    (tree, out)
}

fn analyze(files: &[(&str, Vec<u8>)]) -> Output {
    analyze_with(files, |_| {}).1
}

fn rules(out: &Output) -> Vec<&str> {
    out.findings.iter().map(|f| f.rule.as_str()).collect()
}

fn has(out: &Output, rule: &str) -> bool {
    out.findings.iter().any(|f| f.rule == rule)
}

fn finding<'a>(out: &'a Output, rule: &str) -> &'a aa_core::Finding {
    out.findings.iter().find(|f| f.rule == rule).unwrap_or_else(|| panic!("no finding {rule} among {:?}", rules(out)))
}

fn unpack(unpacker: &dyn Unpacker, bytes: &[u8]) -> (Unpack, Collect) {
    let mut sink = Collect::default();
    let outcome = unpacker.unpack(&artifact("input", bytes, None), bytes, &mut sink);
    (outcome, sink)
}

/// A deterministic stream of pseudo-random numbers for mutation tests.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

// ---------------------------------------------------------------- disk images

#[test]
fn tiny_dmg_unpacks_to_the_files_7zip_lists() {
    let (outcome, sink) = unpack(&Dmg, TINY_DMG);
    assert_eq!(outcome, Unpack::Done { kind: "dmg" });
    assert!(sink.limitations.is_empty(), "{:?}", sink.limitations);
    let names: Vec<&str> = sink.files.iter().map(|f| f.0.as_str()).collect();
    // The symbolic link `link` is not a file; `hard` is a hard link and yields its target's content.
    assert_eq!(names, ["App.app/Contents/Info.plist", "big.bin", "hard", "hello.txt"]);
    let content = |name: &str| &sink.files.iter().find(|f| f.0 == name).expect("file").1;
    assert_eq!(content("hello.txt"), b"hello\n");
    assert_eq!(content("hard"), b"linked\n");
    assert!(content("App.app/Contents/Info.plist").starts_with(b"<?xml"));
    // SHA-256 of big.bin as extracted by 7-Zip 23.01 from the same volume.
    assert_eq!(hex::encode(sha2::Sha256::digest(content("big.bin"))), "1e0d7c1f75b60785a19d26b1335ce40ba353da1154e09905170a9e411da3e3e0");
    assert_eq!(content("big.bin").len(), 10000);
    assert!(content("big.bin").iter().enumerate().all(|(i, b)| *b == ((i * 31 + 7) % 251) as u8));
}

#[test]
fn dmg_fact_names_every_chunk_method() {
    let fact = crate::inspect::dmg_fact(TINY_DMG).expect("udif");
    assert_eq!(fact["encrypted"], false);
    assert_eq!(fact["udif_version"], 4);
    assert_eq!(fact["compression"], serde_json::json!(["adc", "bzip2", "lzma", "zlib"]));
    assert!(fact["partitions"][0]["chunks"]["raw"].as_u64().is_some());
    assert!(fact["partitions"][0]["chunks"]["zero"].as_u64().is_some());
}

#[test]
fn empty_apfs_container_opens() {
    let (outcome, sink) = unpack(&Dmg, APFS_EMPTY_DMG);
    assert_eq!(outcome, Unpack::Done { kind: "dmg" });
    assert!(sink.files.is_empty());
    assert!(sink.limitations.is_empty(), "{:?}", sink.limitations);
    let koly = disk::udif::koly(APFS_EMPTY_DMG).expect("koly");
    let tables = disk::udif::tables(APFS_EMPTY_DMG, &koly).expect("tables");
    let partition = disk::udif::Partition::new(APFS_EMPTY_DMG, &tables[0]);
    assert_eq!(disk::find_volumes(&partition).first().map(|v| v.2), Some(disk::VolumeKind::Apfs));
    let (volumes, skipped) = disk::apfs::open(&partition).expect("container");
    assert!(skipped.is_empty());
    assert_eq!(volumes.len(), 1);
    assert_eq!(volumes[0].name, "TinyAPFS");
    assert!(volumes[0].files.is_empty() && volumes[0].damage.is_none());
}

#[test]
fn encrypted_images_are_a_limitation() {
    let mut image = b"encrcdsa".to_vec();
    image.extend([0x5a; 4096]);
    let (outcome, sink) = unpack(&Dmg, &image);
    assert_eq!(outcome, Unpack::Done { kind: "dmg" });
    assert_eq!(sink.limitations, ["dmg.encrypted"]);
    assert!(sink.files.is_empty());
    let mut old = vec![0x5a; 4096];
    old.extend_from_slice(b"cdsaencr");
    assert_eq!(unpack(&Dmg, &old).1.limitations, ["dmg.encrypted"]);
    assert_eq!(crate::inspect::dmg_fact(&image).expect("fact")["encrypted"], true);
}

#[test]
fn other_files_are_not_disk_images() {
    for bytes in [&b""[..], b"hello", &[0u8; 4096], b"PK\x03\x04"] {
        assert_eq!(unpack(&Dmg, bytes).0, Unpack::NotMine);
        assert_eq!(unpack(&XarArchive, bytes).0, Unpack::NotMine);
        assert_eq!(unpack(&Payload, bytes).0, Unpack::NotMine);
    }
}

#[test]
fn truncated_and_corrupted_images_do_not_panic() {
    // Cut anywhere: without the trailer the file is no longer recognised.
    for cut in (0..TINY_DMG.len()).step_by(4099) {
        let _ = unpack(&Dmg, &TINY_DMG[..cut]);
    }
    // The trailer kept, the data before it shortened: chunks and the property list go missing.
    let trailer = &TINY_DMG[TINY_DMG.len() - 512..];
    for keep in [0usize, 100, 5000, 60000, 130000] {
        let mut image = TINY_DMG[..keep].to_vec();
        image.extend_from_slice(trailer);
        let (outcome, _) = unpack(&Dmg, &image);
        assert!(matches!(outcome, Unpack::Failed { .. } | Unpack::Done { .. }));
    }
    // Random damage anywhere in the file.
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    for _ in 0..150 {
        let mut image = TINY_DMG.to_vec();
        for _ in 0..1 + random.next() % 6 {
            let at = (random.next() % image.len() as u64) as usize;
            image[at] = random.next() as u8;
        }
        let _ = unpack(&Dmg, &image);
        let _ = crate::inspect::dmg_fact(&image);
    }
}

/// A disk whose bytes differ from another's at a few offsets.
struct Patched<'a> {
    base: &'a dyn Disk,
    patches: Vec<(u64, u8)>,
}

impl Disk for Patched<'_> {
    fn len(&self) -> u64 {
        self.base.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        self.base.read_at(offset, buf)?;
        for &(at, value) in &self.patches {
            if at >= offset && at < offset + buf.len() as u64 {
                buf[(at - offset) as usize] = value;
            }
        }
        Ok(())
    }
}

#[test]
fn damaged_file_systems_do_not_panic() {
    // Each image with the byte ranges worth damaging.
    type Case<'a> = (&'a [u8], &'a [(u64, u64)]);
    let cases: [Case<'_>; 2] = [
        // HFS+: the volume header, and the B-trees mkfs put in the first megabyte.
        (TINY_DMG, &[(1024, 512), (2 * 4096, 8 * 4096), (26 * 4096, 2 * 4096)]),
        // APFS: the container superblock and the handful of metadata blocks mkapfs wrote.
        (APFS_EMPTY_DMG, &[(0, 4096), (4096, 64 * 4096)]),
    ];
    for (image, regions) in cases {
        let koly = disk::udif::koly(image).expect("koly");
        let tables = disk::udif::tables(image, &koly).expect("tables");
        let partition = disk::udif::Partition::new(image, &tables[0]);
        let mut random = Random(0x1234_5678_9abc_def1);
        for round in 0..400 {
            let (start, length) = regions[round % regions.len()];
            let patches = (0..1 + random.next() % 4).map(|_| (start + random.next() % length, random.next() as u8)).collect();
            let damaged = Patched { base: &partition, patches };
            if let Ok(volume) = disk::hfs::Volume::open(&damaged) {
                for file in &volume.files {
                    if let Ok(mut reader) = volume.open_file(file) {
                        let _ = reader.read_to_end(&mut Vec::new());
                    }
                }
            }
            if let Ok((volumes, _)) = disk::apfs::open(&damaged) {
                for volume in &volumes {
                    for file in &volume.files {
                        if let Ok(mut reader) = volume.open_file(file) {
                            let _ = reader.read_to_end(&mut Vec::new());
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- packages

const PACKAGE_INFO: &str = r#"<pkg-info format-version="2" identifier="com.example.tool" version="1.2" install-location="/" auth="root">
  <payload installKBytes="12" numberOfFiles="3"/>
  <scripts><preinstall file="./preinstall"/><postinstall file="./postinstall"/></scripts></pkg-info>"#;

fn package() -> Vec<u8> {
    let toc = format!(
        r#"<?xml version="1.0"?><xar><toc><checksum style="sha1"><offset>0</offset><size>20</size></checksum>
        <file id="1"><name>PackageInfo</name><type>file</type><data><offset>20</offset><size>{0}</size><length>{0}</length>
        <encoding style="application/octet-stream"/></data></file></toc></xar>"#,
        PACKAGE_INFO.len()
    );
    let mut heap = vec![0u8; 20];
    heap.extend_from_slice(PACKAGE_INFO.as_bytes());
    xar_archive(&toc, &heap)
}

#[test]
fn unsigned_package_with_scripts() {
    let archive = package();
    let (outcome, sink) = unpack(&XarArchive, &archive);
    assert_eq!(outcome, Unpack::Done { kind: "xar" });
    assert_eq!(sink.files.len(), 1);
    let files = [("tool.pkg", archive), ("tool.pkg/PackageInfo", sink.files[0].1.clone())];
    let (_, out) = analyze_with(&files, |a| {
        if a.path == "tool.pkg" {
            a.kind = Some("xar".into());
        } else {
            a.parent = Some("tool.pkg".into());
        }
    });
    assert_eq!(finding(&out, "apple.pkg-unsigned").severity, Severity::Medium);
    let scripts = finding(&out, "apple.pkg-scripts");
    assert_eq!(scripts.params["scripts"], "preinstall → ./preinstall, postinstall → ./postinstall");
    assert_eq!(finding(&out, "apple.pkg-component").params["identifier"], "com.example.tool");
    // The synthetic archive's checksum bytes are zeros, not the digest of the table of contents.
    assert!(has(&out, "apple.xar-checksum-mismatch"));
    assert!(out.kinds.contains(&("tool.pkg".to_string(), "pkg".to_string())));
}

#[test]
fn real_package_signature_verifies_and_tampering_is_seen() {
    // The first 15 KB of "Install macFUSE.pkg": header, table of contents, checksum, signatures.
    let fact = crate::inspect::xar_fact(PKG_HEAD).expect("xar");
    assert_eq!(fact["toc_checksum"]["matches"], true);
    assert_eq!(fact["is_package"], true);
    let signatures = fact["signatures"].as_array().expect("signatures");
    assert_eq!(signatures.len(), 2);
    for signature in signatures {
        assert_eq!(signature["signature"], "valid", "{signature}");
        assert_eq!(signature["anchored"], true);
        assert_eq!(signature["signing_type"], "developer-id-installer");
        assert_eq!(signature["chain"]["certificates"][0]["common_name"], "Developer ID Installer: Benjamin Fleischer (3T5GSNBU6W)");
        assert_eq!(signature["chain"]["anchor"], "known root: Apple Root CA");
    }
    let (_, out) = analyze_with(&[("m.pkg", PKG_HEAD.to_vec())], |a| a.kind = Some("xar".into()));
    assert!(has(&out, "apple.pkg-signed") && has(&out, "apple.pkg-signature-valid-apple-root"));
    assert!(out.limitations.iter().any(|l| l.code == "apple.trust-not-evaluated"));
    // The files' data was cut off: the unpacker says so for each instead of failing.
    let (outcome, sink) = unpack(&XarArchive, PKG_HEAD);
    assert_eq!(outcome, Unpack::Done { kind: "xar" });
    assert!(sink.limitations.contains(&"xar.entry-unreadable".to_string()));

    // One byte of the RSA signature changed (it sits right after the 20-byte checksum).
    let heap = 28 + u64::from_be_bytes(PKG_HEAD[8..16].try_into().expect("8 bytes")) as usize;
    let mut tampered = PKG_HEAD.to_vec();
    tampered[heap + 20 + 100] ^= 1;
    let fact = crate::inspect::xar_fact(&tampered).expect("xar");
    assert_eq!(fact["signatures"][0]["signature"], "invalid");
    // One byte of the table of contents changed: the checksum no longer matches, and nothing
    // can be said about the signatures, which sign that checksum.
    let mut tampered = PKG_HEAD.to_vec();
    tampered[40] ^= 1;
    if let Some(fact) = crate::inspect::xar_fact(&tampered) {
        assert_eq!(fact["toc_checksum"]["matches"], false);
        assert!(fact["signatures"].as_array().into_iter().flatten().all(|s| s["signature"] != "valid"));
    }
    for cut in (0..PKG_HEAD.len()).step_by(97) {
        let _ = crate::inspect::xar_fact(&PKG_HEAD[..cut]);
        let _ = unpack(&XarArchive, &PKG_HEAD[..cut]);
    }
}

#[test]
fn compressed_cpio_payloads_open_directly() {
    use std::io::Write;
    let mut archive = Vec::new();
    for (name, mode, data) in [("./usr/bin/tool", 0o100755u32, &b"#!/bin/sh\n"[..]), ("TRAILER!!!", 0, b"")] {
        archive.extend(
            format!(
                "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
                1,
                2,
                mode,
                0,
                0,
                1,
                0,
                0,
                name.len() + 1,
                data.len()
            )
            .bytes(),
        );
        archive.extend_from_slice(name.as_bytes());
        archive.push(0);
        archive.extend_from_slice(data);
    }
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&archive).expect("write");
    let gzip = gzip.finish().expect("finish");
    let mut pbzx = b"pbzx".to_vec();
    pbzx.extend((1u64 << 24).to_be_bytes());
    pbzx.extend((archive.len() as u64).to_be_bytes());
    pbzx.extend((archive.len() as u64).to_be_bytes());
    pbzx.extend_from_slice(&archive);
    for (bytes, kind) in [(&archive, "cpio"), (&gzip, "cpio-gzip"), (&pbzx, "cpio-pbzx")] {
        let (outcome, sink) = unpack(&Payload, bytes);
        assert_eq!(outcome, Unpack::Done { kind });
        assert_eq!(sink.files, vec![("./usr/bin/tool".to_string(), b"#!/bin/sh\n".to_vec())]);
    }
    // A gzip stream that is not a cpio archive is left to the generic unpackers.
    let mut other = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    other.write_all(b"just text").expect("write");
    assert_eq!(unpack(&Payload, &other.finish().expect("finish")).0, Unpack::NotMine);
}

/// A sink that refuses everything after the first entry.
struct OneEntry(usize);

impl UnpackSink for OneEntry {
    fn add(&mut self, _path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
        if self.0 >= 1 {
            return Err(SinkError::LimitReached);
        }
        self.0 += 1;
        std::io::copy(data, &mut std::io::sink()).map(|_| ()).map_err(|e| SinkError::Read(e.to_string()))
    }

    fn limitation(&mut self, _code: &str, _detail: Option<String>) {}
}

#[test]
fn unpackers_stop_at_the_sink_limit() {
    let mut sink = OneEntry(0);
    assert_eq!(Dmg.unpack(&artifact("tiny.dmg", TINY_DMG, None), TINY_DMG, &mut sink), Unpack::Done { kind: "dmg" });
    assert_eq!(sink.0, 1);
}

// ---------------------------------------------------------------- real signatures

#[test]
fn real_signature_blob_matches_rcodesign() {
    // Values from `rcodesign print-signature-info` (apple-codesign 0.29) on Rectangle 0.93, arm64 slice.
    let signature = codesign::parse(RECTANGLE_SIGNATURE).expect("signature");
    let directory = signature.best();
    assert_eq!(directory.identifier, "com.knollsoft.Rectangle");
    assert_eq!(directory.team_id.as_deref(), Some("XSYZ3E4B7D"));
    assert_eq!(hex::encode(&directory.cdhash), "84003c9fe04da4b8ca9949fce22716593cd4d559");
    assert_eq!(codesign::flag_names(directory.flags), ["runtime"]);
    assert_eq!(format!("{:#x}", directory.version), "0x20500");
    assert_eq!(signature.requirements().map(|r| r.0), Some(1));
    let check = signature.check_cms().expect("has CMS").expect("parses");
    assert_eq!(check.digest_matches, Some(true));
    assert_eq!(check.signature, crate::certs::Verdict::Valid);
    assert_eq!(check.signing_time.as_ref().map(|t| t.0.as_str()), Some("2026-01-04T20:31:08Z"));
    assert!(check.timestamped);
    let chain = check.chain.expect("chain");
    assert!(chain.anchored());
    let names: Vec<&str> = chain.certificates.iter().filter_map(|c| c.common_name.as_deref()).collect();
    assert_eq!(names, ["Developer ID Application: Ryan Hanson (XSYZ3E4B7D)", "Developer ID Certification Authority", "Apple Root CA"]);
    assert_eq!(chain.certificates[0].organizational_unit.as_deref(), Some("XSYZ3E4B7D"));
    assert!(chain.certificates[0].apple_extensions.contains(&"1.2.840.113635.100.6.1.13".to_string()));
    assert_eq!(check.cdhashes.map(|list| list.contains(&directory.cdhash)), Some(true));
}

#[test]
fn a_changed_signature_no_longer_verifies() {
    let original = codesign::parse(RECTANGLE_SIGNATURE).expect("signature");
    let (directory_at, directory_length) = original.directories[0].blob;
    let (_, cms_at, cms_length) = original.blobs[&0x10000];
    // The identifier inside the code directory: the signed digest no longer matches.
    let mut changed = RECTANGLE_SIGNATURE.to_vec();
    let at = directory_at + directory_length / 2;
    changed[at] ^= 1;
    let check = codesign::parse(&changed).expect("still parses").check_cms().expect("has CMS").expect("parses");
    assert_eq!(check.digest_matches, Some(false));
    // The last bytes of the CMS blob are padding or the timestamp; walk back to the signer's
    // signature by changing bytes until the verdict flips, to prove a flip is noticed.
    let mut noticed = 0;
    for offset in (cms_at + 8..cms_at + cms_length).step_by(61) {
        let mut changed = RECTANGLE_SIGNATURE.to_vec();
        changed[offset] ^= 0x40;
        let outcome = codesign::parse(&changed).ok().and_then(|s| s.check_cms());
        let verified = matches!(&outcome, Some(Ok(check)) if check.signature == crate::certs::Verdict::Valid
            && check.digest_matches == Some(true)
            && check.chain.as_ref().is_some_and(crate::certs::Chain::anchored));
        if !verified {
            noticed += 1;
        }
    }
    // Everything but the unsigned timestamp token is covered by a signature somewhere.
    assert!(noticed > 40, "only {noticed} changes were noticed");
}

#[test]
fn real_universal_binary_matches_rcodesign() {
    // Stats' LaunchAtLogin helper, signed with a Developer ID. Expected values from rcodesign.
    let fact = crate::inspect::macho_fact(LAUNCH_AT_LOGIN).expect("mach-o");
    let slices = fact["slices"].as_array().expect("slices");
    let expected = [("x86_64", "e74e941b1ae1778eb5d90f6291c79160d538c67a", 7), ("arm64", "c2b12c9270d213a4ab9d7857a1f1baaea75ce64f", 4)];
    assert_eq!(slices.len(), 2);
    for (slice, (arch, cdhash, pages)) in slices.iter().zip(expected) {
        let signature = &slice["signature"];
        assert_eq!(slice["arch"], arch);
        assert_eq!(signature["cdhash"], cdhash);
        assert_eq!(signature["identifier"], "eu.exelban.Stats.LaunchAtLogin");
        assert_eq!(signature["team_id"], "RP2S87B72W");
        assert_eq!(signature["signing_type"], "developer-id");
        assert_eq!(signature["hardened_runtime"], true);
        let directory = &signature["directories"][0];
        assert_eq!(directory["pages"]["checked"], pages);
        assert_eq!(directory["pages"]["mismatched"], 0);
        assert_eq!(directory["slots"]["requirements"], "match");
        assert_eq!(signature["cms"]["verified"], true);
        assert_eq!(signature["cms"]["anchored"], true);
        assert_eq!(signature["cms"]["cdhashes_bound"], true);
        assert_eq!(signature["cms"]["signed_within_validity"], true);
    }
    // On its own the file is reported briefly: who signed it, and that it is intact.
    let out = analyze(&[("LaunchAtLogin", LAUNCH_AT_LOGIN.to_vec())]);
    assert!(has(&out, "apple.signature") && has(&out, "apple.signed-developer-id") && has(&out, "apple.other-code-intact"));
    assert!(out.findings.iter().all(|f| f.severity == Severity::Info), "{:?}", rules(&out));

    // One byte of code changed in the arm64 slice.
    let mut tampered = LAUNCH_AT_LOGIN.to_vec();
    let arm64 = slices[1]["offset"].as_u64().expect("offset") as usize;
    tampered[arm64 + 0x4100] ^= 0x01;
    let fact = crate::inspect::macho_fact(&tampered).expect("mach-o");
    assert_eq!(fact["slices"][0]["signature"]["directories"][0]["pages"]["mismatched"], 0);
    assert_eq!(fact["slices"][1]["signature"]["directories"][0]["pages"]["mismatched"], 1);
    assert_eq!(fact["slices"][1]["signature"]["directories"][0]["pages"]["first_mismatches"], serde_json::json!([1]));
    let out = analyze(&[("LaunchAtLogin", tampered)]);
    assert_eq!(finding(&out, "apple.code-modified").severity, Severity::High);
    assert!(!has(&out, "apple.other-code-intact"));

    let mut random = Random(42);
    for _ in 0..60 {
        let mut damaged = LAUNCH_AT_LOGIN.to_vec();
        for _ in 0..4 {
            // Headers and load commands of either slice, and the signatures at the end.
            let region = [0usize, 0x4000, arm64, LAUNCH_AT_LOGIN.len() - 0x6000][(random.next() % 4) as usize];
            let at = region + (random.next() % 0x1800) as usize;
            damaged[at.min(LAUNCH_AT_LOGIN.len() - 1)] = random.next() as u8;
        }
        let _ = analyze(&[("damaged", damaged)]);
    }
}

// ---------------------------------------------------------------- bundles

const INFO_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>com.example.mini</string>
  <key>CFBundleName</key><string>Mini</string>
  <key>CFBundleDisplayName</key><string>Mini App</string>
  <key>CFBundleShortVersionString</key><string>1.2.3</string>
  <key>CFBundleVersion</key><string>45</string>
  <key>CFBundleExecutable</key><string>Mini</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>MinimumOSVersion</key><string>15.0</string>
  <key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array>
  <key>UIDeviceFamily</key><array><integer>1</integer><integer>2</integer></array>
  <key>DTXcode</key><string>1620</string>
  <key>DTSDKName</key><string>iphoneos18.2</string>
  <key>NSCameraUsageDescription</key><string>Scan codes</string>
  <key>NSLocationWhenInUseUsageDescription</key><string></string>
  <key>CFBundleURLTypes</key><array><dict><key>CFBundleURLSchemes</key><array><string>mini</string><string>fb123</string></array></dict></array>
  <key>LSApplicationQueriesSchemes</key><array><string>whatsapp</string></array>
  <key>UIBackgroundModes</key><array><string>audio</string><string>location</string></array>
  <key>UIRequiredDeviceCapabilities</key><array><string>arm64</string></array>
  <key>UIFileSharingEnabled</key><true/>
  <key>NSAppTransportSecurity</key><dict>
    <key>NSAllowsArbitraryLoads</key><true/>
    <key>NSExceptionDomains</key><dict>
      <key>example.org</key><dict>
        <key>NSExceptionAllowsInsecureHTTPLoads</key><true/>
        <key>NSIncludesSubdomains</key><true/>
        <key>NSExceptionMinimumTLSVersion</key><string>TLSv1.0</string>
        <key>NSExceptionRequiresForwardSecrecy</key><false/>
      </dict>
    </dict>
  </dict>
</dict></plist>"#;

const ENTITLEMENTS: &[u8] = br#"<plist><dict>
  <key>application-identifier</key><string>TEAM.com.example.mini</string>
  <key>get-task-allow</key><true/>
  <key>keychain-access-groups</key><array><string>TEAM.com.example.mini</string></array>
  <key>aps-environment</key><string>development</string>
  <key>com.apple.security.application-groups</key><array><string>group.com.example</string></array>
  <key>com.apple.developer.associated-domains</key><array><string>applinks:example.org</string></array>
  <key>com.apple.private.security.no-sandbox</key><true/>
</dict></plist>"#;

const PRIVACY: &str = r#"<plist><dict>
  <key>NSPrivacyTracking</key><true/>
  <key>NSPrivacyTrackingDomains</key><array><string>track.example.net</string></array>
  <key>NSPrivacyCollectedDataTypes</key><array><dict>
    <key>NSPrivacyCollectedDataType</key><string>NSPrivacyCollectedDataTypeDeviceID</string>
    <key>NSPrivacyCollectedDataTypeLinked</key><true/><key>NSPrivacyCollectedDataTypeTracking</key><true/>
  </dict></array>
  <key>NSPrivacyAccessedAPITypes</key><array><dict>
    <key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryUserDefaults</string>
    <key>NSPrivacyAccessedAPITypeReasons</key><array><string>CA92.1</string></array>
  </dict></array>
</dict></plist>"#;

fn base64(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::new();
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().fold(0u32, |total, byte| (total << 8) | *byte as u32) << (8 * (3 - chunk.len()));
        for index in 0..4 {
            encoded.push(if index <= chunk.len() { alphabet[((value >> (18 - 6 * index)) & 63) as usize] as char } else { '=' });
        }
    }
    encoded
}

/// A `CodeResources` sealing `files` by SHA-256 and `nested` code by cdhash.
fn code_resources(files: &[(&str, &[u8])], nested: &[(&str, &[u8])]) -> Vec<u8> {
    let mut xml = String::from("<plist><dict><key>files2</key><dict>");
    for (path, content) in files {
        xml.push_str(&format!("<key>{path}</key><dict><key>hash2</key><data>{}</data></dict>", base64(&sha2::Sha256::digest(content))));
    }
    for (path, code) in nested {
        let fact = crate::inspect::macho_fact(code).expect("mach-o");
        let cdhash = hex::decode(fact["slices"][0]["signature"]["cdhash"].as_str().expect("cdhash")).expect("hex");
        xml.push_str(&format!(
            "<key>{path}</key><dict><key>cdhash</key><data>{}</data><key>requirement</key><string>cdhash</string></dict>",
            base64(&cdhash)
        ));
    }
    xml.push_str("</dict></dict></plist>");
    xml.into_bytes()
}

/// A small iOS-style app inside an IPA-like path.
fn mini_app(executable: Vec<u8>) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("mini.ipa", b"PK\x03\x04".to_vec()),
        ("mini.ipa/Payload/Mini.app/Info.plist", INFO_PLIST.as_bytes().to_vec()),
        ("mini.ipa/Payload/Mini.app/Mini", executable),
        ("mini.ipa/Payload/Mini.app/a.txt", b"sealed".to_vec()),
        ("mini.ipa/Payload/Mini.app/extra.txt", b"added later".to_vec()),
        ("mini.ipa/Payload/Mini.app/PrivacyInfo.xcprivacy", PRIVACY.as_bytes().to_vec()),
        ("mini.ipa/Payload/Mini.app/en.lproj/Main.strings", b"x".to_vec()),
        (
            "mini.ipa/Payload/Mini.app/Frameworks/libswiftCore.dylib",
            signed_macho(&[0x2a; 64], "libswiftCore", b"", codesign::FLAG_ADHOC, 0),
        ),
        ("mini.ipa/Payload/Mini.app/embedded.mobileprovision", PROFILE.to_vec()),
        (
            "mini.ipa/Payload/Mini.app/_CodeSignature/CodeResources",
            code_resources(
                &[
                    ("a.txt", b"sealed"),
                    ("gone.txt", b"was here"),
                    ("PrivacyInfo.xcprivacy", PRIVACY.as_bytes()),
                    ("en.lproj/Main.strings", b"x"),
                    ("embedded.mobileprovision", PROFILE),
                ],
                &[("Frameworks/libswiftCore.dylib", &signed_macho(&[0x2a; 64], "libswiftCore", b"", codesign::FLAG_ADHOC, 0))],
            ),
        ),
    ]
}

fn as_ipa(artifact: &mut Artifact) {
    if artifact.path == "mini.ipa" {
        artifact.unpacked_by = Some("zip".into());
        artifact.kind = Some("zip".into());
    } else {
        artifact.parent = Some("mini.ipa".into());
    }
}

#[test]
fn ios_app_bundle_end_to_end() {
    let executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
    let (_, out) = analyze_with(&mini_app(executable), as_ipa);
    let text = |rule: &str, param: &str| finding(&out, rule).params[param].clone();

    assert!(out.kinds.contains(&("mini.ipa".to_string(), "ipa".to_string())));
    assert_eq!(text("apple.ipa", "app"), "Mini.app");
    assert_eq!(text("apple.bundle-id", "bundle_id"), "com.example.mini");
    assert_eq!(text("apple.bundle-id", "kind"), "app");
    assert_eq!(text("apple.bundle-name", "name"), "Mini App");
    assert_eq!(text("apple.bundle-version", "version"), "1.2.3 (build 45)");
    assert_eq!(text("apple.min-os", "platform"), "iOS");
    assert_eq!(text("apple.device-families", "families"), "iPhone, iPad");
    assert_eq!(text("apple.build-info", "details"), "Xcode 1620, SDK iphoneos18.2");
    assert_eq!(text("apple.executable", "archs"), "arm64");

    assert_eq!(text("apple.usage-description", "resource"), "Camera");
    assert_eq!(text("apple.usage-description", "purpose"), "Scan codes");
    assert_eq!(text("apple.usage-description-empty", "key"), "NSLocationWhenInUseUsageDescription");
    assert_eq!(text("apple.url-schemes", "schemes"), "fb123, mini");
    assert!(finding(&out, "apple.url-schemes").references.contains(&"MASVS-PLATFORM-1".to_string()));
    assert_eq!(text("apple.queried-schemes", "count"), 1);
    assert_eq!(text("apple.background-modes", "modes"), "audio, location");
    assert!(has(&out, "apple.file-sharing") && has(&out, "apple.required-capabilities"));

    let ats = finding(&out, "apple.ats-arbitrary-loads");
    assert_eq!(ats.severity, Severity::Medium);
    assert_eq!(ats.references, ["MASVS-NETWORK-1", "CWE-319"]);
    assert_eq!(text("apple.ats-insecure-domain", "domain"), "example.org");
    assert_eq!(text("apple.ats-weak-tls", "version"), "TLSv1.0");
    assert!(has(&out, "apple.ats-no-forward-secrecy"));

    // Signature: ad-hoc, intact, with entitlements.
    assert!(has(&out, "apple.signature") && has(&out, "apple.signed-adhoc"));
    assert_eq!(text("apple.team-id", "team"), "TEAM");
    assert_eq!(text("apple.code-and-seal-intact", "slots"), "requirements, entitlements");
    assert_eq!(text("apple.entitlements", "count"), 7);
    let debuggable = finding(&out, "apple.debuggable");
    assert_eq!(debuggable.severity, Severity::Low);
    assert_eq!(debuggable.references, ["MASVS-RESILIENCE-4", "CWE-489"]);
    assert_eq!(text("apple.push-notifications", "environment"), "development");
    assert_eq!(text("apple.app-groups", "values"), "group.com.example");
    assert_eq!(text("apple.associated-domains", "values"), "applinks:example.org");
    assert_eq!(text("apple.keychain-groups", "count"), 1);
    assert!(has(&out, "apple.private-entitlements"));

    // Sealed resources: one file gone, one added, the rest intact, nested code by cdhash.
    assert_eq!(text("apple.resources-missing", "paths"), "gone.txt");
    let added = finding(&out, "apple.resources-added");
    assert_eq!(added.evidence.len(), 1);
    assert!(added.evidence[0].artifact.ends_with("extra.txt"));
    assert!(!has(&out, "apple.resources-modified"));

    // Provisioning profile: a development profile for two devices, whose identifiers stay out.
    assert_eq!(text("apple.profile", "name"), "Mini Development");
    assert_eq!(text("apple.profile-development", "devices"), 2);
    assert!(has(&out, "apple.profile-signature-valid"));
    assert_eq!(text("apple.profile-signature-valid", "anchored"), false);
    let mismatch = finding(&out, "apple.profile-entitlement-mismatch");
    assert_eq!(mismatch.params["count"], 4);
    let everything = serde_json::to_string(&out.findings).expect("json") + &format!("{:?}", out.facts);
    assert!(!everything.contains("00008030"), "device identifiers must not leave the profile");

    // Privacy manifest and composition.
    assert_eq!(text("apple.privacy-manifest", "tracking"), true);
    assert_eq!(text("apple.privacy-tracking", "domains"), "track.example.net");
    assert_eq!(text("apple.privacy-collected-data", "types"), "DeviceID (linked to identity, used for tracking)");
    assert_eq!(text("apple.privacy-required-reason-apis", "apis"), "UserDefaults [CA92.1]");
    assert_eq!(text("apple.framework", "framework"), "Swift");
    assert_eq!(text("apple.embedded-code", "summary"), "1 dylib");
    assert_eq!(text("apple.localizations", "languages"), "en");
    assert_eq!(text("apple.code-summary", "count"), 2);

    // Every finding carries evidence, and every rule and limitation has text.
    let known: Vec<&str> = Apple.rules().iter().map(|r| r.id).collect();
    for found in &out.findings {
        assert!(!found.evidence.is_empty(), "{} has no evidence", found.rule);
        assert!(known.contains(&found.rule.as_str()), "{} has no text", found.rule);
        assert!(!found.id.is_empty());
    }
    for limitation in &out.limitations {
        assert!(known.contains(&limitation.code.as_str()), "{} has no text", limitation.code);
    }
}

#[test]
fn analysis_is_deterministic() {
    let run = || {
        let executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
        let (_, out) = analyze_with(&mini_app(executable), as_ipa);
        (serde_json::to_string(&out.findings).expect("json"), format!("{:?}", out.facts), format!("{:?}", out.limitations))
    };
    assert_eq!(run(), run());
}

#[test]
fn tampering_with_a_bundle_is_reported() {
    // A byte of code changed after signing.
    let mut executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
    executable[5000] ^= 0xff;
    let out = analyze(&mini_app(executable));
    let modified = finding(&out, "apple.code-modified");
    assert_eq!((modified.severity, &modified.params["pages"]), (Severity::High, &Value::from(1)));
    assert!(!has(&out, "apple.code-and-seal-intact") && !has(&out, "apple.code-intact"));

    // A sealed resource changed.
    let executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
    let mut files = mini_app(executable);
    files[3].1 = b"changed".to_vec();
    let out = analyze(&files);
    let modified = finding(&out, "apple.resources-modified");
    assert_eq!(modified.severity, Severity::High);
    assert!(modified.evidence[0].artifact.ends_with("a.txt"));

    // Nested code replaced by something signed differently.
    let executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
    let mut files = mini_app(executable);
    files[7].1 = signed_macho(&[0x2b; 64], "libswiftCore", b"", codesign::FLAG_ADHOC, 0);
    let out = analyze(&files);
    assert_eq!(finding(&out, "apple.nested-code-replaced").params["paths"], "Frameworks/libswiftCore.dylib");

    // The entitlements blob edited inside the signature.
    let mut executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, codesign::FLAG_ADHOC, 0);
    let needle = b"development";
    let at = executable.windows(needle.len()).position(|w| w == needle).expect("entitlement value");
    executable[at..at + needle.len()].copy_from_slice(b"production!");
    let out = analyze(&mini_app(executable));
    assert_eq!(finding(&out, "apple.seal-broken").params["slot"], "entitlements");
}

#[test]
fn fairplay_encryption_is_a_finding_and_a_limitation() {
    let executable = signed_macho(&[0x1f; 9000], "com.example.mini", ENTITLEMENTS, 0, 1);
    let out = analyze(&mini_app(executable));
    let found = finding(&out, "apple.fairplay");
    assert_eq!(found.params["bytes"], 9000);
    assert!(
        out.limitations
            .iter()
            .any(|l| l.code == "apple.fairplay-encrypted" && l.artifact.as_deref() == Some("mini.ipa/Payload/Mini.app/Mini"))
    );
    // Encrypted pages are neither called intact nor modified.
    assert!(!has(&out, "apple.code-modified") && !has(&out, "apple.code-intact") && !has(&out, "apple.code-and-seal-intact"));
}

#[test]
fn unsigned_and_missing_executables() {
    let unsigned = crate::macho::tests::build(&[0; 64], b"", 0);
    // The helper always writes a signature command; point it at nothing by cutting the command count.
    let mut unsigned = unsigned;
    unsigned[16..20].copy_from_slice(&2u32.to_le_bytes());
    unsigned[20..24].copy_from_slice(&96u32.to_le_bytes());
    let out = analyze(&mini_app(unsigned));
    assert_eq!(finding(&out, "apple.unsigned").severity, Severity::Medium);

    let mut files = mini_app(Vec::new());
    files.remove(2);
    let out = analyze(&files);
    assert_eq!(finding(&out, "apple.executable-missing").params["executable"], "Mini");

    let mut files = mini_app(b"#!/bin/sh\nexec true\n".to_vec());
    files[1].1 = INFO_PLIST.replace("com.example.mini", "com.example.other").into_bytes();
    let out = analyze(&files);
    assert!(has(&out, "apple.executable-not-macho"));
}

#[test]
fn unreadable_property_lists_are_limitations() {
    let files = vec![
        ("X.app/Contents/Info.plist", b"bplist00 this is not a plist".to_vec()),
        ("Y.app/Info.plist", b"<plist><dict><key>CFBundleName</key><string>Y</string></dict></plist>".to_vec()),
        ("Y.app/embedded.mobileprovision", b"not a profile".to_vec()),
        ("Y.app/Y", b"x".to_vec()),
    ];
    let out = analyze(&files);
    assert!(
        out.limitations.iter().any(|l| l.code == "apple.plist-unreadable" && l.artifact.as_deref() == Some("X.app/Contents/Info.plist"))
    );
    assert!(has(&out, "apple.bundle-id-missing"));
    let hostile: Vec<(&str, Vec<u8>)> = vec![
        ("Z.app/Info.plist", INFO_PLIST.replace("<string>Mini</string>", "<array><dict/></array>").into_bytes()),
        ("Z.app/_CodeSignature/CodeResources", b"<plist><dict><key>files2</key><string>no</string></dict></plist>".to_vec()),
        ("Z.app/PrivacyInfo.xcprivacy", b"<plist><array/></plist>".to_vec()),
    ];
    let _ = analyze(&hostile);
}

#[test]
fn macos_bundle_with_hardening_findings() {
    let entitlements = br#"<plist><dict>
      <key>com.apple.security.cs.disable-library-validation</key><true/>
      <key>com.apple.security.cs.allow-jit</key><true/>
      <key>com.apple.security.get-task-allow</key><true/></dict></plist>"#;
    let info = INFO_PLIST.replace("MinimumOSVersion", "LSMinimumSystemVersion").replace("iPhoneOS", "MacOSX");
    let files = vec![
        ("Mac.app/Contents/Info.plist", info.into_bytes()),
        (
            "Mac.app/Contents/MacOS/Mini",
            signed_macho(&[7; 5000], "com.example.mini", entitlements, codesign::FLAG_ADHOC | codesign::FLAG_RUNTIME, 0),
        ),
        ("Mac.app/Contents/CodeResources", vec![1; 100]),
        (
            "Mac.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Resources/Info.plist",
            b"<plist><dict><key>CFBundleIdentifier</key><string>com.github.Electron.framework</string></dict></plist>".to_vec(),
        ),
        ("Mac.app/Contents/Resources/app.asar", vec![0; 16]),
    ];
    let out = analyze(&files);
    assert_eq!(finding(&out, "apple.min-os").params["platform"], "macOS");
    assert!(has(&out, "apple.hardened-runtime"));
    assert!(has(&out, "apple.sandbox-off"));
    assert_eq!(out.findings.iter().filter(|f| f.rule == "apple.runtime-exception").count(), 2);
    assert_eq!(finding(&out, "apple.notarization-ticket").params["bytes"], 100);
    assert_eq!(finding(&out, "apple.framework").params["framework"], "Electron");
    assert_eq!(finding(&out, "apple.embedded-code").params["summary"], "1 framework");
    assert!(has(&out, "apple.debuggable"));
}
