//! Appx block declarations and captured uncompressed bytes, independent of package authentication.

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use roxmltree::Node;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Digest;

const NS: &str = "http://schemas.microsoft.com/appx/2010/blockmap";
const NS2021: &str = "http://schemas.microsoft.com/appx/2021/blockmap";
const BLOCK_SIZE: usize = 65536;
const MAX_XML: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 4096;
const MAX_BLOCKS: usize = 32768;
const MAX_FACT: usize = 8 * 1024 * 1024;
const MAX_PAYLOAD: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_PAYLOAD: u64 = 512 * 1024 * 1024;

#[derive(Serialize)]
struct Block {
    digest: String,
    compressed_size: Option<u64>,
}

#[derive(Serialize)]
struct File {
    name: String,
    path: Option<String>,
    size: u64,
    local_file_header_size: u64,
    blocks: Vec<Block>,
    file_digest: Option<String>,
    unresolved: Option<&'static str>,
}

#[derive(Serialize)]
struct Map {
    source_sha256: String,
    hash_method: String,
    algorithm: Option<&'static str>,
    files: Vec<File>,
    block_count: usize,
    block_size: usize,
    payloads_checked: bool,
    package_signature_checked: bool,
    zip_structure_checked: bool,
}

fn algorithm(uri: &str) -> Option<&'static str> {
    match uri {
        "http://www.w3.org/2001/04/xmlenc#sha256" => Some("sha256"),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Some("sha384"),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Some("sha512"),
        _ => None,
    }
}

fn number(value: Option<&str>) -> Result<u64, &'static str> {
    let value = value.ok_or("a required block-map integer is absent")?.trim_matches([' ', '\t', '\r', '\n']);
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("block-map integer is outside the unsigned decimal profile");
    }
    value.parse().map_err(|_| "block-map integer overflow")
}

fn shape(node: Node<'_, '_>, name: &str, attributes: &[&str]) -> Result<(), &'static str> {
    shape_in(node, name, attributes, NS)
}

fn shape_in(node: Node<'_, '_>, name: &str, attributes: &[&str], namespace: &str) -> Result<(), &'static str> {
    if node.tag_name().name() != name
        || node.tag_name().namespace() != Some(namespace)
        || node.attributes().any(|a| a.namespace().is_some() || !attributes.contains(&a.name()))
        || node.children().any(|n| n.is_text() && n.text().is_some_and(|s| !s.trim().is_empty()))
    {
        return Err("unsupported block-map element, attribute or text content");
    }
    Ok(())
}

fn digest(text: Option<&str>, algorithm: Option<&str>) -> Result<String, &'static str> {
    let hash = text.filter(|s| s.len() <= 256).ok_or("missing or oversized content hash")?;
    let compact: String = hash.chars().filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n')).collect();
    let digest = STANDARD.decode(compact).map_err(|_| "content hash is not supported base64")?;
    let expected = match algorithm {
        Some("sha256") => 32,
        Some("sha384") => 48,
        Some("sha512") => 64,
        _ => digest.len(),
    };
    if digest.is_empty() || digest.len() > 64 || digest.len() != expected {
        return Err("content hash has an invalid digest width");
    }
    Ok(hex::encode(digest))
}

fn xml(bytes: &[u8]) -> Result<String, &'static str> {
    let text = crate::text::decode(bytes, MAX_XML)?;
    if text.contains("<!DOCTYPE") {
        return Err("DTDs are unsupported in block maps");
    }
    if let Some(header) = text.strip_prefix("<?xml").and_then(|s| s.split_once("?>").map(|p| p.0))
        && let Some(encoding) = header.split_once("encoding").map(|p| p.1.trim_start())
    {
        let value = encoding.strip_prefix('=').map(str::trim_start).ok_or("invalid XML encoding declaration")?;
        let quote = value.chars().next().filter(|q| matches!(q, '\'' | '"')).ok_or("invalid XML encoding declaration")?;
        let declared = value.get(1..).and_then(|s| s.split(quote).next()).unwrap_or("").to_ascii_lowercase();
        let matches = if bytes.starts_with(&[0xff, 0xfe]) {
            matches!(declared.as_str(), "utf-16" | "utf-16le")
        } else if bytes.starts_with(&[0xfe, 0xff]) {
            matches!(declared.as_str(), "utf-16" | "utf-16be")
        } else {
            matches!(declared.as_str(), "utf-8" | "utf8")
        };
        if !matches {
            return Err("block-map XML declaration and byte encoding do not match the supported profile");
        }
    }
    Ok(text)
}

fn parse(bytes: &[u8]) -> Result<Map, &'static str> {
    let text = xml(bytes)?;
    let options = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 100_000 };
    let document =
        roxmltree::Document::parse_with_options(&text, options).map_err(|_| "block-map XML is malformed or exceeds its node budget")?;
    let root = document.root_element();
    shape(root, "BlockMap", &["HashMethod", "IgnorableNamespaces"])?;
    let ignorable = root.attribute("IgnorableNamespaces").unwrap_or("");
    if ignorable.len() > 512
        || ignorable.split_ascii_whitespace().count() > 8
        || ignorable.split_ascii_whitespace().any(|prefix| root.lookup_namespace_uri(Some(prefix)) != Some(NS2021))
    {
        return Err("unsupported block-map extension namespace profile");
    }
    let modern = !ignorable.trim().is_empty();
    let method =
        root.attribute("HashMethod").filter(|s| !s.is_empty() && s.len() <= 512).ok_or("missing or oversized block-map hash method")?;
    let algo = algorithm(method);
    let mut files = Vec::new();
    let mut count = 0;
    for file in root.children().filter(Node::is_element) {
        shape(file, "File", &["Name", "Size", "LfhSize"])?;
        if files.len() >= MAX_FILES {
            return Err("block-map file-count budget exceeded");
        }
        let name = file
            .attribute("Name")
            .filter(|s| !s.is_empty() && s.len() <= 8192 && s.encode_utf16().count() <= 32767)
            .ok_or("missing or oversized block-map file name")?;
        let name_safe = aa_core::text::redact_sensitive_text(name)?;
        let path = name.replace('\\', "/");
        let supported = name == name_safe && path.split('/').all(crate::references::ordinary_component);
        let size = number(file.attribute("Size"))?;
        let header = number(file.attribute("LfhSize"))?;
        if !(30..=65536).contains(&header) {
            return Err("block-map local-file-header size is outside the supported range");
        }
        let mut blocks = Vec::new();
        let mut file_digest = None;
        for block in file.children().filter(Node::is_element) {
            if block.tag_name().namespace() == Some(NS2021) && modern {
                shape_in(block, "FileHash", &["Hash"], NS2021)?;
                if file_digest.is_some() || block.children().any(|n| n.is_element()) {
                    return Err("duplicate or nested block-map FileHash extension");
                }
                file_digest = Some(digest(block.attribute("Hash"), algo)?);
                continue;
            }
            if file_digest.is_some() {
                return Err("a Block follows the FileHash extension");
            }
            shape(block, "Block", &["Hash", "Size"])?;
            if block.children().any(|n| n.is_element()) {
                return Err("block-map Block element has child elements");
            }
            if count >= MAX_BLOCKS {
                return Err("block-map block-count budget exceeded");
            }
            let digest = digest(block.attribute("Hash"), algo)?;
            let compressed_size = block.attribute("Size").map(|s| number(Some(s))).transpose()?;
            if compressed_size == Some(0) {
                return Err("compressed block size must be positive");
            }
            blocks.push(Block { digest, compressed_size });
            count += 1;
        }
        let expected_blocks = size / BLOCK_SIZE as u64 + u64::from(size % BLOCK_SIZE as u64 != 0);
        let unresolved = if !supported {
            Some("unsupported-or-redacted-file-path")
        } else if expected_blocks != blocks.len() as u64 {
            Some("declared-size-and-block-count-disagree")
        } else {
            None
        };
        files.push(File {
            name: name_safe,
            path: supported.then_some(path),
            size,
            local_file_header_size: header,
            blocks,
            file_digest,
            unresolved,
        });
    }
    if files.is_empty() {
        return Err("block map contains no File elements");
    }
    // Windows file names are case-insensitive. Keep every declaration, but never select
    // one of several equal names as the block sequence for a supplied target.
    let mut names = std::collections::BTreeMap::<String, usize>::new();
    for file in &files {
        if let Some(path) = &file.path {
            *names.entry(path.to_ascii_lowercase()).or_default() += 1;
        }
    }
    for file in &mut files {
        if file.path.as_ref().is_some_and(|p| names.get(&p.to_ascii_lowercase()).copied().unwrap_or(0) > 1) {
            file.unresolved = Some("duplicate-or-case-aliased-file-declarations");
        }
    }
    let map = Map {
        source_sha256: aa_core::sha256_hex(bytes),
        hash_method: aa_core::text::redact_sensitive_text(method)?,
        algorithm: algo,
        files,
        block_count: count,
        block_size: BLOCK_SIZE,
        payloads_checked: false,
        package_signature_checked: false,
        zip_structure_checked: false,
    };
    if serde_json::to_vec(&map).map_err(|_| "block-map publication failed")?.len() > MAX_FACT {
        return Err("block-map serialized declaration budget exceeded");
    }
    Ok(map)
}

pub fn analyze_file(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !file.name().eq_ignore_ascii_case("AppxBlockMap.xml") {
        return;
    }
    let map = match parse(bytes) {
        Ok(map) => map,
        Err(reason) => {
            out.limitation("windows.msix-blockmap-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    if file.digests.as_ref().is_some_and(|d| d.sha256 != map.source_sha256) {
        out.limitation("windows.msix-blockmap-unreadable", Some(file), Some("block-map bytes differ from the captured digest".into()));
        return;
    }
    if map.algorithm.is_none() || map.files.iter().any(|f| f.unresolved.is_some()) {
        out.limitation("windows.msix-blockmap-unresolved", Some(file), None);
    }
    out.kind(file, "msix-block-map");
    out.finding(
        Finding::new(Section::Provenance, "windows", "windows.msix-blockmap", Confidence::Verified, Severity::Info)
            .param("files", map.files.len())
            .param("blocks", map.block_count)
            .evidence(Evidence::field(file, "BlockMap/HashMethod", map.hash_method.as_str()))
            .evidence(Evidence::field(file, "BlockMap/File count", map.files.len())),
    );
    out.limitation("windows.msix-blockmap-scope", Some(file), None);
    out.fact(file, "windows.msix-blockmap", json!(map));
}

fn computed(algorithm: &str, bytes: &[u8]) -> Option<String> {
    Some(match algorithm {
        "sha256" => hex::encode(sha2::Sha256::digest(bytes)),
        "sha384" => hex::encode(sha2::Sha384::digest(bytes)),
        "sha512" => hex::encode(sha2::Sha512::digest(bytes)),
        _ => return None,
    })
}

pub fn analyze_tree(tree: &dyn Tree, out: &mut Output) {
    check_tree(tree, out, MAX_TOTAL_PAYLOAD, MAX_FILES, MAX_BLOCKS, MAX_FACT);
}

fn check_tree(
    tree: &dyn Tree,
    out: &mut Output,
    mut bytes_left: u64,
    mut files_left: usize,
    mut blocks_left: usize,
    mut output_left: usize,
) {
    let maps: Vec<_> = tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.msix-blockmap")).take(33).collect();
    if maps.is_empty() {
        return;
    }
    if maps.len() > 32 {
        out.limitation("windows.msix-blockmap-limit", None, Some("only the first 32 block maps were considered".into()));
    }
    let complete = tree.summary().get("engine.input-listing").and_then(|v| v.get("complete")).and_then(Value::as_bool) == Some(true);
    let index = match crate::references::Index::for_distribution_roots(tree.artifacts(), complete) {
        Ok(index) => index,
        Err(reason) => {
            out.limitation("windows.msix-blockmap-limit", None, Some(reason.into()));
            return;
        }
    };
    for source in maps.into_iter().take(32) {
        let map = &source.facts["windows.msix-blockmap"];
        let source_matches = source.digests.as_ref().is_some_and(|d| map["source_sha256"] == d.sha256);
        let root = source.path.rsplit_once('/').map_or(".", |p| p.0).to_ascii_lowercase();
        let mut records = Vec::new();
        let mut matched = 0;
        let mut mismatched = 0;
        let mut unresolved = 0;
        let mut omitted = 0;
        let mut agreements = Vec::new();
        let mut failures = Vec::new();
        for (position, row) in map["files"].as_array().into_iter().flatten().enumerate() {
            if files_left == 0 {
                omitted += 1;
                continue;
            }
            files_left -= 1;
            let mut record = json!({"file":position,"name":row["name"],"status":"unresolved"});
            let result = (|| -> Result<(), &'static str> {
                if !source_matches {
                    return Err("block-map-source-digest-not-established");
                }
                if row["unresolved"].as_str().is_some() {
                    return Err("unsupported-file-declaration");
                }
                let algorithm =
                    map["algorithm"].as_str().filter(|a| matches!(*a, "sha256" | "sha384" | "sha512")).ok_or("unsupported-hash-method")?;
                let path = row["path"].as_str().ok_or("unsupported-file-path")?;
                let target = index.resolve_distribution(source, &root, path)?;
                let digests = target.digests.as_ref().ok_or("target-digest-not-captured")?;
                if target.size > MAX_PAYLOAD || target.size > bytes_left {
                    return Err("payload-byte-budget-exhausted");
                }
                let declared = row["blocks"].as_array().ok_or("block-list-not-read")?;
                if declared.len() > blocks_left {
                    return Err("block-check-budget-exhausted");
                }
                bytes_left -= target.size;
                blocks_left -= declared.len();
                let bytes = tree.read(&target.path).map_err(|_| "supplied-target-unreadable")?;
                if bytes.len() as u64 != target.size || bytes.len() as u64 > MAX_PAYLOAD {
                    return Err("target-byte-length-changed");
                }
                let snapshot = bytes.to_vec();
                if aa_core::sha256_hex(&snapshot) != digests.sha256 {
                    return Err("target-bytes-do-not-match-captured-digest");
                }
                let size_matches = row["size"].as_u64() == Some(target.size);
                let mut failed = 0usize;
                let mut checked = 0usize;
                let mut details = Vec::new();
                let mut first_block = None;
                if size_matches {
                    for (block, data) in snapshot.chunks(BLOCK_SIZE).enumerate() {
                        let actual = computed(algorithm, data).ok_or("unsupported-hash-method")?;
                        let expected = declared.get(block).and_then(|b| b["digest"].as_str()).ok_or("block-list-length-disagrees")?;
                        checked += 1;
                        if block == 0 {
                            first_block = Some(json!({"expected":expected,"computed":actual,"size":data.len()}));
                        }
                        if actual != expected {
                            failed += 1;
                            if details.len() < 8 {
                                details.push(json!({"block":block,"offset":block*BLOCK_SIZE,"size":data.len(),"expected":expected,"computed":actual}));
                            }
                        }
                    }
                }
                let file_digest = if let Some(expected) = row["file_digest"].as_str() {
                    let actual = computed(algorithm, &snapshot).ok_or("unsupported-hash-method")?;
                    Some(json!({"expected":expected,"computed":actual,"matches":expected==actual}))
                } else {
                    None
                };
                let agrees = size_matches && failed == 0 && file_digest.as_ref().is_none_or(|v| v["matches"] == true);
                record = json!({"file":position,"name":row["name"],"target":target.path,"target_sha256":digests.sha256,
                    "status":if agrees {"hashes-agree"} else {"size-or-content-hash-mismatch"},"size_matches":size_matches,
                    "declared_size":row["size"],"captured_size":target.size,"checked_blocks":checked,"failed_blocks":failed,
                    "failure_details":details,"failure_details_omitted":failed.saturating_sub(8),"first_block":first_block,"file_digest":file_digest,"algorithm":algorithm});
                if agrees {
                    matched += 1;
                    if agreements.len() < 6 {
                        agreements.push((position, target));
                    }
                } else {
                    mismatched += 1;
                    if failures.len() < 6 {
                        failures.push((position, target, record.clone()));
                    }
                }
                Ok(())
            })();
            if let Err(reason) = result {
                record["reason"] = json!(reason);
                unresolved += 1;
            }
            let cost = serde_json::to_vec(&record).map_or(usize::MAX, |v| v.len());
            if cost > output_left {
                omitted += 1;
                continue;
            }
            output_left -= cost;
            records.push(record);
        }
        for (rule, severity, count, examples) in [
            ("windows.msix-block-hashes", Severity::Info, matched, &agreements),
            (
                "windows.msix-content-hash-mismatch",
                Severity::High,
                mismatched,
                &failures.iter().map(|(i, t, _)| (*i, *t)).collect::<Vec<_>>(),
            ),
        ] {
            if count == 0 {
                continue;
            }
            let mut finding = Finding::new(Section::Provenance, "windows", rule, Confidence::Verified, severity).param("count", count);
            for (position, target) in examples {
                let row = &map["files"][*position];
                finding = finding.evidence(Evidence::field(source,format!("BlockMap/File/{position}"),
                    json!({"name":row["name"],"size":row["size"],"blocks":row["blocks"].as_array().map(Vec::len),"hash_method":map["hash_method"]})))
                    .evidence(Evidence::field(target,"captured bytes/SHA256",target.digests.as_ref().map(|d|d.sha256.as_str()).unwrap_or("")));
                if let Some(first) = row["blocks"].as_array().and_then(|b| b.first()) {
                    finding = finding.evidence(Evidence::field(
                        source,
                        format!("BlockMap/File/{position}/Block/0/Hash"),
                        first["digest"].clone(),
                    ));
                }
            }
            if severity == Severity::High {
                for (_, _, record) in &failures {
                    finding = finding.evidence(Evidence::field(source, "computed block comparison", record.clone()));
                }
            }
            out.finding(finding);
        }
        if unresolved > 0 {
            out.limitation("windows.msix-blockmap-unresolved", Some(source), Some(aa_core::counted(unresolved, "files were unresolved")));
        }
        if omitted > 0 {
            out.limitation("windows.msix-blockmap-limit", Some(source), Some(aa_core::counted(omitted, "file results were omitted")));
        }
        out.fact(source,"windows.msix-blockmap-checks",json!({"basis":"block-map-containing-directory-within-parent-container","root":root,
            "files":records,"files_omitted":omitted,"files_with_matching_hashes":matched,"files_with_mismatches":mismatched,"files_unresolved":unresolved,
            "package_signature_checked":false,"zip_structure_checked":false,"compressed_block_sizes_checked":false,"windows_trust_checked":false}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;
    use aa_core::plugin::Bytes;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Supplied {
        artifacts: Vec<Artifact>,
        contents: BTreeMap<String, Vec<u8>>,
        summary: BTreeMap<String, Value>,
        reads: AtomicUsize,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.artifacts
        }
        fn summary(&self) -> &BTreeMap<String, Value> {
            &self.summary
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.contents.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::other("not supplied"))
        }
    }
    fn artifact(path: &str, data: &[u8]) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: data.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: aa_core::sha256_hex(data) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }
    fn map(data: &[u8], method: &str) -> Vec<u8> {
        let mut xml =
            format!(r#"<BlockMap xmlns="{NS}" HashMethod="{method}"><File Name="payload.bin" Size="{}" LfhSize="41">"#, data.len());
        let algo = algorithm(method).expect("test algorithm");
        for block in data.chunks(BLOCK_SIZE) {
            let digest = hex::decode(computed(algo, block).expect("test digest")).expect("digest bytes");
            xml.push_str(&format!(r#"<Block Hash="{}"/>"#, STANDARD.encode(digest)));
        }
        xml.push_str("</File></BlockMap>");
        xml.into_bytes()
    }
    fn supplied(map: Vec<u8>, data: &[u8]) -> Supplied {
        let mut source = artifact("pkg/AppxBlockMap.xml", &map);
        let mut out = Output::default();
        analyze_file(&source, &map, &mut out);
        for fact in out.facts {
            source.facts.insert(fact.key, fact.value);
        }
        Supplied {
            artifacts: vec![source, artifact("pkg/payload.bin", data)],
            contents: BTreeMap::from([("pkg/AppxBlockMap.xml".into(), map), ("pkg/payload.bin".into(), data.to_vec())]),
            summary: BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]),
            reads: AtomicUsize::new(0),
        }
    }
    fn comparison(out: &Output) -> &Value {
        &out.facts.iter().find(|f| f.key == "windows.msix-blockmap-checks").expect("comparison").value
    }
    const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";

    #[test]
    fn modern_file_hashes_are_independent_checks_with_strict_namespace_and_ordering() {
        let original = String::from_utf8(map(b"abc", SHA256)).expect("XML");
        let extension = format!(r#"<b4:FileHash Hash="{}"/>"#, STANDARD.encode([0; 32]));
        let modern = original
            .replace("<BlockMap ", &format!(r#"<BlockMap xmlns:b4="{NS2021}" IgnorableNamespaces="b4" "#))
            .replace("</File>", &format!("{extension}</File>"));
        let input = supplied(modern.as_bytes().to_vec(), b"abc");
        let mut out = Output::default();
        analyze_tree(&input, &mut out);
        let record = &comparison(&out)["files"][0];
        assert_eq!(record["failed_blocks"], 0);
        assert_eq!(record["file_digest"]["matches"], false);
        assert!(out.findings.iter().any(|f| f.rule == "windows.msix-content-hash-mismatch"));
        for invalid in [
            modern.replace("IgnorableNamespaces=\"b4\"", "IgnorableNamespaces=\"missing\""),
            modern.replace(NS2021, "urn:unknown"),
            modern.replace(&extension, &format!("{extension}{extension}")),
            modern.replace("<Block Hash", &format!("{extension}<Block Hash")),
            modern.replace("b4:FileHash", "b4:Other"),
        ] {
            assert!(parse(invalid.as_bytes()).is_err());
        }
        let mut source = artifact("AppxBlockMap.xml", original.as_bytes());
        source.digests.as_mut().expect("digest").sha256 = "0".repeat(64);
        let mut out = Output::default();
        analyze_file(&source, original.as_bytes(), &mut out);
        assert!(out.facts.is_empty());
        assert!(out.limitations.iter().any(|l| l.code == "windows.msix-blockmap-unreadable"));
    }

    #[test]
    fn all_three_supported_hash_algorithms_check_fixed_64k_blocks_and_the_remainder() {
        let bytes = vec![0x5a; BLOCK_SIZE + 7];
        for method in [SHA256, "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512"] {
            let input = supplied(map(&bytes, method), &bytes);
            let mut out = Output::default();
            analyze_tree(&input, &mut out);
            let record = &comparison(&out)["files"][0];
            assert_eq!(record["status"], "hashes-agree");
            assert_eq!(record["checked_blocks"], 2);
            assert_eq!(record["first_block"]["computed"], record["first_block"]["expected"]);
            assert_eq!(comparison(&out)["package_signature_checked"], false);
            assert_eq!(comparison(&out)["zip_structure_checked"], false);
            assert_eq!(comparison(&out)["compressed_block_sizes_checked"], false);
            assert!(out.findings.iter().all(|f| !f.evidence.is_empty()));
            let mut changed = bytes.clone();
            changed[BLOCK_SIZE] ^= 1;
            let changed = supplied(map(&bytes, method), &changed);
            let mut out = Output::default();
            analyze_tree(&changed, &mut out);
            let record = &comparison(&out)["files"][0];
            assert_eq!(record["failed_blocks"], 1);
            assert_eq!(record["failure_details"][0]["block"], 1);
            assert_eq!(record["failure_details"][0]["offset"], BLOCK_SIZE);
            assert!(out.findings.iter().any(|f| f.rule == "windows.msix-content-hash-mismatch" && f.severity == Severity::High));
        }
    }

    #[test]
    fn size_changes_empty_files_and_unknown_algorithms_have_distinct_results() {
        for bytes in [b"".as_slice(), b"abc"] {
            let input = supplied(map(bytes, SHA256), bytes);
            let mut out = Output::default();
            analyze_tree(&input, &mut out);
            assert_eq!(comparison(&out)["files"][0]["status"], "hashes-agree");
        }
        let input = supplied(map(b"abc", SHA256), b"abcd");
        let mut out = Output::default();
        analyze_tree(&input, &mut out);
        assert_eq!(comparison(&out)["files"][0]["size_matches"], false);
        assert_eq!(comparison(&out)["files"][0]["checked_blocks"], 0);
        let xml = String::from_utf8(map(b"abc", SHA256)).expect("XML").replace(SHA256, "urn:unsupported");
        let input = supplied(xml.into_bytes(), b"abc");
        let mut out = Output::default();
        analyze_tree(&input, &mut out);
        assert_eq!(comparison(&out)["files"][0]["reason"], "unsupported-hash-method");
        assert_eq!(input.reads.load(Ordering::Relaxed), 0);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn stale_bytes_ambiguous_names_incomplete_listings_and_external_containers_are_unresolved() {
        for case in 0..5 {
            let mut input = supplied(map(b"abc", SHA256), b"abc");
            match case {
                0 => {
                    input.contents.insert("pkg/payload.bin".into(), b"xyz".to_vec());
                }
                1 => {
                    input.artifacts.push(artifact("pkg/PAYLOAD.bin", b"abc"));
                }
                2 => {
                    input.summary.clear();
                }
                3 => {
                    input.artifacts[1].path = "other/payload.bin".into();
                    input.artifacts[1].parent = Some("other".into());
                }
                _ => {
                    input.artifacts[0].digests = None;
                }
            }
            let mut out = Output::default();
            analyze_tree(&input, &mut out);
            assert_eq!(comparison(&out)["files"][0]["status"], "unresolved");
            assert!(out.findings.is_empty());
            assert!(out.limitations.iter().any(|l| l.code == "windows.msix-blockmap-unresolved"));
            if case != 0 {
                assert_eq!(input.reads.load(Ordering::Relaxed), 0);
            }
        }
    }

    #[test]
    fn repeated_file_declarations_and_unsupported_paths_do_not_select_a_hash_sequence() {
        let xml = String::from_utf8(map(b"abc", SHA256)).expect("XML");
        let file = xml.split_once("<File").expect("File").1.split_once("</File>").expect("File end").0;
        let duplicate = xml.replace("</BlockMap>", &format!("<File{file}</File></BlockMap>"));
        let parsed = parse(duplicate.as_bytes()).expect("preserved duplicates");
        assert!(parsed.files.iter().all(|f| f.unresolved == Some("duplicate-or-case-aliased-file-declarations")));
        for path in ["../payload.bin", "C:/payload.bin", "CON", "dir//payload.bin", "payload.bin ", "驱动.bin"] {
            let parsed = parse(xml.replace("payload.bin", path).as_bytes()).expect("unsupported path declaration retained");
            assert!(parsed.files[0].path.is_none());
        }
        let long = format!("{}/file.bin", vec!["a".repeat(200); 4].join("/"));
        let parsed = parse(xml.replace("payload.bin", &long).as_bytes()).expect("long logical path within the byte profile");
        assert_eq!(parsed.files[0].path.as_deref(), Some(long.as_str()));
        let token = format!("ghp_{}", "a".repeat(36));
        let parsed = parse(xml.replace("payload.bin", &format!("{token}.bin")).as_bytes()).expect("redacted name");
        assert!(parsed.files[0].path.is_none());
        assert!(!serde_json::to_string(&parsed).expect("fact").contains(&token));
        let broken = xml.replace("Size=\"3\"", "Size=\"65537\"");
        assert_eq!(
            parse(broken.as_bytes()).expect("inconsistent row retained").files[0].unresolved,
            Some("declared-size-and-block-count-disagree")
        );
    }

    #[test]
    fn parse_limits_encoding_and_xml_structure_fail_explicitly() {
        let xml = String::from_utf8(map(b"abc", SHA256)).expect("XML");
        for bad in [
            xml.replace(NS, "urn:other"),
            xml.replace("Size=\"3\"", "Size=\"18446744073709551616\""),
            xml.replace("LfhSize=\"41\"", "LfhSize=\"29\""),
            xml.replace("<Block ", "<Block Size=\"0\" "),
            format!("<!DOCTYPE BlockMap []>{xml}"),
            format!("<?xml version=\"1.0\" encoding=\"UTF-16\"?>{xml}"),
            xml.replace("<File ", "<File Other=\"x\" "),
        ] {
            assert!(parse(bad.as_bytes()).is_err());
        }
        assert!(parse(&vec![b'x'; MAX_XML + 1]).is_err());
        let many_files = format!(
            r#"<BlockMap xmlns="{NS}" HashMethod="{SHA256}">{}</BlockMap>"#,
            r#"<File Name="x" Size="0" LfhSize="31"/>"#.repeat(MAX_FILES + 1)
        );
        assert!(parse(many_files.as_bytes()).is_err());
        let block = format!(r#"<Block Hash="{}"/>"#, STANDARD.encode([0; 32]));
        let many_blocks = format!(
            r#"<BlockMap xmlns="{NS}" HashMethod="{SHA256}"><File Name="x" Size="1" LfhSize="31">{}</File></BlockMap>"#,
            block.repeat(MAX_BLOCKS + 1)
        );
        assert!(parse(many_blocks.as_bytes()).is_err());
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        assert!(parse(&utf16).is_ok());
        utf16.pop();
        assert!(parse(&utf16).is_err());
        for cut in 0..xml.len() {
            assert!(parse(&xml.as_bytes()[..cut]).is_err());
        }
    }

    #[test]
    fn global_byte_file_block_and_result_budgets_keep_unchecked_work_visible() {
        for (bytes, files, blocks, output) in [(2, 1, 1, 4096), (3, 0, 1, 4096), (3, 1, 0, 4096), (3, 1, 1, 0)] {
            let input = supplied(map(b"abc", SHA256), b"abc");
            let mut out = Output::default();
            check_tree(&input, &mut out, bytes, files, blocks, output);
            let fact = comparison(&out);
            assert!(fact["files_unresolved"] == 1 || fact["files_omitted"] == 1);
            assert!(
                out.limitations
                    .iter()
                    .any(|l| matches!(l.code.as_str(), "windows.msix-blockmap-unresolved" | "windows.msix-blockmap-limit"))
            );
            if bytes < 3 || files == 0 || blocks == 0 {
                assert_eq!(input.reads.load(Ordering::Relaxed), 0);
            }
        }
    }
}
