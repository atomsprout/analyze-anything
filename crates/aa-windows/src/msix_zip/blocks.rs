//! Bind physical block extents to original bytes and the captured uncompressed artifact.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use flate2::{Decompress, FlushDecompress, Status};
use serde_json::{Value, json};

use super::{Entry, Result, span};

const BLOCK: usize = 65536;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_COMPRESSED_BLOCK: usize = 256 * 1024;

pub(super) struct Budget {
    files: usize,
    blocks: usize,
    work: u64,
    output: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self { files: 4096, blocks: 32768, work: 512 * 1024 * 1024, output: 8 * 1024 * 1024 }
    }
}

impl Budget {
    pub(super) fn attempt(&mut self) -> Result<()> {
        self.files = self.files.checked_sub(1).ok_or("raw block file-attempt budget exhausted")?;
        Ok(())
    }
}

fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>> {
    // The output bound is independently checked before allocation, including in block calls.
    if size as u64 > MAX_FILE {
        return Err("raw block plain-byte allocation limit");
    }
    let mut output = vec![0; size + 1];
    let mut decoder = Decompress::new(false);
    let status =
        decoder.decompress(data, &mut output, FlushDecompress::Finish).map_err(|_| "DEFLATE stream outside independent-block profile")?;
    if status != Status::StreamEnd || decoder.total_in() != data.len() as u64 || decoder.total_out() != size as u64 {
        return Err("DEFLATE stream length, terminator or output size outside independent-block profile");
    }
    output.truncate(size);
    Ok(output)
}

pub(super) fn check_file(
    bytes: &[u8],
    entry: &Entry<'_>,
    row: &Value,
    algorithm: Option<&str>,
    target: &Artifact,
    budget: &mut Budget,
) -> Result<Value> {
    let algorithm = algorithm.filter(|a| matches!(*a, "sha256" | "sha384" | "sha512")).ok_or("unsupported raw block hash algorithm")?;
    let target_digest = &target.digests.as_ref().ok_or("raw block target digest not captured")?.sha256;
    if entry.size > MAX_FILE || entry.compressed > 128 * 1024 * 1024 {
        return Err("raw block file-byte limit");
    }
    if target.size != entry.size || row["size"].as_u64() != Some(entry.size) {
        return Err("raw, captured and declared file sizes disagree");
    }
    let blocks = row["blocks"].as_array().ok_or("block declarations absent")?;
    if blocks.len() as u64 != entry.size.div_ceil(BLOCK as u64) {
        return Err("raw block declaration count differs from file size");
    }
    let work = (entry.size + entry.compressed as u64) * if entry.method == 8 { 2 } else { 1 };
    if work > budget.work || blocks.len() > budget.blocks {
        return Err("raw block decode-work or block-count budget exhausted");
    }
    budget.work -= work;
    budget.blocks -= blocks.len();
    let compressed = span(bytes, entry.data, entry.compressed)?;
    let plain = if entry.method == 0 { compressed.to_vec() } else { inflate(compressed, entry.size as usize)? };
    if plain.len() as u64 != entry.size || aa_core::sha256_hex(&plain) != *target_digest {
        return Err("original compressed bytes do not reproduce the captured target SHA256");
    }
    let crc = crc32fast::hash(&plain);
    let mut result = json!({"target":target.path,"target_sha256":target_digest,"data_offset":entry.data,"compressed_size":entry.compressed,
        "uncompressed_size":entry.size,"algorithm":algorithm,"compression_method":entry.method,"captured_target_bound":true,
        "crc_expected":entry.crc,"crc_computed":crc,"crc_matches":crc==entry.crc,
        "declared_blocks":blocks.len(),"checked_blocks":0,"compressed_block_sizes_checked":false,"package_signature_checked":false});
    let mut lengths = Vec::new();
    let mut total = 0usize;
    for (number, block) in blocks.iter().enumerate() {
        let size = if entry.method == 0 {
            (entry.size as usize - number * BLOCK).min(BLOCK)
        } else {
            let declared = block["compressed_size"].as_u64().ok_or("compressed block Size declaration absent")?;
            let size = usize::try_from(declared).map_err(|_| "compressed block Size exceeds address space")?;
            if size == 0 || size > MAX_COMPRESSED_BLOCK {
                return Err("compressed block byte limit");
            }
            size
        };
        total = total.checked_add(size).ok_or("compressed block extent overflow")?;
        lengths.push(size);
    }
    result["declared_span_bytes"] = json!(total);
    if total > compressed.len() {
        result["status"] = json!("declaration-mismatch");
        result["reason"] = json!("declared block extents exceed original compressed file bytes");
        result["expected_maximum_span_bytes"] = json!(compressed.len());
        return Ok(result);
    }
    if entry.method == 8 && total < compressed.len() {
        let remainder = &compressed[total..];
        if remainder.len() > MAX_COMPRESSED_BLOCK {
            return Err("compressed empty-remainder byte limit");
        }
        // A separately encoded empty final block need not use one fixed Huffman representation.
        inflate(remainder, 0).map_err(|_| "compressed remainder is not an independently decodable empty final stream")?;
    }
    let mut cursor = 0;
    let mut failures = Vec::new();
    let mut failed_blocks = 0usize;
    let mut witnesses = Vec::new();
    for (number, (block, &length)) in blocks.iter().zip(&lengths).enumerate() {
        let content_offset = number * BLOCK;
        let expected_plain = &plain[content_offset..(content_offset + BLOCK).min(plain.len())];
        let raw = span(compressed, cursor, length)?;
        if entry.method == 8 {
            let decoded = if number + 1 == blocks.len() && total == compressed.len() {
                // Some declarations include the original stream terminator in the final block.
                inflate(raw, expected_plain.len())?
            } else {
                let mut terminated = Vec::with_capacity(length + 2);
                terminated.extend_from_slice(raw);
                terminated.extend_from_slice(&[3, 0]);
                inflate(&terminated, expected_plain.len())?
            };
            if decoded != expected_plain {
                return Err("independent compressed block differs from full-stream decoding");
            }
        }
        let expected_hash = block["digest"].as_str().ok_or("raw block digest declaration absent")?;
        let computed = crate::msix_blockmap::computed(algorithm, expected_plain).ok_or("unsupported raw block hash algorithm")?;
        let size_matches = block["compressed_size"].as_u64().is_none_or(|declared| declared == length as u64);
        let hash_matches = expected_hash == computed;
        let witness = json!({"block":number,"compressed_offset":entry.data+cursor,"compressed_size":length,
            "uncompressed_offset":content_offset,"uncompressed_size":expected_plain.len(),"expected_hash":expected_hash,
            "computed_hash":computed,"declared_compressed_size":block["compressed_size"],"size_matches":size_matches,"hash_matches":hash_matches});
        if witnesses.len() < 8 {
            witnesses.push(witness.clone());
        }
        if !size_matches || !hash_matches {
            failed_blocks += 1;
            if failures.len() < 8 {
                failures.push(witness);
            }
        }
        cursor += length;
    }
    let file_digest = if let Some(expected) = row["file_digest"].as_str() {
        let computed = crate::msix_blockmap::computed(algorithm, &plain).ok_or("unsupported raw whole-file algorithm")?;
        Some(json!({"expected":expected,"computed":computed,"matches":expected==computed}))
    } else {
        None
    };
    let matches = failed_blocks == 0 && crc == entry.crc && file_digest.as_ref().is_none_or(|d| d["matches"] == true);
    result["status"] = json!(if matches { "blocks-agree" } else { "declaration-mismatch" });
    result["checked_blocks"] = json!(blocks.len());
    result["failed_blocks"] = json!(failed_blocks);
    result["compressed_block_sizes_checked"] = json!(true);
    result["terminator_size"] = json!(compressed.len() - cursor);
    result["terminator_kind"] = json!(if entry.method == 0 {
        "stored-no-terminator"
    } else if total == compressed.len() {
        "included-in-final-block"
    } else {
        "separate-empty-stream"
    });
    result["witnesses"] = json!(witnesses);
    result["witnesses_omitted"] = json!(blocks.len().saturating_sub(8));
    result["failures"] = json!(failures);
    result["failures_omitted"] = json!(failed_blocks.saturating_sub(8));
    result["file_digest"] = json!(file_digest);
    Ok(result)
}

#[derive(Default)]
pub(super) struct Checks {
    records: Vec<Value>,
    matching: usize,
    spans: usize,
    mismatched: usize,
    unresolved: usize,
    omitted: usize,
    agreements: Vec<Value>,
    failures: Vec<Value>,
}

impl Checks {
    pub(super) fn add(&mut self, position: usize, result: Result<Value>, budget: &mut Budget) {
        let mut record = match result {
            Ok(record) => record,
            Err(reason) => json!({"status":"unresolved","reason":reason}),
        };
        record["file"] = json!(position);
        if record["compressed_block_sizes_checked"] == true {
            self.spans += 1;
        }
        match record["status"].as_str() {
            Some("blocks-agree") => {
                self.matching += 1;
                if self.agreements.len() < 6 {
                    self.agreements.push(record.clone());
                }
            }
            Some("declaration-mismatch") => {
                self.mismatched += 1;
                if self.failures.len() < 6 {
                    self.failures.push(record.clone());
                }
            }
            _ => self.unresolved += 1,
        }
        let cost = serde_json::to_vec(&record).map_or(usize::MAX, |v| v.len());
        if self.records.len() >= 128 || cost > budget.output {
            self.omitted += 1;
        } else {
            budget.output -= cost;
            self.records.push(record);
        }
    }

    pub(super) fn publish(self, parent: &Artifact, source: &Artifact, map_digest: &str, out: &mut Output) {
        for (rule, severity, count, examples) in [
            ("windows.msix-zip-blocks", Severity::Info, self.matching, &self.agreements),
            ("windows.msix-zip-block-mismatch", Severity::High, self.mismatched, &self.failures),
        ] {
            if count == 0 {
                continue;
            }
            let mut finding = Finding::new(Section::Provenance, "windows", rule, Confidence::Verified, severity).param("count", count);
            for record in examples {
                finding =
                    finding.evidence(Evidence::field(parent, "original ZIP block comparison", record.clone())).evidence(Evidence::field(
                        source,
                        format!("BlockMap/File/{}", record["file"]),
                        json!({"source_sha256":map_digest,"file":record["file"]}),
                    ));
            }
            out.finding(finding);
        }
        if self.unresolved > 0 || self.omitted > 0 {
            out.limitation(
                "windows.msix-zip-blocks-unresolved",
                Some(source),
                Some(format!(
                    "{}; {}",
                    aa_core::counted(self.unresolved as u64, "files were unresolved"),
                    aa_core::counted(self.omitted as u64, "file records were omitted")
                )),
            );
        }
        out.fact(parent,"windows.msix-zip-blocks",json!({"profile":"stored-or-independently-decodable-deflate-blocks",
            "source_sha256":parent.digests.as_ref().map(|d|d.sha256.as_str()),"block_map_sha256":map_digest,"block_size":BLOCK,
            "files":self.records,"files_with_matching_blocks":self.matching,"files_with_verified_block_spans":self.spans,"files_with_mismatches":self.mismatched,
            "files_unresolved":self.unresolved,"file_records_omitted":self.omitted,"package_signature_checked":false,"windows_trust_checked":false}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;

    fn artifact(name: &str, size: u64, digest: &str) -> Artifact {
        Artifact {
            path: name.into(),
            parent: None,
            size,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: digest.into() }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        }
    }
    fn data(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)).expect("licensed native sample")
    }
    fn declarations(bytes: &[u8], directory: &super::super::Directory<'_>) -> Value {
        let map = directory.entries.iter().find(|e| e.name == "AppxBlockMap.xml").expect("map entry");
        let bytes = super::super::map_bytes(bytes, map).expect("map content");
        let source = artifact("AppxBlockMap.xml", bytes.len() as u64, &aa_core::sha256_hex(&bytes));
        let mut out = Output::default();
        crate::msix_blockmap::analyze_file(&source, &bytes, &mut out);
        out.facts.into_iter().find(|f| f.key == "windows.msix-blockmap").expect("declarations").value
    }

    #[test]
    fn every_native_mapped_span_and_digest_corresponds_to_captured_reference_content() {
        for name in ["native-msix-sha256.msix", "native-msix-sha384.msix", "native-msix-sha512.msix", "upstream-TestAppxPackage_Win32.appx"]
        {
            let bytes = data(name);
            let directory = super::super::parse(&bytes).expect("native layout");
            let map = declarations(&bytes, &directory);
            let reference: Value = serde_json::from_slice(&data(&format!("{name}.ref.json"))).expect("native readings");
            let mut budget = Budget::default();
            for row in map["files"].as_array().expect("files") {
                let native =
                    reference["files"].as_array().expect("native files").iter().find(|r| r["name"] == row["name"]).expect("native file");
                let entry = directory
                    .entries
                    .iter()
                    .find(|e| row["path"].as_str().is_some_and(|p| p.eq_ignore_ascii_case(e.name)))
                    .expect("raw entry");
                let target = artifact(entry.name, entry.size, native["sha256"].as_str().expect("captured native SHA256"));
                let record = check_file(&bytes, entry, row, map["algorithm"].as_str(), &target, &mut budget)
                    .expect("native physical block correspondence");
                assert_eq!(record["status"], "blocks-agree", "{name}: {record}");
                assert_eq!(record["compressed_block_sizes_checked"], true);
                assert_eq!(record["crc_matches"], true);
                assert_eq!(record["checked_blocks"], native["blocks"].as_array().expect("native blocks").len());
                for (witness, native) in
                    record["witnesses"].as_array().expect("witnesses").iter().zip(native["blocks"].as_array().expect("blocks"))
                {
                    assert_eq!(witness["compressed_size"], native["native_compressed_size"]);
                    assert_eq!(witness["computed_hash"], native["digest"]);
                }
            }
        }
    }

    #[test]
    fn concrete_extent_hash_and_crc_disagreements_do_not_hide_behind_whole_file_hashes() {
        let bytes = data("native-msix-sha256.msix");
        let directory = super::super::parse(&bytes).expect("layout");
        let map = declarations(&bytes, &directory);
        let row = map["files"].as_array().expect("files").iter().find(|r| r["path"] == "payload.bin").expect("two-block payload");
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).expect("independent ZIP decoder");
        let mut plain = Vec::new();
        use std::io::Read;
        archive.by_name("payload.bin").expect("payload").read_to_end(&mut plain).expect("content");
        let target = artifact("pkg/payload.bin", plain.len() as u64, &aa_core::sha256_hex(&plain));
        let entry = directory.entries.iter().find(|e| e.name == "payload.bin").expect("raw payload");
        let mut wrong = row.clone();
        wrong["blocks"][0]["compressed_size"] = json!(entry.compressed + 1);
        let record = check_file(&bytes, entry, &wrong, Some("sha256"), &target, &mut Budget::default()).expect("provable overshoot");
        assert_eq!(record["status"], "declaration-mismatch");
        assert_eq!(record["captured_target_bound"], true);
        assert_eq!(record["compressed_block_sizes_checked"], false);
        let mut wrong = row.clone();
        wrong["blocks"][0]["digest"] = json!("00".repeat(32));
        let record = check_file(&bytes, entry, &wrong, Some("sha256"), &target, &mut Budget::default()).expect("digest comparison");
        assert_eq!(record["status"], "declaration-mismatch");
        assert_eq!(record["failed_blocks"], 1);
        assert_eq!(record["file_digest"]["matches"], true, "the independent whole-file declaration must not mask a block mismatch");
        let mut wrong = row.clone();
        wrong["file_digest"] = json!("00".repeat(32));
        let record = check_file(&bytes, entry, &wrong, Some("sha256"), &target, &mut Budget::default()).expect("whole-file comparison");
        assert_eq!(record["status"], "declaration-mismatch");
        assert_eq!(record["failed_blocks"], 0);
        let mut directory = super::super::parse(&bytes).expect("layout");
        let entry = directory.entries.iter_mut().find(|e| e.name == "payload.bin").expect("entry");
        entry.crc ^= 1;
        let record = check_file(&bytes, entry, row, Some("sha256"), &target, &mut Budget::default()).expect("CRC comparison");
        assert_eq!(record["status"], "declaration-mismatch");
        assert_eq!(record["crc_matches"], false);
    }

    #[test]
    fn unavailable_declarations_other_stream_profiles_and_each_budget_remain_unresolved() {
        let bytes = data("native-msix-sha256.msix");
        let directory = super::super::parse(&bytes).expect("layout");
        let map = declarations(&bytes, &directory);
        let row = map["files"].as_array().expect("files").iter().find(|r| r["path"] == "payload.bin").expect("payload");
        let entry = directory.entries.iter().find(|e| e.name == "payload.bin").expect("entry");
        let plain: Vec<_> = (0..65543).map(|i| ((i * 37 + 19) % 256) as u8).collect();
        let target = artifact("payload.bin", plain.len() as u64, &aa_core::sha256_hex(&plain));
        let mut shifted = row.clone();
        shifted["blocks"][0]["compressed_size"] = json!(row["blocks"][0]["compressed_size"].as_u64().expect("first span") + 1);
        shifted["blocks"][1]["compressed_size"] = json!(row["blocks"][1]["compressed_size"].as_u64().expect("second span") - 1);
        assert!(check_file(&bytes, entry, &shifted, Some("sha256"), &target, &mut Budget::default()).is_err());
        let mut missing = row.clone();
        missing["blocks"][0]["compressed_size"] = Value::Null;
        assert!(check_file(&bytes, entry, &missing, Some("sha256"), &target, &mut Budget::default()).is_err());
        assert!(check_file(&bytes, entry, row, None, &target, &mut Budget::default()).is_err());
        let stale = artifact("payload.bin", plain.len() as u64, &"00".repeat(32));
        assert!(check_file(&bytes, entry, row, Some("sha256"), &stale, &mut Budget::default()).is_err());
        let mut budget = Budget { work: 0, ..Budget::default() };
        assert!(check_file(&bytes, entry, row, Some("sha256"), &target, &mut budget).is_err());
        let mut budget = Budget { blocks: 0, ..Budget::default() };
        assert!(check_file(&bytes, entry, row, Some("sha256"), &target, &mut budget).is_err());
        let mut budget = Budget { files: 0, ..Budget::default() };
        assert!(budget.attempt().is_err());
        assert!(budget.attempt().is_err());
        let mut budget = Budget { output: 0, ..Budget::default() };
        let mut checks = Checks::default();
        checks.add(0, Err("test unavailable"), &mut budget);
        assert_eq!(checks.omitted, 1);
        assert!(checks.records.is_empty());
        assert_eq!(checks.unresolved, 1);
        assert!(inflate(&[3, 0, 0], 0).is_err());
        assert!(inflate(&[3], 0).is_err());
        assert!(inflate(&[], MAX_FILE as usize + 1).is_err());
    }

    #[test]
    fn empty_final_stream_variants_and_terminators_in_the_last_block_are_measured() {
        let bytes = data("native-msix-sha256.msix");
        let mut directory = super::super::parse(&bytes).expect("layout");
        let map = declarations(&bytes, &directory);
        let row = map["files"].as_array().expect("files").iter().find(|r| r["path"] == "payload.bin").expect("payload");
        let entry = directory.entries.iter_mut().find(|e| e.name == "payload.bin").expect("entry");
        let original = span(&bytes, entry.data, entry.compressed).expect("compressed stream").to_vec();
        let plain: Vec<_> = (0..65543).map(|i| ((i * 37 + 19) % 256) as u8).collect();
        let target = artifact("payload.bin", plain.len() as u64, &aa_core::sha256_hex(&plain));
        let mut alternate = original[..original.len() - 2].to_vec();
        alternate.extend_from_slice(&[1, 0, 0, 255, 255]);
        entry.data = 0;
        entry.end = alternate.len();
        entry.compressed = alternate.len();
        let result = check_file(&alternate, entry, row, Some("sha256"), &target, &mut Budget::default()).expect("stored empty final block");
        assert_eq!(result["status"], "blocks-agree");
        assert_eq!(result["terminator_size"], 5);
        let mut inclusive = row.clone();
        inclusive["blocks"][1]["compressed_size"] = json!(row["blocks"][1]["compressed_size"].as_u64().expect("span") + 2);
        entry.end = original.len();
        entry.compressed = original.len();
        let result = check_file(&original, entry, &inclusive, Some("sha256"), &target, &mut Budget::default())
            .expect("last block includes terminator");
        assert_eq!(result["status"], "blocks-agree");
        assert_eq!(result["terminator_size"], 0);
        assert_eq!(result["terminator_kind"], "included-in-final-block");
        let mut excessive = original[..original.len() - 2].to_vec();
        for _ in 0..MAX_COMPRESSED_BLOCK / 5 + 1 {
            excessive.extend_from_slice(&[0, 0, 0, 255, 255]);
        }
        excessive.extend_from_slice(&[3, 0]);
        entry.end = excessive.len();
        entry.compressed = excessive.len();
        assert_eq!(
            check_file(&excessive, entry, row, Some("sha256"), &target, &mut Budget::default()).expect_err("empty closure limit"),
            "compressed empty-remainder byte limit"
        );
    }

    #[test]
    fn stored_block_size_is_measured_even_when_its_optional_declaration_is_absent() {
        let bytes = data("native-msix-sha512.msix");
        let directory = super::super::parse(&bytes).expect("layout");
        let map = declarations(&bytes, &directory);
        let mut row = map["files"].as_array().expect("files").iter().find(|r| r["path"] == "payload.bin").expect("payload").clone();
        let entry = directory.entries.iter().find(|e| e.name == "payload.bin").expect("entry");
        let plain: Vec<_> = (0..65543).map(|i| ((i * 37 + 19) % 256) as u8).collect();
        let target = artifact("payload.bin", plain.len() as u64, &aa_core::sha256_hex(&plain));
        row["blocks"][0]["compressed_size"] = Value::Null;
        let result = check_file(&bytes, entry, &row, Some("sha512"), &target, &mut Budget::default()).expect("stored spans");
        assert_eq!(result["status"], "blocks-agree");
        row["blocks"][0]["compressed_size"] = json!(1);
        let result = check_file(&bytes, entry, &row, Some("sha512"), &target, &mut Budget::default()).expect("measurable stored mismatch");
        assert_eq!(result["status"], "declaration-mismatch");
        assert_eq!(result["failures"][0]["compressed_size"], BLOCK);
    }
}
