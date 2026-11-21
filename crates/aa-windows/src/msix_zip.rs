//! Original ZIP records, kept separate from uncompressed block hashes and authentication.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use flate2::{Decompress, FlushDecompress, Status};
use serde_json::{Value, json};

const MAX_PACKAGE: usize = 256 * 1024 * 1024;
const MAX_DIRECTORY: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 16384;

mod blocks;

type Result<T> = std::result::Result<T, &'static str>;

fn span(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    bytes.get(offset..offset.checked_add(length).ok_or("ZIP extent overflow")?).ok_or("ZIP extent outside captured bytes")
}

fn n16(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(bytes, offset, 2)?.try_into().map_err(|_| "ZIP integer width")?))
}

fn n32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(bytes, offset, 4)?.try_into().map_err(|_| "ZIP integer width")?))
}

fn n64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(bytes, offset, 8)?.try_into().map_err(|_| "ZIP integer width")?))
}

fn address(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| "ZIP offset exceeds address space")
}

fn signature(bytes: &[u8], offset: usize, expected: u32) -> Result<()> {
    if n32(bytes, offset)? == expected { Ok(()) } else { Err("ZIP record signature disagrees") }
}

fn compatible(short: u64, sentinel: u64, wide: u64) -> Result<()> {
    if short == sentinel || short == wide { Ok(()) } else { Err("ZIP32 and ZIP64 fields disagree") }
}

struct Directory<'a> {
    entries: Vec<Entry<'a>>,
    start: usize,
    length: usize,
    footer: usize,
    zip64: bool,
}

struct Entry<'a> {
    name: &'a str,
    central: usize,
    local: usize,
    data: usize,
    end: usize,
    descriptor: usize,
    size: u64,
    compressed: usize,
    crc: u32,
    method: u16,
    flags: u16,
    version: u16,
}

// Unknown extra fields stay opaque; ZIP64 fields are consumed only where a sentinel requires one.
fn zip64_extra(bytes: &[u8]) -> Result<Option<&[u8]>> {
    let mut position = 0;
    let mut found = None;
    let mut fields = 0;
    while position < bytes.len() {
        fields += 1;
        if fields > 128 {
            return Err("ZIP extra-field count limit");
        }
        let tag = n16(bytes, position)?;
        let length = n16(bytes, position + 2)? as usize;
        let value = span(bytes, position + 4, length)?;
        if tag == 1 {
            if found.is_some() {
                return Err("duplicate ZIP64 extra field");
            }
            found = Some(value);
        }
        position += 4 + length;
    }
    Ok(found)
}

fn wide32(value: u32, extra: &[u8], cursor: &mut usize) -> Result<u64> {
    if value != u32::MAX {
        return Ok(value as u64);
    }
    let wide = n64(extra, *cursor)?;
    *cursor += 8;
    Ok(wide)
}

fn ordinary_name(bytes: &[u8]) -> Result<&str> {
    let name = std::str::from_utf8(bytes).map_err(|_| "ZIP name is outside UTF-8 profile")?;
    // This is deliberately narrower than ZIP and Windows namespaces, and never used as a host path.
    if name.is_empty()
        || name.len() > 8192
        || !name.is_ascii()
        || name.ends_with("//")
        || name.bytes().any(|b| b < 32 || b == 127 || b == b'\\' || b == b':')
        || name.trim_end_matches('/').split('/').any(|part| part.is_empty() || matches!(part, "." | "..") || part.ends_with([' ', '.']))
    {
        return Err("ZIP name is outside canonical ASCII relative-path profile");
    }
    Ok(name)
}

fn parse(bytes: &[u8]) -> Result<Directory<'_>> {
    if bytes.len() > MAX_PACKAGE {
        return Err("ZIP package byte limit");
    }
    let end = bytes.len().checked_sub(22).ok_or("ZIP end record absent")?;
    let eocd = (bytes.len().saturating_sub(65557)..=end)
        .rev()
        .find(|&p| n32(bytes, p).ok() == Some(0x06054b50) && n16(bytes, p + 20).is_ok_and(|n| p + 22 + n as usize == bytes.len()))
        .ok_or("ZIP end record does not terminate captured bytes")?;
    let mut count = n16(bytes, eocd + 10)? as u64;
    let mut length = n32(bytes, eocd + 12)? as u64;
    let mut start = n32(bytes, eocd + 16)? as u64;
    let zip64 = eocd >= 20 && n32(bytes, eocd - 20)? == 0x07064b50;
    let footer = if zip64 {
        let locator = eocd - 20;
        if n32(bytes, locator + 4)? != 0 || n32(bytes, locator + 16)? != 1 {
            return Err("multi-disk ZIP64 is unsupported");
        }
        let footer = address(n64(bytes, locator + 8)?)?;
        signature(bytes, footer, 0x06064b50)?;
        if n64(bytes, footer + 4)? != 44 || footer.checked_add(56) != Some(locator) {
            return Err("ZIP64 extended end record is outside supported profile");
        }
        if n16(bytes, footer + 14)? != 45 {
            return Err("ZIP64 extraction version is outside supported profile");
        }
        if n32(bytes, footer + 16)? != 0 || n32(bytes, footer + 20)? != 0 {
            return Err("multi-disk ZIP64 is unsupported");
        }
        let wide_count = n64(bytes, footer + 32)?;
        if n64(bytes, footer + 24)? != wide_count {
            return Err("ZIP64 entry counts disagree");
        }
        compatible(n16(bytes, eocd + 4)? as u64, u16::MAX as u64, 0)?;
        compatible(n16(bytes, eocd + 6)? as u64, u16::MAX as u64, 0)?;
        compatible(n16(bytes, eocd + 8)? as u64, u16::MAX as u64, wide_count)?;
        compatible(count, u16::MAX as u64, wide_count)?;
        compatible(length, u32::MAX as u64, n64(bytes, footer + 40)?)?;
        compatible(start, u32::MAX as u64, n64(bytes, footer + 48)?)?;
        count = wide_count;
        length = n64(bytes, footer + 40)?;
        start = n64(bytes, footer + 48)?;
        footer
    } else {
        if n16(bytes, eocd + 4)? != 0 || n16(bytes, eocd + 6)? != 0 || n16(bytes, eocd + 8)? as u64 != count {
            return Err("multi-disk ZIP or entry-count disagreement");
        }
        if count == u16::MAX as u64 || length == u32::MAX as u64 || start == u32::MAX as u64 {
            return Err("ZIP64 sentinel without end records");
        }
        eocd
    };
    let start = address(start)?;
    let length = address(length)?;
    if count == 0 || count > MAX_ENTRIES as u64 || length > MAX_DIRECTORY {
        return Err("ZIP directory count or byte limit");
    }
    span(bytes, start, length)?;
    if start.checked_add(length) != Some(footer) {
        return Err("ZIP directory extent does not meet end records");
    }
    let mut entries = Vec::new();
    let mut names = BTreeSet::new();
    let mut position = start;
    for _ in 0..count {
        let fixed = span(bytes, position, 46)?;
        signature(fixed, 0, 0x02014b50)?;
        let name_length = n16(fixed, 28)? as usize;
        let extra_length = n16(fixed, 30)? as usize;
        let comment_length = n16(fixed, 32)? as usize;
        let total = 46 + name_length + extra_length + comment_length;
        if position.checked_add(total).is_none_or(|n| n > footer) {
            return Err("ZIP directory record exceeds directory");
        }
        let name = ordinary_name(span(bytes, position + 46, name_length)?)?;
        if !names.insert(name.trim_end_matches('/').to_ascii_lowercase()) {
            return Err("ZIP names are duplicated or aliased");
        }
        let extra = zip64_extra(span(bytes, position + 46 + name_length, extra_length)?)?.unwrap_or(&[]);
        let mut cursor = 0;
        let size = wide32(n32(fixed, 24)?, extra, &mut cursor)?;
        let compressed = address(wide32(n32(fixed, 20)?, extra, &mut cursor)?)?;
        let local = address(wide32(n32(fixed, 42)?, extra, &mut cursor)?)?;
        let disk = n16(fixed, 34)?;
        if disk != 0 && (disk != u16::MAX || n32(extra, cursor)? != 0) {
            return Err("ZIP entry refers to another disk");
        }
        let version = n16(fixed, 6)?;
        if version < 45 && [20, 24, 42].into_iter().any(|at| n32(fixed, at).ok() == Some(u32::MAX)) {
            return Err("ZIP64 entry fields without ZIP64 extraction version");
        }
        let flags = n16(fixed, 8)?;
        let method = n16(fixed, 10)?;
        let allowed = if method == 8 { 0x080e } else { 0x0808 };
        if !matches!(version, 10 | 20 | 45) || !matches!(method, 0 | 8) || flags & !allowed != 0 {
            return Err("ZIP version, flags or compression method is outside supported profile");
        }
        if method == 0 && compressed as u64 != size {
            return Err("stored ZIP entry has unequal byte sizes");
        }
        entries.push(Entry {
            name,
            central: position,
            local,
            data: 0,
            end: 0,
            descriptor: 0,
            size,
            compressed,
            crc: n32(fixed, 16)?,
            method,
            flags,
            version,
        });
        position += total;
    }
    if position != footer {
        return Err("ZIP directory count does not cover directory bytes");
    }
    // Local records must cover precisely the file-record region; no SFX prefix, gaps or overlap.
    entries.sort_by_key(|entry| entry.local);
    if entries.first().is_none_or(|e| e.local != 0) {
        return Err("ZIP prefix or absent local records");
    }
    for index in 0..entries.len() {
        let next = entries.get(index + 1).map_or(start, |entry| entry.local);
        let entry = &mut entries[index];
        if entry.local >= next || next > start {
            return Err("ZIP local records overlap or exceed directory");
        }
        let local = span(bytes, entry.local, next - entry.local)?;
        signature(local, 0, 0x04034b50)?;
        if n16(local, 4)? != entry.version || n16(local, 6)? != entry.flags || n16(local, 8)? != entry.method {
            return Err("ZIP local and central header fields disagree");
        }
        let name_length = n16(local, 26)? as usize;
        let extra_length = n16(local, 28)? as usize;
        if span(local, 30, name_length)? != entry.name.as_bytes() {
            return Err("ZIP local and central names disagree");
        }
        let extra = zip64_extra(span(local, 30 + name_length, extra_length)?)?.unwrap_or(&[]);
        let mut cursor = 0;
        let size = wide32(n32(local, 22)?, extra, &mut cursor)?;
        let compressed = wide32(n32(local, 18)?, extra, &mut cursor)?;
        let crc = n32(local, 14)?;
        let has_descriptor = entry.flags & 8 != 0;
        if (crc != entry.crc && !(has_descriptor && crc == 0))
            || (size != entry.size && !(has_descriptor && size == 0))
            || (compressed != entry.compressed as u64 && !(has_descriptor && compressed == 0))
        {
            return Err("ZIP local sizes or CRC disagree with directory");
        }
        let header_length = 30 + name_length + extra_length;
        span(local, header_length, entry.compressed)?;
        entry.data = entry.local + header_length;
        entry.end = entry.data + entry.compressed;
        entry.descriptor = next - entry.end;
        if !has_descriptor {
            if entry.descriptor != 0 {
                return Err("ZIP unexplained bytes after file data");
            }
            continue;
        }
        let descriptor = span(bytes, entry.end, entry.descriptor)?;
        let prefix = match descriptor.len() {
            12 | 20 => 0,
            16 | 24 => {
                signature(descriptor, 0, 0x08074b50)?;
                4
            }
            _ => return Err("ZIP descriptor width is outside supported profile"),
        };
        let wide = descriptor.len() - prefix == 20;
        if wide && entry.version < 45 {
            return Err("ZIP64 descriptor without ZIP64 extraction version");
        }
        let (compressed, size) = if wide {
            (n64(descriptor, prefix + 4)?, n64(descriptor, prefix + 12)?)
        } else {
            (n32(descriptor, prefix + 4)? as u64, n32(descriptor, prefix + 8)? as u64)
        };
        if n32(descriptor, prefix)? != entry.crc || compressed != entry.compressed as u64 || size != entry.size {
            return Err("ZIP descriptor disagrees with directory");
        }
    }
    Ok(Directory { entries, start, length, footer, zip64 })
}

fn map_bytes(bytes: &[u8], entry: &Entry<'_>) -> Result<Vec<u8>> {
    if entry.size > 8 * 1024 * 1024 || entry.compressed > 16 * 1024 * 1024 {
        return Err("raw block-map byte limit");
    }
    let data = span(bytes, entry.data, entry.compressed)?;
    let plain = if entry.method == 0 {
        data.to_vec()
    } else {
        // One extra output byte distinguishes an exact-size stream from a truncated bomb.
        let mut output = vec![0; entry.size as usize + 1];
        let mut decoder = Decompress::new(false);
        let status = decoder.decompress(data, &mut output, FlushDecompress::Finish).map_err(|_| "raw block-map DEFLATE failed")?;
        if status != Status::StreamEnd || decoder.total_in() != data.len() as u64 || decoder.total_out() != entry.size {
            return Err("raw block-map stream length or terminator disagrees");
        }
        output.truncate(entry.size as usize);
        output
    };
    if plain.len() as u64 != entry.size || crc32fast::hash(&plain) != entry.crc {
        return Err("raw block-map size or CRC disagrees");
    }
    Ok(plain)
}

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    let mut bytes_left = 512 * 1024 * 1024usize;
    let mut block_budget = blocks::Budget::default();
    let maps: Vec<_> = tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.msix-blockmap")).take(33).collect();
    if maps.is_empty() {
        return;
    }
    if maps.len() > 32 {
        out.limitation("windows.msix-zip-unresolved", None, Some("raw ZIP checks limited to 32 block maps".into()));
    }
    let complete = tree.summary().get("engine.input-listing").and_then(|v| v.get("complete")).and_then(Value::as_bool) == Some(true);
    let index = crate::references::Index::for_distribution_roots(tree.artifacts(), complete);
    for source in maps.into_iter().take(32) {
        let checked = (|| -> Result<(&Artifact, Value, usize, Vec<Value>)> {
            let parent = source.parent.as_deref().and_then(|p| tree.get(p)).ok_or("original ZIP container not supplied")?;
            if parent.unpacked_by.as_deref() != Some("zip") {
                return Err("block-map parent is not a captured ZIP container");
            }
            let expected_path =
                if parent.path.is_empty() { "AppxBlockMap.xml".into() } else { format!("{}/AppxBlockMap.xml", parent.path) };
            if source.path != expected_path {
                return Err("block map is not at the canonical immediate ZIP root");
            }
            if parent.size > MAX_PACKAGE as u64 || parent.size > bytes_left as u64 {
                return Err("raw ZIP aggregate byte budget exhausted");
            }
            bytes_left -= parent.size as usize;
            let captured = parent.digests.as_ref().ok_or("original ZIP digest not captured")?;
            let bytes = tree.read(&parent.path).map_err(|_| "original ZIP bytes unreadable")?;
            if bytes.len() as u64 != parent.size || bytes.len() > MAX_PACKAGE {
                return Err("original ZIP length changed");
            }
            let snapshot = bytes.to_vec();
            if aa_core::sha256_hex(&snapshot) != captured.sha256 {
                return Err("original ZIP bytes differ from captured digest");
            }
            let directory = parse(&snapshot)?;
            let entry = directory.entries.iter().find(|e| e.name == "AppxBlockMap.xml").ok_or("canonical raw block map absent")?;
            let raw_map = map_bytes(&snapshot, entry)?;
            let map = &source.facts["windows.msix-blockmap"];
            let digest = aa_core::sha256_hex(&raw_map);
            if source.digests.as_ref().is_none_or(|d| d.sha256 != digest) || map["source_sha256"] != digest {
                return Err("raw block map differs from captured declaration source");
            }
            let mut mismatches = 0;
            let mut examples = Vec::new();
            let mut records = Vec::new();
            let mut unresolved = 0;
            let mut block_checks = blocks::Checks::default();
            let by_name: BTreeMap<_, _> = directory.entries.iter().map(|e| (e.name.to_ascii_lowercase(), e)).collect();
            for (position, row) in map["files"].as_array().ok_or("block-map files absent")?.iter().enumerate() {
                if position >= 4096 {
                    return Err("raw ZIP file comparison count limit");
                }
                let entry = row["path"]
                    .as_str()
                    .filter(|_| row["unresolved"].is_null())
                    .and_then(|path| by_name.get(&path.to_ascii_lowercase()).copied());
                let Some(entry) = entry.filter(|e| !e.name.ends_with('/')) else {
                    unresolved += 1;
                    let result = block_budget.attempt().and(Err("mapped path has no unambiguous raw regular-file entry"));
                    block_checks.add(position, result, &mut block_budget);
                    continue;
                };
                let block_result = (|| {
                    block_budget.attempt()?;
                    let index = index.as_ref().map_err(|reason| *reason)?;
                    let target = index.resolve_distribution(
                        source,
                        &parent.path.to_ascii_lowercase(),
                        row["path"].as_str().ok_or("unsupported map path")?,
                    )?;
                    blocks::check_file(&snapshot, entry, row, map["algorithm"].as_str(), target, &mut block_budget)
                })();
                block_checks.add(position, block_result, &mut block_budget);
                let header = entry.data - entry.local;
                let agrees = row["local_file_header_size"].as_u64() == Some(header as u64) && row["size"].as_u64() == Some(entry.size);
                if !agrees {
                    mismatches += 1;
                    if examples.len() < 6 {
                        examples.push(json!({"file":position,"local_header_offset":entry.local,"local_header_size":header,
                        "central_header_offset":entry.central,"zip_uncompressed_size":entry.size,"declared_header_size":row["local_file_header_size"],"declared_size":row["size"]}));
                    }
                }
                // Preserve physical witnesses without republishing raw, potentially sensitive names.
                if records.len() < 128 {
                    records.push(json!({"file":position,"local_header_offset":entry.local,"local_header_size":header,
                    "central_header_offset":entry.central,"data_offset":entry.data,"compressed_size":entry.compressed,
                    "uncompressed_size":entry.size,"descriptor_size":entry.descriptor,"compression_method":entry.method,"header_and_size_agree":agrees}));
                }
            }
            let fact = json!({"profile":"contiguous-single-disk-ascii-zip32-or-zip64","source_sha256":captured.sha256,
                "block_map_sha256":digest,"directory_offset":directory.start,"directory_size":directory.length,"footer_offset":directory.footer,
                "zip64":directory.zip64,"entries_checked":directory.entries.len(),"mapped_files":records,"mapped_file_records_omitted":map["files"].as_array().map_or(0,Vec::len).saturating_sub(unresolved+128),
                "mapped_files_unresolved":unresolved,"mapped_files_with_header_or_size_mismatch":mismatches,
                "zip_record_structure_checked":true,"block_map_bytes_bound":true,
                "all_payload_crc_checked":false,"compressed_block_sizes_checked":false,"package_signature_checked":false,"windows_trust_checked":false});
            block_checks.publish(parent, source, &digest, out);
            Ok((parent, fact, mismatches, examples))
        })();
        match checked {
            Ok((parent, fact, mismatches, examples)) => {
                out.finding(Finding::new(Section::Provenance,"windows","windows.msix-zip-layout",Confidence::Verified,Severity::Info)
                    .param("count",fact["entries_checked"].as_u64().unwrap_or(0))
                    .evidence(Evidence::field(parent,"captured ZIP directory and end records",json!({"sha256":fact["source_sha256"],"directory_offset":fact["directory_offset"],"directory_size":fact["directory_size"],"zip64":fact["zip64"]})))
                    .evidence(Evidence::field(source,"raw block-map binding/SHA256",fact["block_map_sha256"].clone())));
                if mismatches > 0 {
                    let mut finding =
                        Finding::new(Section::Provenance, "windows", "windows.msix-zip-map-mismatch", Confidence::Verified, Severity::High)
                            .param("count", mismatches);
                    for example in examples {
                        finding = finding
                            .evidence(Evidence::bytes(parent, example["local_header_offset"].as_u64().unwrap_or(0), 30, example.clone()))
                            .evidence(Evidence::bytes(parent, example["central_header_offset"].as_u64().unwrap_or(0), 46, example.clone()))
                            .evidence(Evidence::field(source, format!("BlockMap/File/{}", example["file"]), example));
                    }
                    out.finding(finding);
                }
                if fact["mapped_files_unresolved"].as_u64().unwrap_or(0) > 0 {
                    out.limitation(
                        "windows.msix-zip-unresolved",
                        Some(source),
                        Some("some block-map paths have no unambiguous raw regular-file record".into()),
                    );
                }
                out.fact(parent, "windows.msix-zip-layout", fact);
            }
            Err(reason) => out.limitation("windows.msix-zip-unresolved", Some(source), Some(reason.into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;
    use aa_core::plugin::Bytes;

    const PACKAGES: [&str; 4] =
        ["native-msix-sha256.msix", "native-msix-sha384.msix", "native-msix-sha512.msix", "upstream-TestAppxPackage_Win32.appx"];

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name)).expect("licensed MSIX fixture")
    }

    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn stored(name: &str, data: &[u8], descriptor: usize) -> Vec<u8> {
        let version = if descriptor >= 20 { 45 } else { 20 };
        let flags = if descriptor == 0 { 0 } else { 8 };
        let crc = crc32fast::hash(data);
        let mut local = vec![0; 30];
        put32(&mut local, 0, 0x04034b50);
        put16(&mut local, 4, version);
        put16(&mut local, 6, flags);
        put16(&mut local, 26, name.len() as u16);
        if descriptor == 0 {
            put32(&mut local, 14, crc);
            put32(&mut local, 18, data.len() as u32);
            put32(&mut local, 22, data.len() as u32);
        }
        local.extend_from_slice(name.as_bytes());
        local.extend_from_slice(data);
        if descriptor > 0 {
            if matches!(descriptor, 16 | 24) {
                local.extend_from_slice(&0x08074b50u32.to_le_bytes());
            }
            local.extend_from_slice(&crc.to_le_bytes());
            if descriptor >= 20 {
                local.extend_from_slice(&(data.len() as u64).to_le_bytes());
                local.extend_from_slice(&(data.len() as u64).to_le_bytes());
            } else {
                local.extend_from_slice(&(data.len() as u32).to_le_bytes());
                local.extend_from_slice(&(data.len() as u32).to_le_bytes());
            }
        }
        let start = local.len();
        let mut central = vec![0; 46];
        put32(&mut central, 0, 0x02014b50);
        put16(&mut central, 4, version);
        put16(&mut central, 6, version);
        put16(&mut central, 8, flags);
        put32(&mut central, 16, crc);
        put32(&mut central, 20, data.len() as u32);
        put32(&mut central, 24, data.len() as u32);
        put16(&mut central, 28, name.len() as u16);
        central.extend_from_slice(name.as_bytes());
        let mut end = vec![0; 22];
        put32(&mut end, 0, 0x06054b50);
        put16(&mut end, 8, 1);
        put16(&mut end, 10, 1);
        put32(&mut end, 12, central.len() as u32);
        put32(&mut end, 16, start as u32);
        local.extend(central);
        local.extend(end);
        local
    }

    #[test]
    fn native_layouts_and_header_lengths_match_independent_appxpackaging_readings() {
        for package in PACKAGES {
            let bytes = fixture(package);
            let directory = parse(&bytes).expect("native ZIP64 layout");
            assert!(directory.zip64);
            let reference: Value = serde_json::from_slice(&fixture(&format!("{package}.ref.json"))).expect("native declarations");
            for row in reference["files"].as_array().expect("native file list") {
                let name = row["name"].as_str().expect("native name").replace('\\', "/");
                let entry = directory.entries.iter().find(|e| e.name == name).expect("physical file");
                assert_eq!(entry.data - entry.local, row["local_file_header_size"].as_u64().expect("native header length") as usize);
                assert_eq!(entry.size, row["size"].as_u64().expect("native size"));
            }
            let map = directory.entries.iter().find(|e| e.name == "AppxBlockMap.xml").expect("physical map");
            let plain = map_bytes(&bytes, map).expect("bounded original map decoding");
            assert_eq!(aa_core::sha256_hex(&plain), reference["sha256"]);
        }
    }

    #[test]
    fn zip32_headers_and_all_four_descriptor_widths_are_checked() {
        for width in [0, 12, 16, 20, 24] {
            let mut bytes = stored("AppxBlockMap.xml", b"map", width);
            let directory = parse(&bytes).expect("constructed contiguous ZIP");
            assert!(!directory.zip64);
            let entry = &directory.entries[0];
            assert_eq!(entry.descriptor, width);
            assert_eq!(map_bytes(&bytes, entry).expect("stored content"), b"map");
            let damage = if width == 0 { 14 } else { entry.end + width - 1 };
            bytes[damage] ^= 1;
            assert!(parse(&bytes).is_err(), "disagreement at width {width}");
        }
    }

    #[test]
    fn directory_offsets_counts_names_gaps_flags_and_stream_crc_are_bounded() {
        let original = stored("AppxBlockMap.xml", b"map", 0);
        let directory = parse(&original).expect("fixture");
        let central = directory.start;
        let end = directory.footer;
        for (at, value) in
            [(central + 42, u32::MAX), (end + 12, u32::MAX), (end + 16, u32::MAX), (central + 20, u32::MAX), (central + 24, u32::MAX)]
        {
            let mut bytes = original.clone();
            put32(&mut bytes, at, value);
            assert!(parse(&bytes).is_err(), "offset {at}");
        }
        for at in [end + 8, end + 10, central + 30, central + 28, central + 8, central + 10, 26] {
            let mut bytes = original.clone();
            put16(&mut bytes, at, u16::MAX);
            assert!(parse(&bytes).is_err(), "field {at}");
        }
        let mut bytes = original.clone();
        bytes[30] ^= 1;
        assert!(parse(&bytes).is_err(), "local name mismatch");
        let mut bytes = original.clone();
        bytes.push(0);
        assert!(parse(&bytes).is_err(), "trailing bytes");
        let mut bytes = original.clone();
        bytes.insert(0, 0);
        assert!(parse(&bytes).is_err(), "prefix");
        for name in ["../x", "a//b", "a//", "a/./b", "C:/x", "a\\b", "a./b", "é"] {
            assert!(parse(&stored(name, b"", 0)).is_err(), "unsupported name {name}");
        }
        let mut bytes = original.clone();
        bytes[directory.entries[0].data] ^= 1;
        let parsed = parse(&bytes).expect("CRC matching headers does not prove payload CRC");
        assert!(map_bytes(&bytes, &parsed.entries[0]).is_err());
        assert!(zip64_extra(&[1, 0, 0, 0, 1, 0, 0, 0]).is_err());
        assert!(zip64_extra(&[1, 0, 8, 0]).is_err());
        for package in PACKAGES {
            let original = fixture(package);
            let directory = parse(&original).expect("native layout");
            for at in [directory.footer + 24, directory.footer + 32, directory.footer + 40, directory.footer + 48, original.len() - 34] {
                let mut bytes = original.clone();
                put64(&mut bytes, at, u64::MAX);
                assert!(parse(&bytes).is_err(), "ZIP64 field {at}");
            }
            // Every truncated prefix must be an error, and arbitrary record damage must never panic.
            for cut in (0..original.len()).step_by(97) {
                assert!(parse(&original[..cut]).is_err());
            }
            for at in (0..original.len().saturating_sub(8)).step_by(113) {
                let mut bytes = original.clone();
                put64(&mut bytes, at, u64::MAX);
                let _ = parse(&bytes);
            }
        }
    }

    struct Supplied {
        artifacts: Vec<Artifact>,
        contents: BTreeMap<String, Vec<u8>>,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.artifacts
        }
        fn read(&self, path: &str) -> std::io::Result<Bytes> {
            self.contents.get(path).cloned().map(Bytes::from_vec).ok_or_else(|| std::io::Error::other("absent original bytes"))
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
    fn supplied(package: Vec<u8>) -> Supplied {
        let directory = parse(&package).expect("package layout");
        let plain = map_bytes(&package, directory.entries.iter().find(|e| e.name == "AppxBlockMap.xml").expect("map")).expect("map stream");
        let mut parent = artifact("pkg.msix", &package);
        parent.unpacked_by = Some("zip".into());
        let mut source = artifact("pkg.msix/AppxBlockMap.xml", &plain);
        source.parent = Some(parent.path.clone());
        let mut out = Output::default();
        crate::msix_blockmap::analyze_file(&source, &plain, &mut out);
        for fact in out.facts {
            source.facts.insert(fact.key, fact.value);
        }
        Supplied { artifacts: vec![parent, source], contents: BTreeMap::from([("pkg.msix".into(), package)]) }
    }
    #[test]
    fn aliases_and_nonterminating_or_oversized_map_streams_remain_unresolved() {
        let original = fixture(PACKAGES[0]);
        let directory = parse(&original).expect("native records");
        let empty = directory.entries.iter().find(|e| e.name == "empty.dat").expect("empty fixture entry");
        let mut aliased = original.clone();
        aliased[empty.local + 30..empty.local + 39].copy_from_slice(b"HELLO.EXE");
        aliased[empty.central + 46..empty.central + 55].copy_from_slice(b"HELLO.EXE");
        assert!(parse(&aliased).is_err(), "case alias must not be resolved by entry order");
        let empty_stream = |compressed, size| Entry {
            name: "AppxBlockMap.xml",
            central: 0,
            local: 0,
            data: 0,
            end: compressed,
            descriptor: 0,
            size,
            compressed,
            crc: 0,
            method: 8,
            flags: 0,
            version: 20,
        };
        assert!(map_bytes(&[3, 0], &empty_stream(2, 0)).expect("empty stream").is_empty());
        assert!(map_bytes(&[3], &empty_stream(1, 0)).is_err(), "truncated terminator");
        assert!(map_bytes(&[3, 0, 0], &empty_stream(3, 0)).is_err(), "trailing compressed input");
        assert!(map_bytes(&[], &empty_stream(0, 8 * 1024 * 1024 + 1)).is_err(), "plain allocation limit");
        assert!(map_bytes(&[], &empty_stream(16 * 1024 * 1024 + 1, 0)).is_err(), "compressed work limit");
        use std::io::Write;
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0; 1000]).expect("bounded bomb test");
        let bytes = encoder.finish().expect("test compressed stream");
        assert!(map_bytes(&bytes, &empty_stream(bytes.len(), 1)).is_err(), "output may not exceed declared size");
    }

    #[test]
    fn raw_binding_requires_original_snapshot_and_never_claims_authentication() {
        let original = fixture(PACKAGES[0]);
        let mut input = supplied(original);
        let mut out = Output::default();
        analyze(&input, &mut out);
        let fact = &out.facts.iter().find(|f| f.key == "windows.msix-zip-layout").expect("physical layout").value;
        assert_eq!(fact["mapped_files_unresolved"], 0);
        assert_eq!(fact["mapped_files_with_header_or_size_mismatch"], 0);
        assert_eq!(fact["package_signature_checked"], false);
        assert_eq!(fact["compressed_block_sizes_checked"], false);
        input.artifacts[1].facts.get_mut("windows.msix-blockmap").expect("declarations")["files"][0]["local_file_header_size"] = json!(30);
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.findings.iter().any(|f| f.rule == "windows.msix-zip-map-mismatch" && !f.evidence.is_empty()));
        input.contents.get_mut("pkg.msix").expect("bytes")[0] ^= 1;
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.facts.is_empty());
        assert!(out.limitations.iter().any(|l| l.code == "windows.msix-zip-unresolved"));
        input.contents.clear();
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.facts.is_empty());
        input.artifacts[0].size = MAX_PACKAGE as u64 + 1;
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.facts.is_empty());
        let mut input = supplied(fixture(PACKAGES[0]));
        input.artifacts[1].digests.as_mut().expect("source digest").sha256 = "00".repeat(32);
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.facts.is_empty());
        input.artifacts[1].parent = None;
        let mut out = Output::default();
        analyze(&input, &mut out);
        assert!(out.facts.is_empty());
    }
}
