//! PE fixtures. Expected values were read off `llvm-readobj --file-headers --sections
//! --coff-imports --coff-exports --coff-debug-directory --coff-load-config` for the committed files.

use aa_core::Severity;
use serde_json::json;

use super::{cross, fact, fixture, has, names, run, run_bytes, severity};

#[test]
fn msvc_style_64_bit_matches_llvm_readobj() {
    let out = run("pe_msvc64.exe");
    assert_eq!(out.kinds, [("pe_msvc64.exe".to_string(), "pe".to_string())]);
    let header = fact(&out, "binary.header");
    assert_eq!(header["arch"], "x86_64");
    assert_eq!(header["file_type"], "executable");
    assert_eq!(header["subsystem"], "windows-console");
    assert_eq!(header["entry"], 0x1010);
    assert_eq!(header["image_base"], 0x1_4000_0000u64);
    assert_eq!(header["timestamp"], 0x77FE_35D6u32);
    assert_eq!(header["timestamp_is_hash"], true);
    assert_eq!(header["characteristics"], json!(["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]));
    assert_eq!(header["dll_characteristics"], json!(["HIGH_ENTROPY_VA", "DYNAMIC_BASE", "NX_COMPAT", "GUARD_CF", "TERMINAL_SERVER_AWARE"]));
    assert_eq!(header["dll_characteristics_raw"], 0xC160);
    let debug = fact(&out, "binary.debug");
    assert_eq!(debug["pdb"], json!({ "path": "C:\\build\\fixture\\msvc64.pdb", "guid": "D5AF8E04-2AEA-DEC9-4C4C-44205044422E", "age": 1 }));
    assert_eq!(debug["kinds"], json!(["pdb-reference"]));
    let imports = fact(&out, "binary.imports");
    assert_eq!(
        imports["symbols"],
        json!([{ "name": "ExitProcess", "library": "KERNEL32.dll" }, { "name": "MessageBoxA", "library": "USER32.dll" }])
    );
    assert_eq!(
        fact(&out, "binary.libraries")["libraries"],
        json!([{ "name": "KERNEL32.dll", "kind": "import", "functions": 1 }, { "name": "USER32.dll", "kind": "delay-import", "functions": 1 }])
    );
    assert_eq!(fact(&out, "binary.pe")["load_config"]["security_cookie"], 0x1_4000_3000u64);
    assert_eq!(
        fact(&out, "binary.hardening"),
        &json!({
            "applicable": true, "aslr": true, "high_entropy_va": true, "dep": true, "cfg": true, "gs": true,
            "force_integrity": false, "cet_compat": null, "writable_executable": false, "signature_present": false,
        })
    );
    for rule in [
        "binary.pe-aslr",
        "binary.pe-high-entropy-va",
        "binary.pe-dep",
        "binary.pe-cfg",
        "binary.pe-gs",
        "binary.pe-timestamp-hash",
        "binary.pe-pdb",
    ] {
        assert_eq!(severity(&out, rule), Severity::Info, "{rule}");
    }
    assert_eq!(fact(&out, "binary.hardening")["signature_present"], false);
    assert!(!has(&out, "binary.pe-overlay") && !has(&out, "binary.pe-safeseh") && !has(&out, "binary.pe-no-safeseh"));
    assert!(out.limitations.is_empty());
    assert_eq!(cross::check(&fixture("pe_msvc64.exe"), &out), "pe");
}

#[test]
fn msvc_style_32_bit_without_protections() {
    let out = run("pe_msvc32.exe");
    let header = fact(&out, "binary.header");
    assert_eq!((header["arch"].as_str(), header["bits"].as_u64()), (Some("i386"), Some(32)));
    assert_eq!(header["subsystem"], "windows-gui");
    assert_eq!(header["timestamp"], 1_700_000_000);
    assert_eq!(header["image_base"], 0x40_0000);
    assert_eq!(header["subsystem_version"], "6.0");
    let finding = out.findings.iter().find(|f| f.rule == "binary.pe-timestamp").expect("timestamp finding");
    assert_eq!(finding.params["utc"], "2023-11-14T22:13:20Z");
    let hardening = fact(&out, "binary.hardening");
    assert_eq!(hardening["aslr"], false);
    assert_eq!(hardening["dep"], false);
    assert_eq!(hardening["cfg"], false);
    assert_eq!(hardening["gs"], true);
    assert_eq!(hardening["safe_seh"], false);
    assert!(hardening.get("high_entropy_va").is_none(), "64-bit only");
    assert_eq!(severity(&out, "binary.pe-no-aslr"), Severity::Medium);
    assert_eq!(severity(&out, "binary.pe-no-dep"), Severity::Medium);
    assert_eq!(severity(&out, "binary.pe-no-cfg"), Severity::Low);
    assert_eq!(severity(&out, "binary.pe-no-safeseh"), Severity::Low);
    assert_eq!(fact(&out, "binary.pe")["load_config"]["security_cookie"], 0x40_3000);
    assert_eq!(cross::check(&fixture("pe_msvc32.exe"), &out), "pe");
}

#[test]
fn mingw_executable_and_dll() {
    let out = run("pe_mingw64.exe");
    let sections = fact(&out, "binary.sections");
    let listed: Vec<&str> = sections["sections"].as_array().expect("sections").iter().filter_map(|s| s["name"].as_str()).collect();
    assert_eq!(listed, [".text", ".data", ".rdata", ".pdata", ".xdata", ".bss", ".idata", ".CRT", ".tls", ".reloc"]);
    let text = &sections["sections"][0];
    assert_eq!(
        (text["virtual_address"].as_u64(), text["virtual_size"].as_u64(), text["offset"].as_u64(), text["size"].as_u64()),
        (Some(0x1000), Some(0x6B98), Some(0x400), Some(27648))
    );
    assert!(text["flags"].as_array().expect("flags").contains(&json!("MEM_EXECUTE")));
    // .bss has no bytes in the file, so no entropy; not zero.
    assert!(sections["sections"][5]["entropy"].is_null());
    assert_eq!(names(fact(&out, "binary.libraries"), "libraries"), ["KERNEL32.dll", "msvcrt.dll"]);
    assert!(has(&out, "binary.pe-mingw") && !has(&out, "binary.pe-rich-header"));
    assert_eq!(severity(&out, "binary.pe-no-gs"), Severity::Low);
    assert_eq!(cross::check(&fixture("pe_mingw64.exe"), &out), "pe");

    let out = run("pe_mingw32.dll");
    assert_eq!(fact(&out, "binary.header")["file_type"], "dll");
    let exports = fact(&out, "binary.exports");
    assert_eq!(
        exports["symbols"],
        json!([{ "name": "fixture_add", "ordinal": 1, "address": 0x14D0 }, { "name": "fixture_value", "ordinal": 2, "address": 0x3008 }])
    );
    assert_eq!(fact(&out, "binary.pe")["export_name"], "pe_mingw32.dll");
    let imports = fact(&out, "binary.imports");
    assert_eq!(imports["count"], 26);
    let kernel: Vec<&str> = imports["symbols"]
        .as_array()
        .expect("symbols")
        .iter()
        .filter(|s| s["library"] == "KERNEL32.dll")
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert_eq!(kernel.len(), 13);
    assert!(kernel.contains(&"VirtualProtect"));
    assert_eq!(cross::check(&fixture("pe_mingw32.dll"), &out), "pe");
}

#[test]
fn overlay_is_reported_with_offset_and_size() {
    let out = run("pe_overlay.exe");
    assert_eq!(
        fact(&out, "binary.overlay"),
        &json!({ "offset": 2560, "size": 4, "payload_size": 4, "after_signature_size": 0, "certificate_table_only": false, "entropy": 1.5 })
    );
    let finding = out.findings.iter().find(|f| f.rule == "binary.pe-overlay").expect("overlay finding");
    assert_eq!((finding.params["offset"].as_u64(), finding.params["size"].as_u64()), (Some(2560), Some(4)));
    assert!(!out.facts.iter().any(|f| f.key == "binary.overlay" && run("pe_msvc32.exe").facts.contains(f)), "the original has no overlay");
}

/// Offset of the security (certificate table) data directory entry of the 32-bit fixture.
fn security_directory(bytes: &[u8]) -> usize {
    let lfanew = u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("four bytes")) as usize;
    lfanew + 24 + 96 + 4 * 8
}

#[test]
fn certificate_table_is_presence_only_and_not_an_overlay() {
    let mut bytes = fixture("pe_msvc32.exe");
    let (start, size) = (bytes.len() as u32, 64u32);
    bytes.extend(std::iter::repeat_n(0x30, size as usize));
    let entry = security_directory(&bytes);
    bytes[entry..entry + 4].copy_from_slice(&start.to_le_bytes());
    bytes[entry + 4..entry + 8].copy_from_slice(&size.to_le_bytes());
    let out = run_bytes("signed.exe", &bytes);
    assert!(!has(&out, "binary.pe-overlay"), "a certificate table alone is not unexplained data");
    assert_eq!(fact(&out, "binary.pe")["certificate_table"], json!({ "offset": start, "size": size }));
    assert_eq!(fact(&out, "binary.overlay")["certificate_table_only"], true);
    assert_eq!(fact(&out, "binary.hardening")["signature_present"], true);

    // Bytes after the signature are outside what it covers.
    bytes.extend_from_slice(b"appended after signing");
    let out = run_bytes("signed.exe", &bytes);
    assert_eq!(fact(&out, "binary.overlay")["after_signature_size"], 22);

    // A certificate table that points past the end of the file is a limitation, not a signature.
    let mut broken = fixture("pe_msvc32.exe");
    let entry = security_directory(&broken);
    broken[entry..entry + 4].copy_from_slice(&0x00ff_0000u32.to_le_bytes());
    broken[entry + 4..entry + 8].copy_from_slice(&64u32.to_le_bytes());
    let out = run_bytes("broken.exe", &broken);
    assert_eq!(fact(&out, "binary.hardening")["signature_present"], false);
    assert!(out.limitations.iter().any(|l| l.detail.as_deref().is_some_and(|d| d.contains("certificate table"))));
}

#[test]
fn rich_header_is_decoded() {
    // DanS, three padding words, two records, Rich, key: all but the last two XOR-ed with the key.
    let key = 0x1234_5678u32;
    let records = [(0x0104u32, 30_729u32, 7u32), (0x00ff, 33_135, 1)];
    let mut stub = vec![0u8; 0x80];
    stub[..2].copy_from_slice(b"MZ");
    for word in [0x536e_6144u32, 0, 0, 0] {
        stub.extend((word ^ key).to_le_bytes());
    }
    for (product, build, count) in records {
        stub.extend(((product << 16 | build) ^ key).to_le_bytes());
        stub.extend((count ^ key).to_le_bytes());
    }
    stub.extend(b"Rich");
    stub.extend(key.to_le_bytes());
    let lfanew = stub.len() as u64;
    let rich = crate::pe::rich_header(&crate::common::Rd::new(&stub, true), lfanew).expect("a Rich header");
    assert_eq!(rich.offset, 0x80);
    assert_eq!(rich.key, key);
    assert_eq!(
        rich.entries,
        [json!({ "product_id": 0x0104, "build": 30_729, "count": 7 }), json!({ "product_id": 0x00ff, "build": 33_135, "count": 1 })]
    );
    // No marker, or a marker without a matching start: no header.
    assert!(crate::pe::rich_header(&crate::common::Rd::new(&stub[..0x90], true), 0x90).is_none());
    stub[0x80] ^= 0xff;
    assert!(crate::pe::rich_header(&crate::common::Rd::new(&stub, true), lfanew).is_none());
}

#[test]
fn timestamps_convert_to_utc() {
    assert_eq!(crate::pe::utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(crate::pe::utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(crate::pe::utc(0x77FE_35D6), "2033-10-17T07:57:10Z");
    assert_eq!(crate::pe::utc(u32::MAX), "2106-02-07T06:28:15Z");
}

#[test]
fn guids_use_registry_byte_order() {
    let raw = [0xC4, 0x5C, 0x95, 0x66, 0x60, 0xD5, 0xAC, 0xA9, 0x4C, 0x4C, 0x44, 0x20, 0x50, 0x44, 0x42, 0x2E];
    assert_eq!(crate::pe::guid_text(&raw), "66955CC4-D560-A9AC-4C4C-44205044422E");
}
