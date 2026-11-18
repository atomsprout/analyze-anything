//! Mach-O fixtures. Expected values were read off `llvm-otool -l`, `llvm-nm` and
//! `llvm-readobj --file-headers --macho-load-commands` for the committed files.

use aa_core::Severity;
use serde_json::json;

use super::{cross, fact, fixture, has, names, run, run_bytes, sentences, severity};

#[test]
fn arm64_executable_matches_otool() {
    let out = run("macho_arm64");
    assert_eq!(out.kinds, [("macho_arm64".to_string(), "macho".to_string())]);
    let header = fact(&out, "binary.header");
    assert_eq!(header["arch"], "arm64");
    assert_eq!(header["file_type"], "executable");
    assert_eq!(header["flags"], json!(["NOUNDEFS", "DYLDLINK", "TWOLEVEL", "PIE"]));
    assert_eq!(header["flags_raw"], 0x0020_0085);
    assert_eq!(header["min_os"], json!({ "platform": "macOS", "minos": "12.0", "sdk": "13.1", "source": "LC_BUILD_VERSION" }));
    assert_eq!(header["uuid"], "4C4C44D0-5555-3144-A176-4667C08FE995");
    assert_eq!(header["entry_offset"], 1400);
    assert_eq!(header["entry"], 0x1_0000_0578u64);
    assert_eq!(
        fact(&out, "binary.libraries")["libraries"],
        json!([{ "name": "/usr/lib/libSystem.B.dylib", "kind": "load", "current_version": "1345.100.2", "compatibility_version": "1.0" }])
    );
    assert_eq!(
        fact(&out, "binary.linking"),
        &json!({ "install_name": null, "dylinker": "/usr/lib/dyld", "rpaths": ["@executable_path/../Frameworks"] })
    );
    let imports = fact(&out, "binary.imports");
    assert_eq!(names(imports, "symbols"), ["___stack_chk_fail", "___stack_chk_guard", "_puts", "_strcpy", "dyld_stub_binder"]);
    assert_eq!(imports["symbols"][0]["library"], "/usr/lib/libSystem.B.dylib");
    assert_eq!(names(fact(&out, "binary.exports"), "symbols"), ["__mh_execute_header", "_main"]);
    let macho = fact(&out, "binary.macho");
    assert_eq!(macho["load_commands"].as_array().map(Vec::len), Some(17));
    assert_eq!(macho["code_signature"], json!({ "offset": 49600, "size": 544 }));
    assert!(macho["encryption"].is_null());
    let text = &fact(&out, "binary.sections")["sections"][0];
    assert_eq!((text["name"].as_str(), text["segment"].as_str()), (Some("__text"), Some("__TEXT")));
    assert_eq!(
        (text["address"].as_u64(), text["offset"].as_u64(), text["size"].as_u64(), text["flags"].as_u64()),
        (Some(0x1_0000_0578), Some(1400), Some(0x64), Some(0x8000_0400))
    );
    assert_eq!(
        fact(&out, "binary.hardening"),
        &json!({ "pie": true, "nx_stack": true, "nx_heap_flag": false, "canary": true, "arc": null, "restrict_segment": false, "writable_executable": false })
    );
    for rule in ["binary.macho-pie", "binary.macho-nx-stack", "binary.canary", "binary.macho-build-tools", "binary.macho-min-os"] {
        assert_eq!(severity(&out, rule), Severity::Info, "{rule}");
    }
    assert!(out.limitations.is_empty());
    assert_eq!(cross::check(&fixture("macho_arm64"), &out), "macho");
}

#[test]
fn x86_64_executable_without_pie_or_canary() {
    let out = run("macho_x86_64");
    let header = fact(&out, "binary.header");
    assert_eq!(header["arch"], "x86_64");
    assert_eq!(header["min_os"]["minos"], "10.13");
    let hardening = fact(&out, "binary.hardening");
    assert_eq!(hardening["pie"], false);
    assert_eq!(hardening["canary"], false);
    assert_eq!(severity(&out, "binary.macho-no-pie"), Severity::Medium);
    assert_eq!(severity(&out, "binary.no-canary"), Severity::Low);
    assert_eq!(cross::check(&fixture("macho_x86_64"), &out), "macho");
}

#[test]
fn universal_binary_reports_every_slice() {
    let bytes = fixture("macho_fat");
    let out = run("macho_fat");
    assert_eq!(out.kinds, [("macho_fat".to_string(), "macho-fat".to_string())]);
    assert_eq!(fact(&out, "binary.header"), &json!({ "format": "macho-fat", "fat64": false, "slices": 2, "archs": ["x86_64", "arm64"] }));
    let slices = fact(&out, "binary.slices").as_array().expect("slices");
    // llvm-objdump --universal-headers: x86_64 at 4096 (12608 bytes), arm64 at 32768 (50144 bytes).
    assert_eq!(
        (slices[0]["arch"].as_str(), slices[0]["offset"].as_u64(), slices[0]["size"].as_u64()),
        (Some("x86_64"), Some(4096), Some(12608))
    );
    assert_eq!(
        (slices[1]["arch"].as_str(), slices[1]["offset"].as_u64(), slices[1]["size"].as_u64()),
        (Some("arm64"), Some(32768), Some(50144))
    );
    // Each slice carries the same facts the thin file does.
    let thin = run("macho_arm64");
    for key in [
        "header",
        "sections",
        "segments",
        "libraries",
        "linking",
        "imports",
        "exports",
        "symbols",
        "hardening",
        "toolchain",
        "macho",
        "debug",
    ] {
        assert_eq!(&slices[1][key], fact(&thin, &format!("binary.{key}")), "{key}");
        assert_eq!(slices[0]["kind"], "macho");
    }
    // Findings name their slice, and evidence offsets are file offsets, not slice offsets.
    let text = sentences(&out);
    assert!(text.iter().any(|s| s.contains("binary.macho-no-pie: [x86_64] ")));
    assert!(text.iter().any(|s| s.contains("binary.macho-pie: [arm64] ")));
    let pie = out.findings.iter().find(|f| f.rule == "binary.macho-pie").expect("pie finding");
    assert_eq!(pie.evidence[0].location, aa_core::Location::Bytes { offset: 32768 + 24, length: 4 });
    assert_eq!(&bytes[32768 + 24..32768 + 28], 0x0020_0085u32.to_le_bytes());
    assert_eq!(cross::check(&bytes, &out), "macho-fat");
}

#[test]
fn slice_outside_the_file_is_a_limitation() {
    let mut bytes = fixture("macho_fat");
    bytes.truncate(40_000);
    let out = run_bytes("cut", &bytes);
    let slices = fact(&out, "binary.slices").as_array().expect("slices");
    assert_eq!(slices[0]["kind"], "macho");
    assert_eq!(slices[1]["kind"], "truncated");
    assert!(slices[1].get("header").is_none());
    assert!(out.limitations.iter().any(|l| l.code == "binary.malformed" && l.detail.as_deref().is_some_and(|d| d.contains("arm64 slice"))));
}

#[test]
fn relocatable_object() {
    let out = run("macho_arm64.o");
    assert_eq!(fact(&out, "binary.header")["file_type"], "object");
    // Hardening is not judged for objects.
    assert_eq!(fact(&out, "binary.hardening"), &json!({}));
    assert!(!has(&out, "binary.macho-pie") && !has(&out, "binary.macho-no-pie"));
    assert_eq!(cross::check(&fixture("macho_arm64.o"), &out), "macho");
}

#[test]
fn java_class_files_are_not_universal_binaries() {
    // Same magic; the next word is the class-file version (Java 8 = 52), not a slice count.
    let mut class = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52];
    class.resize(256, 0);
    assert!(run_bytes("A.class", &class).kinds.is_empty());
    // A small "count" whose entries point at nothing recognisable is not accepted either.
    let mut odd = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
    odd.resize(256, 0);
    let out = run_bytes("odd", &odd);
    assert!(out.kinds.is_empty() && out.facts.is_empty());
}

#[test]
fn version_and_architecture_names() {
    assert_eq!(crate::macho::version(0x000d_0100), "13.1");
    assert_eq!(crate::macho::version(0x000a_0d04), "10.13.4");
    assert_eq!(crate::macho::arch_name(0x0100_000c, 0x8000_0002), Some("arm64e"));
    assert_eq!(crate::macho::arch_name(12, 9), Some("armv7"));
    assert_eq!(crate::macho::arch_name(99, 0), None);
}
