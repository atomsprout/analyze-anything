//! ELF fixtures. Expected values were read off `readelf -hlSd --dyn-syms -n` and
//! `llvm-readobj --file-headers --needed-libs` for the committed files.

use aa_core::Severity;
use serde_json::json;

use super::{cross, fact, fixture, has, names, run, severity};

#[test]
fn hardened_executable_matches_readelf() {
    let out = run("elf_hardened");
    assert_eq!(out.kinds, [("elf_hardened".to_string(), "elf".to_string())]);
    let header = fact(&out, "binary.header");
    assert_eq!(header["arch"], "x86_64");
    assert_eq!(header["file_type"], "pie-executable");
    assert_eq!(header["entry"], 0x1110);
    assert_eq!(header["build_id"], "a46ffbb81d92a25eccde895639315218bc717abc");
    assert_eq!(header["abi_tag"], "Linux 3.2.0");
    assert_eq!(names(fact(&out, "binary.libraries"), "libraries"), ["libc.so.6"]);
    let linking = fact(&out, "binary.linking");
    assert_eq!(linking["interp"], "/lib64/ld-linux-x86-64.so.2");
    assert_eq!(linking["static"], false);
    // readelf -d: FLAGS BIND_NOW, FLAGS_1 NOW PIE.
    assert_eq!(linking["dt_flags"], 0x8);
    assert_eq!(linking["dt_flags_1"], 0x0800_0001);
    assert_eq!(
        names(fact(&out, "binary.imports"), "symbols"),
        [
            "_ITM_deregisterTMCloneTable",
            "_ITM_registerTMCloneTable",
            "__cxa_finalize",
            "__gmon_start__",
            "__libc_start_main",
            "__printf_chk",
            "__stack_chk_fail",
            "__strcpy_chk"
        ]
    );
    assert_eq!(fact(&out, "binary.symbols"), &json!({ "stripped": true, "symtab": null, "dynsym": 8 }));
    assert_eq!(
        fact(&out, "binary.hardening"),
        &json!({
            "pie": true, "nx": true, "relro": "full", "canary": true, "fortify": true,
            "fortified_functions": ["__printf_chk", "__strcpy_chk"],
            "rpath": false, "runpath": false, "writable_executable": false, "cf_protection": ["IBT", "SHSTK"],
        })
    );
    for rule in [
        "binary.elf-pie",
        "binary.elf-nx",
        "binary.elf-relro-full",
        "binary.canary",
        "binary.elf-fortify",
        "binary.elf-cf-protection",
        "binary.symbols-stripped",
    ] {
        assert_eq!(severity(&out, rule), Severity::Info, "{rule}");
    }
    assert!(out.limitations.is_empty());
    assert_eq!(cross::check(&fixture("elf_hardened"), &out), "elf");
}

#[test]
fn weak_executable_matches_readelf() {
    let out = run("elf_weak");
    let header = fact(&out, "binary.header");
    assert_eq!(header["file_type"], "executable");
    assert_eq!(header["entry"], 0x401070);
    assert_eq!(header["build_id"], "72bde13dff52c6655dcc46c8eeb16c637637d254");
    assert_eq!(fact(&out, "binary.linking")["runpath"], json!(["$ORIGIN/lib", "./plugins"]));
    assert_eq!(fact(&out, "binary.symbols"), &json!({ "stripped": false, "symtab": 34, "dynsym": 4 }));
    let debug = fact(&out, "binary.debug");
    assert_eq!(debug["has_debug_info"], true);
    assert!(debug["sections"].as_array().expect("sections").contains(&json!(".debug_info")));
    let hardening = fact(&out, "binary.hardening");
    assert_eq!(hardening["pie"], false);
    assert_eq!(hardening["nx"], false);
    assert_eq!(hardening["relro"], "none");
    assert_eq!(hardening["canary"], false);
    assert_eq!(hardening["fortify"], false);
    assert_eq!(hardening["runpath"], true);
    for rule in ["binary.elf-no-pie", "binary.elf-nx-disabled", "binary.elf-relro-none", "binary.elf-rpath-risky"] {
        assert_eq!(severity(&out, rule), Severity::Medium, "{rule}");
    }
    for rule in ["binary.no-canary", "binary.elf-no-fortify"] {
        assert_eq!(severity(&out, rule), Severity::Low, "{rule}");
    }
    assert!(has(&out, "binary.symbols-present") && has(&out, "binary.debug-info") && has(&out, "binary.compiler-ident"));
    // readelf -S: .text is PROGBITS AX at 0x401070, file offset 0x1070, size 0x164.
    let sections = fact(&out, "binary.sections");
    let text = sections["sections"].as_array().expect("sections").iter().find(|s| s["name"] == ".text").expect(".text");
    assert_eq!(text["type"], "PROGBITS");
    assert_eq!(text["flags"], json!(["ALLOC", "EXECINSTR"]));
    assert_eq!((text["address"].as_u64(), text["offset"].as_u64(), text["size"].as_u64()), (Some(0x401070), Some(0x1070), Some(0x164)));
    assert!(text["entropy"].as_f64().is_some_and(|e| e > 4.0 && e < 7.0));
    assert_eq!(sections["total"], 37);
    assert_eq!(cross::check(&fixture("elf_weak"), &out), "elf");
}

#[test]
fn shared_library_matches_readelf() {
    let out = run("elf_lib.so");
    assert_eq!(fact(&out, "binary.header")["file_type"], "shared-library");
    assert_eq!(fact(&out, "binary.linking")["soname"], "libfixture.so.1");
    assert_eq!(names(fact(&out, "binary.exports"), "symbols"), ["fixture_add", "fixture_value"]);
    let hardening = fact(&out, "binary.hardening");
    // PIE is a property of executables.
    assert!(hardening["pie"].is_null());
    assert_eq!(hardening["relro"], "partial");
    assert_eq!(severity(&out, "binary.elf-relro-partial"), Severity::Low);
    assert!(!has(&out, "binary.elf-pie") && !has(&out, "binary.elf-no-pie"));
    assert_eq!(cross::check(&fixture("elf_lib.so"), &out), "elf");
}

#[test]
fn objects_of_other_classes_and_byte_orders() {
    let out = run("elf_i386.o");
    let header = fact(&out, "binary.header");
    assert_eq!((header["arch"].as_str(), header["bits"].as_u64(), header["endian"].as_str()), (Some("i386"), Some(32), Some("little")));
    assert_eq!(header["file_type"], "object");
    // Hardening is not judged for relocatable objects.
    assert_eq!(fact(&out, "binary.hardening"), &json!({}));
    assert_eq!(cross::check(&fixture("elf_i386.o"), &out), "elf");

    let out = run("elf_aarch64_be.o");
    let header = fact(&out, "binary.header");
    assert_eq!((header["arch"].as_str(), header["bits"].as_u64(), header["endian"].as_str()), (Some("aarch64"), Some(64), Some("big")));
    assert_eq!(cross::check(&fixture("elf_aarch64_be.o"), &out), "elf");
}

#[test]
fn static_file_without_sections_leaves_the_canary_open() {
    let out = run("elf_static");
    assert_eq!(fact(&out, "binary.linking")["static"], true);
    assert!(has(&out, "binary.static"));
    let hardening = fact(&out, "binary.hardening");
    assert!(hardening["canary"].is_null(), "no symbols: unknown, not false");
    assert_eq!(hardening["relro"], "none");
    assert_eq!(severity(&out, "binary.elf-relro-static"), Severity::Info);
    assert!(!has(&out, "binary.no-canary") && !has(&out, "binary.canary"));
    assert!(out.limitations.iter().any(|l| l.code == "binary.undetermined"));
    // Imports were not read, so there is no imports fact rather than an empty one.
    assert!(!out.facts.iter().any(|f| f.key == "binary.imports"));
}

/// With the section headers cut away, the dynamic segment still yields libraries and imports.
#[test]
fn dynamic_information_survives_without_section_headers() {
    let mut bytes = fixture("elf_hardened");
    // e_shoff, e_shnum, e_shstrndx.
    bytes[40..48].fill(0);
    bytes[60..64].fill(0);
    let out = super::run_bytes("sstripped", &bytes);
    assert_eq!(names(fact(&out, "binary.libraries"), "libraries"), ["libc.so.6"]);
    let imports = names(fact(&out, "binary.imports"), "symbols");
    assert!(imports.contains(&"__stack_chk_fail".to_string()) && imports.len() == 8, "{imports:?}");
    assert_eq!(fact(&out, "binary.hardening")["canary"], true);
    assert_eq!(fact(&out, "binary.hardening")["relro"], "full");
}
