//! Mach-O fixtures. Expected values were read off `llvm-otool -l`, `llvm-nm` and
//! `llvm-readobj --file-headers --macho-load-commands` for the committed files.

use aa_core::Severity;
use serde_json::json;

use std::collections::BTreeMap;

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

/// The committed arm64 fixture with its `LC_SYMTAB` command renamed to one nobody reads: what a
/// file without a symbol table looks like.
fn without_symtab() -> Vec<u8> {
    let mut bytes = fixture("macho_arm64");
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().expect("four bytes"));
    let mut at = 32;
    for _ in 0..ncmds {
        let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"));
        if word(at) == 0x2 {
            bytes[at..at + 4].copy_from_slice(&0x7f00_0001u32.to_le_bytes());
            return bytes;
        }
        at += word(at + 4) as usize;
    }
    panic!("the fixture has no LC_SYMTAB");
}

#[test]
fn symbol_table_and_dyld_tables_are_merged_without_double_counting() {
    let out = run("macho_arm64");
    let imports = fact(&out, "binary.imports");
    assert_eq!(imports["count"], 5);
    assert_eq!(imports["sources"], json!(["symtab", "bind-opcodes"]));
    assert_eq!(imports["by_source"], json!({ "symtab": 5, "bind-opcodes": 5 }));
    let exports = fact(&out, "binary.exports");
    assert_eq!(exports["count"], 2);
    assert_eq!(exports["sources"], json!(["symtab", "export-trie"]));
    assert_eq!(exports["by_source"], json!({ "symtab": 2, "export-trie": 2 }));
    // otool -l: LC_DYLD_INFO_ONLY with bind 49160+48, lazy bind 49208+56, export 49264+48.
    assert_eq!(
        fact(&out, "binary.macho")["dyld"],
        json!({
            "export_trie": { "offset": 49264, "size": 48, "command": "LC_DYLD_INFO" },
            "chained_fixups": null,
            "bind": { "offset": 49160, "size": 48 },
            "weak_bind": { "offset": 0, "size": 0 },
            "lazy_bind": { "offset": 49208, "size": 56 },
        })
    );
}

#[test]
fn imports_and_exports_survive_a_missing_symbol_table() {
    let whole = run("macho_arm64");
    let out = run_bytes("macho_arm64", &without_symtab());
    // The same names, libraries and addresses the symbol table gave (`dyld_info -imports -exports`
    // prints the same five and two for the fixture).
    let imports = fact(&out, "binary.imports");
    assert_eq!(imports["sources"], json!(["bind-opcodes"]));
    assert_eq!(imports["by_source"], json!({ "bind-opcodes": 5 }));
    assert_eq!(imports["symbols"], fact(&whole, "binary.imports")["symbols"]);
    let exports = fact(&out, "binary.exports");
    assert_eq!(exports["sources"], json!(["export-trie"]));
    assert_eq!(exports["symbols"], fact(&whole, "binary.exports")["symbols"]);
    assert_eq!(exports["symbols"][1], json!({ "name": "_main", "address": 0x1_0000_0578u64 }));
    assert_eq!(fact(&out, "binary.symbols")["symbols"], json!(null));

    // What is judged from imports is judged again.
    assert_eq!(fact(&out, "binary.hardening")["canary"], true);
    let canary = out.findings.iter().find(|f| f.rule == "binary.canary").expect("canary finding");
    // The evidence is the name where the bind opcodes spell it (the first stack-protector
    // symbol they bind is the guard).
    assert_eq!(canary.params["symbol"], "___stack_chk_guard");
    let aa_core::Location::Bytes { offset, length } = canary.evidence[0].location else { panic!("byte evidence") };
    let bytes = without_symtab();
    assert_eq!(&bytes[offset as usize..(offset + length) as usize], b"___stack_chk_guard");
    let counts = out.findings.iter().find(|f| f.rule == "binary.symbol-counts").expect("counts");
    assert_eq!((&counts.params["imports"], &counts.params["exports"]), (&json!(5), &json!(2)));
    // Whether local symbols were stripped is a statement about the symbol table.
    assert!(!has(&out, "binary.symbols-stripped") && !has(&out, "binary.symbols-present"));
    assert!(out.limitations.is_empty(), "{:?}", out.limitations);
}

#[test]
fn nothing_to_read_imports_from_is_still_a_limitation() {
    let mut bytes = without_symtab();
    let ncmds = u32::from_le_bytes(bytes[16..20].try_into().expect("four bytes"));
    let mut at = 32;
    for _ in 0..ncmds {
        let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("four bytes"));
        let size = word(at + 4) as usize;
        if word(at) == 0x8000_0022 {
            bytes[at..at + 4].copy_from_slice(&0x7f00_0002u32.to_le_bytes());
        }
        at += size;
    }
    let out = run_bytes("bare", &bytes);
    assert!(out.facts.iter().all(|f| f.key != "binary.imports" && f.key != "binary.exports"));
    assert_eq!(fact(&out, "binary.hardening")["canary"], json!(null));
    assert!(!has(&out, "binary.symbol-counts") && !has(&out, "binary.no-canary"));
    assert!(
        out.limitations.iter().any(
            |l| l.code == "binary.undetermined" && l.detail.as_deref().is_some_and(|d| d.contains("imports and exports were not read"))
        )
    );
}

/// Offsets of the two tables in [`chained_image`].
const TRIE_AT: usize = 0x200;
const FIXUPS_AT: usize = 0x240;

/// A 64-bit arm64 executable with no symbol table: two libraries, `LC_DYLD_EXPORTS_TRIE` and
/// `LC_DYLD_CHAINED_FIXUPS` holding the given tables.
fn chained_image(trie: &[u8], fixups: &[u8]) -> Vec<u8> {
    fn dylib(name: &str) -> Vec<u8> {
        let size = (24 + name.len() + 1).next_multiple_of(8);
        let mut command = Vec::new();
        for word in [0xcu32, size as u32, 24, 0, 0x0001_0000, 0x0001_0000] {
            command.extend(word.to_le_bytes());
        }
        command.extend_from_slice(name.as_bytes());
        command.resize(size, 0);
        command
    }
    let total = FIXUPS_AT + fixups.len();
    let mut segment = Vec::new();
    segment.extend(0x19u32.to_le_bytes());
    segment.extend(72u32.to_le_bytes());
    segment.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
    for word in [0x1_0000_0000u64, 0x4000, 0, total as u64] {
        segment.extend(word.to_le_bytes());
    }
    for word in [5u32, 5, 0, 0] {
        segment.extend(word.to_le_bytes());
    }
    let mut commands = vec![segment, dylib("/usr/lib/libSystem.B.dylib"), dylib("/usr/lib/libobjc.A.dylib")];
    for (cmd, at, size) in [(0x8000_0033u32, TRIE_AT, trie.len()), (0x8000_0034, FIXUPS_AT, fixups.len())] {
        commands.push([cmd, 16, at as u32, size as u32].iter().flat_map(|w| w.to_le_bytes()).collect());
    }
    let sizeofcmds: usize = commands.iter().map(Vec::len).sum();
    let mut image = Vec::new();
    // MH_MAGIC_64, arm64, executable; flags NOUNDEFS | DYLDLINK | TWOLEVEL | PIE.
    for word in [0xfeed_facfu32, 0x0100_000c, 0, 2, commands.len() as u32, sizeofcmds as u32, 0x0020_0085, 0] {
        image.extend(word.to_le_bytes());
    }
    image.extend(commands.concat());
    assert!(image.len() <= TRIE_AT && trie.len() <= FIXUPS_AT - TRIE_AT);
    image.resize(TRIE_AT, 0);
    image.extend_from_slice(trie);
    image.resize(FIXUPS_AT, 0);
    image.extend_from_slice(fixups);
    image
}

/// `_a` at image offset 0x10 and `_b`, passed on from the second library where it is `_orig`.
const TRIE: &[u8] = &[0, 2, b'_', b'a', 0, 10, b'_', b'b', 0, 14, 2, 0, 0x10, 0, 8, 8, 2, b'_', b'o', b'r', b'i', b'g', 0, 0];

/// `___stack_chk_fail` from library 1, `_opt` weakly from library 2, `_coalesced` by weak lookup.
fn fixups_table() -> Vec<u8> {
    let names = b"\0___stack_chk_fail\0_opt\0_coalesced\0";
    let mut table = Vec::new();
    for word in [0u32, 0, 28, 40, 3, 1, 0] {
        table.extend(word.to_le_bytes());
    }
    for (ordinal, weak, name_offset) in [(1u32, 0u32, 1u32), (2, 1, 19), (0xfd, 0, 24)] {
        table.extend((ordinal | (weak << 8) | (name_offset << 9)).to_le_bytes());
    }
    table.extend_from_slice(names);
    table
}

#[test]
fn chained_fixups_and_export_trie_without_a_symbol_table() {
    let bytes = chained_image(TRIE, &fixups_table());
    let out = run_bytes("chained", &bytes);
    assert!(out.limitations.is_empty(), "{:?}", out.limitations);
    assert_eq!(
        fact(&out, "binary.imports"),
        &json!({
            "count": 3,
            "truncated": false,
            "sources": ["chained-fixups"],
            "by_source": { "chained-fixups": 3 },
            "symbols": [
                { "name": "_coalesced", "library": "(weak lookup)", "weak": false },
                { "name": "___stack_chk_fail", "library": "/usr/lib/libSystem.B.dylib", "weak": false },
                { "name": "_opt", "library": "/usr/lib/libobjc.A.dylib", "weak": true },
            ],
        })
    );
    assert_eq!(
        fact(&out, "binary.exports"),
        &json!({
            "count": 2,
            "truncated": false,
            "sources": ["export-trie"],
            "by_source": { "export-trie": 2 },
            "symbols": [
                { "name": "_a", "address": 0x1_0000_0010u64 },
                { "name": "_b", "reexport": { "library": "/usr/lib/libobjc.A.dylib", "name": "_orig" } },
            ],
        })
    );
    let dyld = &fact(&out, "binary.macho")["dyld"];
    assert_eq!(dyld["export_trie"], json!({ "offset": TRIE_AT, "size": TRIE.len(), "command": "LC_DYLD_EXPORTS_TRIE" }));
    assert_eq!(
        dyld["chained_fixups"],
        json!({ "offset": FIXUPS_AT, "size": fixups_table().len(), "version": 0, "imports_format": 1, "imports": 3, "symbols_format": 0 })
    );
    assert_eq!(dyld["bind"], json!(null));
    assert_eq!(fact(&out, "binary.hardening")["canary"], true);
    let canary = out.findings.iter().find(|f| f.rule == "binary.canary").expect("canary finding");
    assert_eq!(canary.evidence[0].location, aa_core::Location::Bytes { offset: (FIXUPS_AT + 41) as u64, length: 17 });
    assert!(has(&out, "binary.symbol-counts"));
}

#[test]
fn damaged_dyld_tables_are_limitations_and_keep_what_was_read() {
    let malformed = |out: &aa_core::plugin::Output, wanted: &str| {
        assert!(
            out.limitations.iter().any(|l| l.code == "binary.malformed" && l.detail.as_deref().is_some_and(|d| d.contains(wanted))),
            "no limitation mentioning {wanted:?}: {:?}",
            out.limitations
        );
    };
    // A trie whose second child points back at the root.
    let mut cycle = TRIE.to_vec();
    cycle[9] = 0;
    let out = run_bytes("cycle", &chained_image(&cycle, &fixups_table()));
    malformed(&out, "reaches a node twice");
    assert_eq!(names(fact(&out, "binary.exports"), "symbols"), ["_a"]);
    assert_eq!(fact(&out, "binary.imports")["count"], 3);

    // A child offset outside the trie, and a ULEB that never ends.
    let mut outside = TRIE.to_vec();
    outside[5] = 0x7f;
    malformed(&run_bytes("outside", &chained_image(&outside, &fixups_table())), "outside the trie");
    let mut endless = TRIE.to_vec();
    endless[10..].fill(0x80);
    malformed(&run_bytes("endless", &chained_image(&endless, &fixups_table())), "cut off");

    // An import count in the millions, and an import whose name lies outside the table.
    let mut many = fixups_table();
    many[16..20].copy_from_slice(&0x00ff_ffffu32.to_le_bytes());
    let out = run_bytes("many", &chained_image(TRIE, &many));
    malformed(&out, "more imports than fit");
    assert!(fact(&out, "binary.imports")["count"].as_u64().expect("count") <= 16);
    let mut stray = fixups_table();
    stray[28..32].copy_from_slice(&(1u32 | (0x7f_ffff << 9)).to_le_bytes());
    let out = run_bytes("stray", &chained_image(TRIE, &stray));
    malformed(&out, "name outside");
    assert_eq!(names(fact(&out, "binary.imports"), "symbols"), ["_coalesced", "_opt"]);
    assert_eq!(fact(&out, "binary.hardening")["canary"], false);

    // Tables that end after the file does.
    let mut cut = chained_image(TRIE, &fixups_table());
    cut.truncate(FIXUPS_AT + 8);
    let out = run_bytes("cut", &cut);
    malformed(&out, "imports (chained fixups) extend past the end of the file");
    assert_eq!(fact(&out, "binary.imports")["count"], 0);
    assert_eq!(fact(&out, "binary.exports")["count"], 2);
}

#[test]
fn dyld_tables_corrupted_anywhere_never_panic() {
    let original = chained_image(TRIE, &fixups_table());
    for length in 0..original.len() {
        run_bytes("cut", &original[..length]);
    }
    let mut bytes = original.clone();
    for offset in (32..0x110).chain(TRIE_AT..original.len()) {
        for value in [0x00, 0x01, 0x7f, 0x80, 0xff, original[offset] ^ 0x08] {
            bytes[offset] = value;
            let out = run_bytes("flipped", &bytes);
            assert!(out.limitations.len() <= 64);
        }
        bytes[offset] = original[offset];
    }
    // The bind opcodes and trie of the linker-made fixture, byte by byte.
    let original = without_symtab();
    let mut bytes = original.clone();
    for offset in 49160..49312 {
        for value in [0x00, 0x40, 0x7f, 0x80, 0xff, original[offset] ^ 0x10] {
            bytes[offset] = value;
            run_bytes("flipped", &bytes);
        }
        bytes[offset] = original[offset];
    }
}

/// One slice's symbols as the system tools print them.
#[derive(Default)]
struct Reference {
    /// `dyld_info -exports`.
    trie: std::collections::BTreeSet<String>,
    /// `dyld_info -imports`: name and the libraries it is bound from.
    binds: BTreeMap<String, std::collections::BTreeSet<String>>,
    /// `objdump --macho --bind --lazy-bind --weak-bind`: the symbols the bind opcodes name.
    opcodes: std::collections::BTreeSet<String>,
    /// `nm -gU` and `nm -u`.
    defined: std::collections::BTreeSet<String>,
    undefined: std::collections::BTreeSet<String>,
}

fn tool(arguments: &[&str]) -> String {
    let done = std::process::Command::new("xcrun").args(arguments).output().expect("xcrun runs");
    String::from_utf8_lossy(&done.stdout).into_owned()
}

/// The name `dyld_info` prints for a library: the leaf without `.dylib` and one version suffix.
fn leaf(library: &str) -> Vec<String> {
    let special = match library {
        "(weak lookup)" => Some("<weak-def-coalesce>"),
        "(this image)" => Some("<this-image>"),
        "(main executable)" => Some("<main-executable>"),
        "(dynamic lookup)" => Some("<flat-namespace>"),
        _ => None,
    };
    if let Some(name) = special {
        return vec![name.to_string()];
    }
    let base = library.rsplit('/').next().unwrap_or(library);
    let base = base.strip_suffix(".dylib").unwrap_or(base);
    let shorter = base.rsplit_once('.').map_or(base, |(head, _)| head);
    vec![base.to_string(), shorter.to_string()]
}

fn references(path: &str) -> Vec<Reference> {
    let mut slices: Vec<Reference> = Vec::new();
    let mut section = "";
    for line in tool(&["dyld_info", "-exports", "-imports", path]).lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if line.starts_with(path) && line.ends_with("]:") {
            slices.push(Reference::default());
        } else if let ["-exports:"] | ["-imports:"] = words[..] {
            section = if words[0] == "-exports:" { "exports" } else { "imports" };
        } else if let (Some(slice), true) = (slices.last_mut(), words.len() >= 2 && words != ["offset", "symbol"]) {
            if section == "exports" {
                slice.trie.insert(words[1].to_string());
            } else {
                let name = if words[0].starts_with("0x") { words[1] } else { words[0] };
                let from = line.rsplit_once("(from ").map(|(_, tail)| tail.trim_end_matches(')').to_string()).unwrap_or_default();
                slice.binds.entry(name.to_string()).or_default().insert(from);
            }
        }
    }
    let mut index = None;
    for line in tool(&["objdump", "--macho", "--arch", "all", "--bind", "--lazy-bind", "--weak-bind", path]).lines() {
        // A weakly imported symbol is followed by a note.
        let words: Vec<&str> = line.split_whitespace().filter(|word| *word != "(weak_import)").collect();
        if line.starts_with(path) && line.ends_with(':') {
            index = Some(index.map_or(0, |i| i + 1));
        } else if let (Some(slice), true) = (index.and_then(|i: usize| slices.get_mut(i)), words.len() >= 5 && words[0] != "segment") {
            slice.opcodes.insert(words[words.len() - 1].to_string());
        }
    }
    for (flag, defined) in [("-gUj", true), ("-uj", false)] {
        let mut index = None;
        for line in tool(&["nm", "-arch", "all", flag, path]).lines() {
            if line.ends_with("):") && line.contains("(for architecture ") {
                index = Some(index.map_or(0, |i| i + 1));
            } else if !line.is_empty() {
                let slice = &mut slices[index.unwrap_or(0)];
                if defined {
                    slice.defined.insert(line.to_string())
                } else {
                    slice.undefined.insert(line.to_string())
                };
            }
        }
    }
    slices
}

/// Compares imports and exports with `dyld_info` and `nm` for every file named in
/// `AA_BINARY_DYLD_SAMPLES` (colon-separated), whole lists, on a Mac with Xcode:
/// `AA_BINARY_DYLD_SAMPLES=/bin/ls cargo test -p aa-binary --release crosscheck_dyld_info -- --ignored --nocapture`.
#[test]
#[ignore = "needs macOS with Xcode and sample files outside the repository"]
fn crosscheck_dyld_info() {
    let Ok(list) = std::env::var("AA_BINARY_DYLD_SAMPLES") else { return };
    crate::macho::SYMBOL_CAP.with(|cap| cap.set(usize::MAX));
    let mut failed = false;
    for path in list.split(':').filter(|p| !p.is_empty()) {
        let bytes = std::fs::read(path).expect("readable file");
        let out = run_bytes("sample", &bytes);
        let slices: Vec<serde_json::Value> = match out.facts.iter().find(|f| f.key == "binary.slices") {
            Some(found) => found.value.as_array().expect("slices").clone(),
            None => vec![json!({
                "arch": fact(&out, "binary.header")["arch"],
                "imports": fact(&out, "binary.imports"),
                "exports": fact(&out, "binary.exports"),
            })],
        };
        let reference = references(path);
        assert_eq!(slices.len(), reference.len(), "{path}: slice count");
        for (mine, theirs) in slices.iter().zip(&reference) {
            let arch = mine["arch"].as_str().unwrap_or("?");
            let (imports, exports) = (&mine["imports"], &mine["exports"]);
            assert_eq!(imports["truncated"], false);
            let exported: std::collections::BTreeSet<String> = names(exports, "symbols").into_iter().collect();
            let imported: BTreeMap<String, String> = imports["symbols"]
                .as_array()
                .expect("imports")
                .iter()
                .map(|s| (s["name"].as_str().expect("name").to_string(), s["library"].as_str().unwrap_or("").to_string()))
                .collect();
            let imported_names: std::collections::BTreeSet<String> = imported.keys().cloned().collect();
            let expected_exports: std::collections::BTreeSet<String> = theirs.trie.union(&theirs.defined).cloned().collect();
            // For an image bound by opcodes `dyld_info -imports` prints the undefined symbols of
            // the symbol table; what the opcodes themselves name is what objdump prints.
            let held = |fact: &serde_json::Value, source: &str| fact["by_source"].get(source).and_then(serde_json::Value::as_u64);
            let by_opcodes = held(imports, "bind-opcodes").is_some();
            let bound: std::collections::BTreeSet<String> =
                if by_opcodes { theirs.opcodes.clone() } else { theirs.binds.keys().cloned().collect() };
            let expected_imports: std::collections::BTreeSet<String> = bound.union(&theirs.undefined).cloned().collect();
            // Libraries: ours must be one dyld_info names for the symbol. Where the symbol table
            // names the library that defines a coalesced symbol, that is the answer kept.
            let (mut same, mut coalesced, mut different) = (0, 0, Vec::new());
            for (name, libraries) in &theirs.binds {
                let ours = imported.get(name).map(String::as_str).unwrap_or("");
                if leaf(ours).iter().any(|l| libraries.contains(l)) {
                    same += 1;
                } else if libraries.iter().all(|l| l == "<weak-def-coalesce>") && theirs.undefined.contains(name) {
                    coalesced += 1;
                } else {
                    different.push(format!("{name}: {ours:?} vs {libraries:?}"));
                }
            }
            let dyld_imports = held(imports, "chained-fixups").or(held(imports, "bind-opcodes"));
            // A symbol only the weak bind opcodes name is defined in the image itself.
            let weak_only = imported.iter().filter(|(name, library)| !theirs.binds.contains_key(*name) && *library == "(weak lookup)");
            let weak_only = weak_only.count();
            let checks = [
                ("export names", exported == expected_exports),
                ("import names", imported_names == expected_imports),
                ("export count", exports["count"] == exported.len()),
                ("import count", imports["count"] == imported.len()),
                ("exports held by the trie", held(exports, "export-trie").unwrap_or(0) == theirs.trie.len() as u64),
                ("exports held by the symbol table", held(exports, "symtab").unwrap_or(0) == theirs.defined.len() as u64),
                ("imports held by dyld tables", dyld_imports.unwrap_or(0) == bound.len() as u64),
                ("imports held by the symbol table", held(imports, "symtab").unwrap_or(0) == theirs.undefined.len() as u64),
                ("import libraries", different.is_empty()),
            ];
            println!(
                "{path} [{arch}]: exports {} (dyld_info {}, nm {}), imports {} ({} {}, nm {}), libraries same {same}, \
                 coalesced-with-known-library {coalesced}, weak-bind-only {weak_only}, different {}; sources {} / {}",
                exported.len(),
                theirs.trie.len(),
                theirs.defined.len(),
                imported.len(),
                if by_opcodes { "objdump" } else { "dyld_info" },
                bound.len(),
                theirs.undefined.len(),
                different.len(),
                exports["by_source"],
                imports["by_source"],
            );
            for (what, held) in checks {
                if !held {
                    failed = true;
                    println!("  MISMATCH {what}");
                }
            }
            for line in different.iter().take(5) {
                println!("    {line}");
            }
            for (what, ours, theirs) in [("export", &exported, &expected_exports), ("import", &imported_names, &expected_imports)] {
                for name in ours.symmetric_difference(theirs).take(5) {
                    println!("    {what} only in {}: {name}", if ours.contains(name) { "ours" } else { "the tools" });
                }
            }
        }
    }
    assert!(!failed, "see the mismatches above");
}
