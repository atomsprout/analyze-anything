//! Shared helpers for the tests in the format modules, and tests that span formats.

use std::collections::BTreeMap;
use std::path::PathBuf;

use aa_core::plugin::Output;
use aa_core::{Artifact, Severity};
use serde_json::Value;

use crate::rules::RULES;

mod cross;
mod elf;
mod lang;
mod macho;
mod malformed;
mod pe;

pub fn artifact(name: &str, size: usize) -> Artifact {
    Artifact {
        path: name.into(),
        parent: None,
        size: size as u64,
        digests: None,
        detected: None,
        kind: None,
        entropy: None,
        unpacked_by: None,
        facts: BTreeMap::new(),
    }
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

pub fn run_bytes(name: &str, bytes: &[u8]) -> Output {
    let mut out = Output::default();
    crate::analyze_bytes(&artifact(name, bytes.len()), bytes, &mut out);
    out
}

pub fn run(name: &str) -> Output {
    run_bytes(name, &fixture(name))
}

pub fn fact<'a>(out: &'a Output, key: &str) -> &'a Value {
    out.facts.iter().find(|f| f.key == key).map(|f| &f.value).unwrap_or_else(|| panic!("no fact {key}"))
}

pub fn has(out: &Output, rule: &str) -> bool {
    out.findings.iter().any(|f| f.rule == rule)
}

pub fn severity(out: &Output, rule: &str) -> Severity {
    out.findings.iter().find(|f| f.rule == rule).map(|f| f.severity).unwrap_or_else(|| panic!("no finding {rule}"))
}

/// The names in a `{ symbols: [{name}] }` or `{ libraries: [{name}] }` fact.
pub fn names(value: &Value, list: &str) -> Vec<String> {
    value[list].as_array().expect("a list").iter().map(|item| item["name"].as_str().expect("a name").to_string()).collect()
}

/// Every finding as the English sentence a report would print.
pub fn sentences(out: &Output) -> Vec<String> {
    out.findings
        .iter()
        .map(|finding| {
            let rule = RULES.iter().find(|r| r.id == finding.rule).unwrap_or_else(|| panic!("rule {} has no text", finding.rule));
            format!("[{:?}/{:?}] {}: {}", finding.severity, finding.confidence, finding.rule, aa_core::fill(rule.text_en, &finding.params))
        })
        .collect()
}

const FIXTURES: &[&str] = &[
    "elf_hardened",
    "elf_weak",
    "elf_lib.so",
    "elf_i386.o",
    "elf_aarch64_be.o",
    "elf_static",
    "pe_mingw64.exe",
    "pe_mingw32.dll",
    "pe_msvc64.exe",
    "pe_msvc32.exe",
    "pe_overlay.exe",
    "macho_arm64",
    "macho_x86_64",
    "macho_fat",
    "macho_arm64.o",
];

#[test]
fn rule_ids_are_unique_and_prefixed() {
    let mut seen = std::collections::BTreeSet::new();
    for rule in RULES {
        assert!(rule.id.starts_with("binary."), "{}", rule.id);
        assert!(seen.insert(rule.id), "duplicate rule {}", rule.id);
        assert!(!rule.text_zh.is_empty() && !rule.text_en.is_empty() && !rule.title_zh.is_empty() && !rule.title_en.is_empty());
    }
}

/// Every finding and limitation of every fixture has rule text, evidence, and no placeholder
/// left unfilled in either language.
#[test]
fn findings_are_complete() {
    for name in FIXTURES {
        let out = run(name);
        assert!(!out.kinds.is_empty(), "{name} was not recognised");
        assert!(!out.findings.is_empty(), "{name} produced no findings");
        for finding in &out.findings {
            let rule = RULES.iter().find(|r| r.id == finding.rule).unwrap_or_else(|| panic!("{name}: rule {} has no text", finding.rule));
            assert!(!finding.evidence.is_empty(), "{name}: {} has no evidence", finding.rule);
            assert_eq!(finding.analyzer, "binary");
            for text in [rule.text_en, rule.text_zh] {
                let filled = aa_core::fill(text, &finding.params);
                assert!(!filled.contains('{'), "{name}: {} leaves a placeholder: {filled}", finding.rule);
            }
        }
        for limitation in &out.limitations {
            assert!(RULES.iter().any(|r| r.id == limitation.code), "{name}: limitation {} has no text", limitation.code);
        }
        for fact in &out.facts {
            assert!(fact.key.starts_with("binary."), "{name}: fact {}", fact.key);
        }
    }
}

#[test]
fn output_is_deterministic() {
    for name in FIXTURES {
        let (a, b) = (run(name), run(name));
        assert_eq!(a.facts, b.facts, "{name}");
        assert_eq!(a.findings, b.findings, "{name}");
        assert_eq!(a.limitations, b.limitations, "{name}");
    }
}

#[test]
fn other_files_are_left_alone() {
    for bytes in [
        &b"plain text, long enough to pass the size check"[..],
        b"MZ but not a PE file at all, just two letters",
        b"\xca\xfe\xba\xbe\x00\x00\x00\x34 java class file header",
    ] {
        let out = run_bytes("x", bytes);
        assert!(out.kinds.is_empty() && out.findings.is_empty() && out.facts.is_empty() && out.limitations.is_empty());
    }
}

/// Prints what the analyzer says about the file named by `AA_BINARY_DUMP`, for comparing with
/// reference tools by hand: `AA_BINARY_DUMP=/path cargo test -p aa-binary dump -- --ignored --nocapture`.
#[test]
#[ignore = "manual inspection helper"]
fn dump() {
    let Ok(path) = std::env::var("AA_BINARY_DUMP") else { return };
    let bytes = std::fs::read(&path).expect("readable file");
    let out = run_bytes("input", &bytes);
    println!("kinds: {:?}", out.kinds);
    if std::env::var("AA_BINARY_FACTS").is_ok() {
        for fact in &out.facts {
            println!("## {}\n{}", fact.key, serde_json::to_string_pretty(&fact.value).expect("json"));
        }
    }
    for sentence in sentences(&out) {
        println!("{sentence}");
    }
    for limitation in &out.limitations {
        println!("LIMITATION {} {:?}", limitation.code, limitation.detail);
    }
}

/// Compares against goblin for every file named in `AA_BINARY_SAMPLES` (colon-separated), for
/// checking real-world binaries that are too large to commit.
#[test]
#[ignore = "needs sample files outside the repository"]
fn crosscheck_samples() {
    let Ok(list) = std::env::var("AA_BINARY_SAMPLES") else { return };
    for path in list.split(':').filter(|p| !p.is_empty()) {
        let bytes = std::fs::read(path).expect("readable file");
        let out = run_bytes("sample", &bytes);
        // goblin rejects some files outright (packed PE files, for one); those are reported, not fatal.
        match std::panic::catch_unwind(|| cross::check(&bytes, &out)) {
            Ok(kind) => println!("{path}: {kind} ok, {} findings, {} limitations", out.findings.len(), out.limitations.len()),
            Err(_) => println!("{path}: COMPARISON FAILED"),
        }
        // One line per fact for scripts that compare against readelf or llvm-readobj output.
        for wanted in
            ["binary.header", "binary.hardening", "binary.pe", "binary.macho", "binary.libraries", "binary.linking", "binary.slices"]
        {
            if let Some(found) = out.facts.iter().find(|f| f.key == wanted) {
                println!("FACT\t{path}\t{wanted}\t{}", found.value);
            }
        }
    }
}
