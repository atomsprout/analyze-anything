//! Feeds arbitrary bytes to the whole engine: every unpacker and analyzer sees them.
//!
//! Run with `cargo +nightly fuzz run analyze`. Seed the corpus with the fixtures:
//! `cargo +nightly fuzz run analyze fuzz/corpus/analyze crates/*/tests/data`.
#![no_main]

use std::sync::LazyLock;

use aa_engine::{Limits, NoProgress, Options, Registry, analyze_bytes};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::standard);

fuzz_target!(|data: &[u8]| {
    // Tight limits keep each run short, so the fuzzer explores parsers instead of waiting.
    let limits = Limits { max_files: 2_000, max_total_bytes: 1 << 26, max_unpacked_bytes: 1 << 24, max_entry_bytes: 1 << 22, max_depth: 3 };
    let options = Options { limits, cancel: None };
    let report = analyze_bytes(&REGISTRY, "input", data.to_vec(), &options, &mut NoProgress);
    // A panicking analyzer is caught by the engine and recorded; for the fuzzer it is a bug.
    if let Some(failure) = report.limitations.iter().find(|l| l.code == "analyzer_failed") {
        panic!("analyzer failed: {:?}", failure.detail);
    }
});
