//! Feeds arbitrary bytes to the whole engine: every unpacker and analyzer sees them.
//!
//! Run with `cargo +nightly fuzz run analyze`. Seed the corpus with the fixtures:
//! `cargo +nightly fuzz run analyze fuzz/corpus/analyze crates/*/tests/data`.
#![no_main]

use std::sync::LazyLock;

use aa_engine::{Limits, NoProgress, Options, Registry, analyze_bytes};
use libfuzzer_sys::fuzz_target;

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    // libFuzzer aborts on every panic. A panic inside a third-party decoder is caught by the
    // engine and reported as a limitation, so only panics in this project's own code count here.
    let abort = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let third_party = info.location().is_some_and(|l| l.file().contains("/.cargo/registry/") || l.file().contains("/rustc/"));
        if !third_party {
            abort(info);
        }
    }));
    Registry::standard()
});

fuzz_target!(|data: &[u8]| {
    // Tight limits keep each run short, so the fuzzer explores parsers instead of waiting.
    let limits = Limits { max_files: 2_000, max_total_bytes: 1 << 26, max_unpacked_bytes: 1 << 24, max_entry_bytes: 1 << 22, max_depth: 3, analyzer_seconds: 20, unpack_seconds: 20 };
    let options = Options { limits, ..Options::default() };
    let report = analyze_bytes(&REGISTRY, "input", data.to_vec(), &options, &mut NoProgress);
    // A caught panic becomes a limitation. Its text names the analyzer or unpacker; a panic in
    // this project's own code has already aborted through the hook above.
    let _ = report;
});
