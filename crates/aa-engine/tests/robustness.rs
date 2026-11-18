//! Damaged inputs must never crash or hang the engine.
//!
//! Every fixture under any crate's `tests/data/` is cut short and corrupted in many ways, and
//! each variant is analyzed with every built-in format. The run must finish and return a report.
//! The corruption is generated from a fixed seed, so a failure is reproducible by name.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use aa_engine::{NoProgress, Options, analyze};

/// Longest a single damaged input may take. Generous: fixtures are under 200 KB.
const TIME_LIMIT: Duration = Duration::from_secs(60);
/// Fixtures above this size are skipped; the fixture rules keep them below it anyway.
const MAX_FIXTURE: u64 = 512 * 1024;

struct Random(u64);

impl Random {
    fn below(&mut self, bound: usize) -> usize {
        // xorshift64: small, fast, and the same sequence everywhere.
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound.max(1) as u64) as usize
    }
}

fn fixtures() -> Vec<PathBuf> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("crates folder").to_path_buf();
    let mut found = Vec::new();
    let mut pending: Vec<PathBuf> = std::fs::read_dir(&crates)
        .expect("list crates")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path().join("tests").join("data"))
        .filter(|path| path.is_dir())
        .collect();
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("list fixtures").filter_map(|entry| entry.ok()) {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if entry.metadata().is_ok_and(|m| m.len() > 0 && m.len() <= MAX_FIXTURE) {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The damaged variants of one fixture, each with a name that says how it was made.
fn variants(bytes: &[u8], random: &mut Random) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for part in 1..12 {
        let length = bytes.len() * part / 12;
        out.push((format!("cut at {length}"), bytes[..length].to_vec()));
    }
    for length in [1usize, 2, 4, 8, 16, 32, 64, 128, 512] {
        if length < bytes.len() {
            out.push((format!("cut at {length}"), bytes[..length].to_vec()));
            out.push((format!("last {length} bytes dropped"), bytes[..bytes.len() - length].to_vec()));
        }
    }
    // Headers live at the start, so most single-byte damage goes there.
    for round in 0..40 {
        let window = if round < 28 { bytes.len().min(1024) } else { bytes.len() };
        let at = random.below(window);
        let value = [0x00, 0xff, 0x7f, 0x80][random.below(4)];
        let mut copy = bytes.to_vec();
        copy[at] = value;
        out.push((format!("byte {at} set to {value:#04x}"), copy));
    }
    for _ in 0..8 {
        let mut copy = bytes.to_vec();
        let start = random.below(bytes.len());
        let length = random.below(64).min(bytes.len() - start);
        copy[start..start + length].fill(0xff);
        out.push((format!("{length} bytes at {start} set to 0xff"), copy));
    }
    out
}

#[test]
fn damaged_fixtures_never_crash_or_hang() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut runs = 0u64;
    for fixture in fixtures() {
        let bytes = std::fs::read(&fixture).expect("read fixture");
        let name = fixture.file_name().expect("file name").to_string_lossy().into_owned();
        for (how, damaged) in variants(&bytes, &mut random) {
            // Keep the original name: several formats are recognised partly by extension.
            let path = dir.path().join(&name);
            std::fs::write(&path, &damaged).expect("write variant");
            let (done, finished) = mpsc::channel();
            let worker = std::thread::spawn({
                let path = path.clone();
                move || {
                    let result = analyze(&path, &Options::default(), &mut NoProgress).map(|report| report.artifacts.len());
                    let _ = done.send(result.map_err(|error| error.to_string()));
                }
            });
            match finished.recv_timeout(TIME_LIMIT) {
                Ok(Ok(artifacts)) => assert!(artifacts >= 1, "{}: {how}: no artifact for the input itself", fixture.display()),
                Ok(Err(error)) => panic!("{}: {how}: engine error: {error}", fixture.display()),
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("{}: {how}: still running after {TIME_LIMIT:?}", fixture.display()),
                Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{}: {how}: the engine crashed", fixture.display()),
            }
            worker.join().expect("worker thread");
            runs += 1;
        }
    }
    // With no fixtures yet the test is vacuous; say so rather than pass silently.
    eprintln!("analyzed {runs} damaged inputs");
}
