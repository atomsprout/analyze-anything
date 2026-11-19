//! Hostile input: truncated files, flipped header bytes, huge counts. Nothing may panic, and a
//! run that panics on overflow in a debug build fails here too.

use super::{FIXTURES, fixture, run_bytes};

/// A small deterministic generator, so failures reproduce.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

/// The larger fixtures take longer per run and are sampled more coarsely; an odd stride still
/// reaches every byte position within a field over the length of the headers.
fn stride(bytes: &[u8]) -> usize {
    if bytes.len() > 30_000 { 3 } else { 1 }
}

fn check(name: &str, bytes: &[u8]) {
    let out = run_bytes(name, bytes);
    assert!(out.limitations.len() <= 64, "{name}: {} limitations", out.limitations.len());
}

#[test]
fn truncated_at_every_early_length_and_many_later_ones() {
    for name in FIXTURES {
        let bytes = fixture(name);
        let step = (bytes.len() / 150).max(1);
        let lengths = (0..bytes.len().min(1200)).chain((1200..bytes.len()).step_by(step));
        for length in lengths {
            check(name, &bytes[..length]);
        }
    }
}

#[test]
fn single_bytes_overwritten_in_headers() {
    for name in FIXTURES {
        let original = fixture(name);
        let mut bytes = original.clone();
        // Headers and load commands sit in the first kilobytes; the fat fixture's slices start
        // at 4 KiB and 16 KiB.
        let offsets = (0..bytes.len().min(1024)).chain(4096..bytes.len().min(4096 + 256)).chain(16384..bytes.len().min(16384 + 256));
        for offset in offsets.step_by(stride(&bytes)) {
            for value in [0xff, original[offset] ^ 0x01] {
                bytes[offset] = value;
                check(name, &bytes);
            }
            bytes[offset] = original[offset];
        }
    }
}

#[test]
fn words_set_to_extreme_values() {
    for name in FIXTURES {
        let original = fixture(name);
        let mut bytes = original.clone();
        for offset in (0..bytes.len().saturating_sub(8).min(2048)).step_by(2 * stride(&bytes)) {
            for (width, value) in [(4, 0xffu8), (8, 0xff), (4, 0x7f)] {
                bytes[offset..offset + width].fill(value);
                check(name, &bytes);
                bytes[offset..offset + width].copy_from_slice(&original[offset..offset + width]);
            }
        }
    }
}

#[test]
fn random_corruption_anywhere() {
    let mut random = Lcg(0x5eed);
    for name in FIXTURES {
        let original = fixture(name);
        for _ in 0..(1200 / stride(&original)) {
            let mut bytes = original.clone();
            for _ in 0..=(random.next() % 6) {
                let offset = (random.next() as usize) % bytes.len();
                bytes[offset] = random.next() as u8;
            }
            if random.next().is_multiple_of(4) {
                bytes.truncate((random.next() as usize) % bytes.len());
            }
            check(name, &bytes);
        }
    }
}

/// Tables in the middle of the file (dynamic section, symbol tables, import and export
/// directories) are reached through offsets a header-only test never corrupts.
#[test]
fn every_region_zeroed_or_filled() {
    for name in FIXTURES {
        let original = fixture(name);
        let window = (original.len() / 64).max(16);
        for start in (0..original.len()).step_by(window) {
            let end = (start + window).min(original.len());
            for value in [0x00u8, 0xff, 0x41] {
                let mut bytes = original.clone();
                bytes[start..end].fill(value);
                check(name, &bytes);
            }
        }
    }
}

/// The same corruptions applied to real-world files named in `AA_BINARY_SAMPLES`.
#[test]
#[ignore = "needs sample files outside the repository"]
fn corrupted_samples() {
    let Ok(list) = std::env::var("AA_BINARY_SAMPLES") else { return };
    let mut random = Lcg(0xfeed);
    for path in list.split(':').filter(|p| !p.is_empty()) {
        let original = std::fs::read(path).expect("readable file");
        if original.len() < 64 {
            continue;
        }
        for round in 0..400 {
            let mut bytes = original.clone();
            // Half the rounds aim at the headers, where every byte steers the parser.
            let span = if round % 2 == 0 { bytes.len().min(4096) } else { bytes.len() };
            for _ in 0..=(random.next() % 8) {
                let offset = (random.next() as usize) % span;
                let width = [1, 2, 4, 8][(random.next() % 4) as usize].min(bytes.len() - offset);
                let value = [0x00, 0xff, random.next() as u8][(random.next() % 3) as usize];
                bytes[offset..offset + width].fill(value);
            }
            if random.next().is_multiple_of(5) {
                bytes.truncate((random.next() as usize) % bytes.len());
            }
            check(path, &bytes);
        }
        println!("{path}: survived");
    }
}
