//! Linux packages and their declared contents, without installation or script evaluation.

mod ar;
mod arch;
mod cpio;
mod deb;
mod declarations;
mod flatpak;
mod rpm;

use aa_core::plugin::{Analyzer, Unpacker};

const MAX_ENTRIES: usize = 100_000;
const MAX_METADATA: usize = 16 * 1024 * 1024;
type Result<T> = std::result::Result<T, String>;

fn extent(bytes: &[u8], start: usize, size: usize) -> Result<&[u8]> {
    let end = start.checked_add(size).ok_or("package range overflow")?;
    bytes.get(start..end).ok_or_else(|| "package range exceeds the input".into())
}

fn align(value: usize, alignment: usize) -> Result<usize> {
    value.checked_add(alignment - 1).map(|value| value & !(alignment - 1)).ok_or_else(|| "package alignment overflow".into())
}

fn number(bytes: &[u8], radix: u32) -> Result<u32> {
    let text = std::str::from_utf8(bytes).map_err(|_| "package integer is not ASCII")?;
    u32::from_str_radix(text, radix).map_err(|_| "invalid package integer".into())
}

/// Package containers precede generic archives; compressed payloads use the shared engine.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(flatpak::Flatpak), Box::new(flatpak::Part), Box::new(deb::Deb), Box::new(rpm::Rpm), Box::new(ar::Ar), Box::new(cpio::Cpio)]
}

/// Ordered metadata declarations and installation scripts remain source data.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![
        Box::new(deb::Deb),
        Box::new(rpm::Rpm),
        Box::new(ar::Ar),
        Box::new(arch::Arch),
        Box::new(cpio::Cpio),
        Box::new(declarations::Declarations),
        Box::new(flatpak::Flatpak),
    ]
}
