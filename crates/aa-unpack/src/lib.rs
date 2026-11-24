//! Unpackers for general-purpose archives: ZIP, TAR, 7z, and single compressed streams.
//!
//! Every size limit is enforced by the engine's sink, so these only translate each format's
//! entries into `sink.add` calls and report what they could not open.

mod dotnet;
mod inflate;
mod pyinstaller;
mod sevenz;
mod stream;
mod tar;
mod zip;

use aa_core::plugin::{Analyzer, Unpacker};

fn native_host(bytes: &[u8]) -> bool {
    bytes.starts_with(b"MZ")
        || bytes.starts_with(b"\x7fELF")
        || matches!(
            bytes.get(..4),
            Some([0xfe, 0xed, 0xfa, 0xce] | [0xfe, 0xed, 0xfa, 0xcf] | [0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe])
        )
}

/// Executable containers precede generic self-extracting overlays in the engine.
pub fn executable_unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(dotnet::Dotnet), Box::new(pyinstaller::PyInstaller)]
}

/// General archives and compressed streams, most specific first.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(zip::Zip), Box::new(sevenz::SevenZ), Box::new(tar::Tar), Box::new(stream::Stream)]
}

/// Metadata for the executable containers whose members the unpackers expose.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(dotnet::Dotnet), Box::new(pyinstaller::PyInstaller)]
}
