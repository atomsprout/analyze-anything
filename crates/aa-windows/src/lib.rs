//! Windows: signatures, .NET, installers and Electron apps.

use aa_core::plugin::{Analyzer, Unpacker};

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    Vec::new()
}

/// The unpackers this crate provides, most specific first.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    Vec::new()
}
