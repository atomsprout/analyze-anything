//! Native executables: PE, Mach-O and ELF.

use aa_core::plugin::Analyzer;

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    Vec::new()
}
