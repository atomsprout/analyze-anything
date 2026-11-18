//! Analysis across the whole tree: what the input is made of, and how its parts relate.

mod structure;

use aa_core::plugin::Analyzer;

/// The analyzers this crate provides. They read what the format analyzers attached, so they
/// are registered after them.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(structure::Structure)]
}
