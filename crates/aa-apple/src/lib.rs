//! Apple platforms: app bundles, IPA, DMG and installer packages.

mod analyzer;
mod bundle;
mod certs;
mod codesign;
mod disk;
#[cfg(test)]
mod e2e;
mod extras;
mod info;
mod inspect;
mod macho;
mod pkg;
mod rules;
mod signing;
mod tree;
mod unpack;
mod util;

use aa_core::plugin::{Analyzer, Unpacker};

/// The analyzers this crate provides, in the order they should run.
pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(analyzer::Apple)]
}

/// The unpackers this crate provides, most specific first.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(unpack::Dmg), Box::new(unpack::XarArchive), Box::new(unpack::Payload)]
}
