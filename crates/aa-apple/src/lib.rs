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
    let mut unpackers = container_unpackers();
    unpackers.extend(payload_unpackers());
    unpackers
}

/// Specific Apple containers keep precedence over generic archive signatures.
pub fn container_unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(unpack::Dmg), Box::new(unpack::XarArchive)]
}

/// Legacy CPIO and pbzx remain fallbacks after shared streams and SVR4 CPIO readers.
pub fn payload_unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(unpack::Payload)]
}
