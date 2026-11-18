//! Unpackers for general-purpose archives: ZIP, TAR, 7z, and single compressed streams.
//!
//! Every size limit is enforced by the engine's sink, so these only translate each format's
//! entries into `sink.add` calls and report what they could not open.

mod sevenz;
mod stream;
mod tar;
mod zip;

use aa_core::plugin::Unpacker;

/// The unpackers this crate provides, most specific first.
pub fn unpackers() -> Vec<Box<dyn Unpacker>> {
    vec![Box::new(zip::Zip), Box::new(sevenz::SevenZ), Box::new(tar::Tar), Box::new(stream::Stream)]
}
