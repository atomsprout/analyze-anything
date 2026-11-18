//! Single compressed streams: gzip, bzip2, xz and Zstandard. Each yields one child, the
//! decompressed data, which the engine then examines in turn (so a `.tar.gz` opens fully).

use std::io::Read;

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};

pub struct Stream;

/// The child's name: the container's name without its compression suffix.
fn inner_name(file: &Artifact, suffixes: &[(&str, &str)]) -> String {
    let name = file.name();
    let lower = name.to_ascii_lowercase();
    for (suffix, replacement) in suffixes {
        if lower.ends_with(suffix) && name.len() > suffix.len() {
            return format!("{}{replacement}", &name[..name.len() - suffix.len()]);
        }
    }
    "content".to_string()
}

impl Unpacker for Stream {
    fn id(&self) -> &'static str {
        "stream"
    }

    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let (kind, name, mut reader): (&'static str, String, Box<dyn Read + '_>) = if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
            ("gzip", inner_name(file, &[(".tgz", ".tar"), (".gz", "")]), Box::new(flate2::read::MultiGzDecoder::new(bytes)))
        } else if bytes.starts_with(b"BZh") && bytes.get(3).is_some_and(u8::is_ascii_digit) {
            (
                "bzip2",
                inner_name(file, &[(".tbz2", ".tar"), (".tbz", ".tar"), (".bz2", "")]),
                Box::new(bzip2::read::MultiBzDecoder::new(bytes)),
            )
        } else if bytes.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            ("xz", inner_name(file, &[(".txz", ".tar"), (".xz", "")]), Box::new(lzma_rust2::XzReader::new(bytes, true)))
        } else if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            match ruzstd::decoding::StreamingDecoder::new(bytes) {
                Ok(decoder) => ("zstd", inner_name(file, &[(".tzst", ".tar"), (".zst", "")]), Box::new(decoder)),
                Err(error) => return Unpack::Failed { kind: "zstd", detail: error.to_string() },
            }
        } else {
            return Unpack::NotMine;
        };
        match sink.add(&name, &mut reader) {
            Ok(()) | Err(SinkError::LimitReached) => Unpack::Done { kind },
            Err(SinkError::Read(detail)) => Unpack::Failed { kind, detail },
        }
    }
}
