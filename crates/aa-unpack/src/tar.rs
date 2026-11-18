//! TAR archives.

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};

pub struct Tar;

impl Unpacker for Tar {
    fn id(&self) -> &'static str {
        "tar"
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        // Both POSIX and GNU archives carry "ustar" at this offset of the first header.
        if bytes.len() < 512 || &bytes[257..262] != b"ustar" {
            return Unpack::NotMine;
        }
        let mut archive = ::tar::Archive::new(bytes);
        let entries = match archive.entries() {
            Ok(entries) => entries,
            Err(error) => return Unpack::Failed { kind: "tar", detail: error.to_string() },
        };
        for entry in entries {
            let mut entry = match entry {
                Ok(entry) => entry,
                // A damaged header leaves no way to find the next entry.
                Err(error) => return Unpack::Failed { kind: "tar", detail: error.to_string() },
            };
            // Links, devices and folders have no content of their own.
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let name = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            match sink.add(&name, &mut entry) {
                Ok(()) | Err(SinkError::Read(_)) => {}
                Err(SinkError::LimitReached) => break,
            }
        }
        Unpack::Done { kind: "tar" }
    }
}
