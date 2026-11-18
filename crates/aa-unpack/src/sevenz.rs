//! 7z archives.

use std::io::Cursor;

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};
use sevenz_rust2::{ArchiveReader, Password};

pub struct SevenZ;

impl Unpacker for SevenZ {
    fn id(&self) -> &'static str {
        "7z"
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c]) {
            return Unpack::NotMine;
        }
        let mut reader = match ArchiveReader::new(Cursor::new(bytes), Password::empty()) {
            Ok(reader) => reader,
            Err(error) => return Unpack::Failed { kind: "7z", detail: error.to_string() },
        };
        let result = reader.for_each_entries(|entry, data| {
            if entry.is_directory() {
                return Ok(true);
            }
            match sink.add(entry.name(), data) {
                Ok(()) | Err(SinkError::Read(_)) => Ok(true),
                Err(SinkError::LimitReached) => Ok(false),
            }
        });
        match result {
            Ok(()) => Unpack::Done { kind: "7z" },
            Err(error) => Unpack::Failed { kind: "7z", detail: error.to_string() },
        }
    }
}
