//! Where an artifact's bytes are kept: the input on disk, a temporary file, or memory.

use std::path::PathBuf;
use std::sync::Arc;

use aa_core::plugin::Bytes;

/// Files up to this size are read into memory; larger ones are mapped.
const READ_WHOLE_BELOW: u64 = 16 * 1024 * 1024;

#[derive(Clone)]
pub enum Store {
    /// A file of the input, or a spilled child in the run's temporary folder.
    Disk(PathBuf),
    Memory(Arc<Vec<u8>>),
}

struct Mapped(memmap2::Mmap);

impl AsRef<[u8]> for Mapped {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Store {
    pub fn read(&self) -> std::io::Result<Bytes> {
        match self {
            Store::Memory(bytes) => Ok(Bytes::new(bytes.clone())),
            Store::Disk(path) => {
                let file = std::fs::File::open(path)?;
                if file.metadata()?.len() < READ_WHOLE_BELOW {
                    return Ok(Bytes::from_vec(std::fs::read(path)?));
                }
                // SAFETY: the mapping is read-only and private to this process. The engine never
                // writes to an input file, and spilled children are written once before they are
                // mapped. A file another program truncates while it is mapped can still fault;
                // that is the accepted cost of not holding multi-gigabyte inputs in memory.
                #[allow(unsafe_code)]
                let map = unsafe { memmap2::Mmap::map(&file)? };
                Ok(Bytes::new(Arc::new(Mapped(map))))
            }
        }
    }
}
