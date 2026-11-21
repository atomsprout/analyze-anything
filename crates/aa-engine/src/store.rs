//! Where an artifact's bytes are kept: the input on disk, a temporary file, or memory.

use std::io::Read;
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
                let file = crate::disk::open(path)?;
                let length = file.metadata()?.len();
                if length < READ_WHOLE_BELOW {
                    // Read from the checked handle, not a second path lookup. A growing file
                    // cannot make this small-file path allocate beyond its bounded snapshot.
                    let mut bytes = Vec::new();
                    file.take(length + 1).read_to_end(&mut bytes)?;
                    if bytes.len() as u64 != length {
                        return Err(std::io::Error::other("file length changed while it was read"));
                    }
                    return Ok(Bytes::from_vec(bytes));
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
