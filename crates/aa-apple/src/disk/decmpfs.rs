//! Transparent file compression (`com.apple.decmpfs`), used by both HFS+ and APFS: the file's
//! data fork is empty and its content lives, compressed, in an extended attribute or in the
//! resource fork.

use std::io::Read;

use crate::util::{be32, le32, le64, slice};

/// Size of the attribute's header.
pub const HEADER: usize = 16;
/// Compressed files are stored in blocks of this many bytes.
const BLOCK: usize = 65536;
/// Largest compressed file this crate expands in memory.
pub const MAX_SIZE: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u32,
    pub size: u64,
}

impl Header {
    /// True when the content is in the resource fork, not in the attribute.
    pub fn in_resource_fork(&self) -> bool {
        matches!(self.kind, 4 | 8 | 10 | 12)
    }
}

pub fn header(attribute: &[u8]) -> Option<Header> {
    if slice(attribute, 0, 4)? != b"fpmc" {
        return None;
    }
    Some(Header { kind: le32(attribute, 4)?, size: le64(attribute, 8)? })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Codec {
    Zlib,
    Lzvn,
    Lzfse,
    Plain,
}

fn inflate(source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(source).take(limit as u64).read_to_end(&mut out).map_err(|e| format!("zlib: {e}"))?;
    Ok(out)
}

fn lzfse(source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut decoder = lzfse_rust::LzfseRingDecoder::default();
    decoder.reader_bytes(source).take(limit as u64).read_to_end(&mut out).map_err(|e| format!("lzfse: {e}"))?;
    Ok(out)
}

/// Decodes a bare LZVN stream of known decoded size by presenting it as the LZVN block of an
/// LZFSE stream, which is the same payload behind a 12-byte header.
fn lzvn(source: &[u8], expected: usize) -> Result<Vec<u8>, String> {
    let (Ok(raw), Ok(payload)) = (u32::try_from(expected), u32::try_from(source.len())) else {
        return Err("lzvn: block too large".into());
    };
    let mut wrapped = Vec::with_capacity(source.len() + 16);
    wrapped.extend_from_slice(b"bvxn");
    wrapped.extend_from_slice(&raw.to_le_bytes());
    wrapped.extend_from_slice(&payload.to_le_bytes());
    wrapped.extend_from_slice(source);
    wrapped.extend_from_slice(b"bvx$");
    lzfse(&wrapped, expected).map_err(|e| e.replace("lzfse", "lzvn"))
}

/// Expands one stored block that decodes to `expected` bytes.
fn block(codec: Codec, source: &[u8], expected: usize) -> Result<Vec<u8>, String> {
    let first = *source.first().ok_or("an empty compressed block")?;
    let out = match codec {
        // A low nibble of 0xF cannot start a zlib stream: the rest is stored as it is.
        Codec::Zlib if first & 0x0f == 0x0f => source[1..].to_vec(),
        Codec::Zlib => inflate(source, expected)?,
        // 0x06 is LZVN's end-of-stream opcode: the rest is stored as it is.
        Codec::Lzvn if first == 0x06 => source[1..].to_vec(),
        Codec::Lzvn => lzvn(source, expected)?,
        Codec::Lzfse if first == 0xff => source[1..].to_vec(),
        Codec::Lzfse => lzfse(source, expected)?,
        Codec::Plain if first == 0xcc || first == 0xff => source[1..].to_vec(),
        Codec::Plain => source.to_vec(),
    };
    if out.len() != expected {
        return Err(format!("a block decoded to {} bytes instead of {expected}", out.len()));
    }
    Ok(out)
}

/// Expands a compressed file. `attribute` is the whole `com.apple.decmpfs` value; `resource`
/// reads the resource fork and is only called for the types that keep their data there.
pub fn expand(attribute: &[u8], resource: impl FnOnce() -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
    let header = header(attribute).ok_or("the decmpfs attribute has no valid header")?;
    if header.size > MAX_SIZE {
        return Err(format!("the compressed file claims {} bytes", header.size));
    }
    let size = header.size as usize;
    let inline = &attribute[HEADER..];
    let codec = match header.kind {
        1 => return slice(inline, 0, size).map(<[u8]>::to_vec).ok_or_else(|| "inline data is shorter than the file size".to_string()),
        3 | 4 => Codec::Zlib,
        7 | 8 => Codec::Lzvn,
        9 | 10 => Codec::Plain,
        11 | 12 => Codec::Lzfse,
        other => return Err(format!("decmpfs compression type {other} is not supported")),
    };
    if size == 0 {
        return Ok(Vec::new());
    }
    if !header.in_resource_fork() {
        return block(codec, inline, size);
    }
    let fork = resource()?;
    // Byte ranges of the blocks in the fork.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let blocks = size.div_ceil(BLOCK);
    if codec == Codec::Zlib {
        // A classic resource fork: the table sits behind a 4-byte length at the data offset.
        let data = be32(&fork, 0).ok_or("the resource fork is truncated")? as usize;
        let base = data.checked_add(4).ok_or("offset overflow")?;
        let count = le32(&fork, base).ok_or("the resource fork is truncated")? as usize;
        if count != blocks {
            return Err(format!("the resource fork lists {count} blocks, the file size needs {blocks}"));
        }
        for index in 0..count {
            let entry = base + 4 + index * 8;
            let offset = le32(&fork, entry).ok_or("the block table is truncated")? as usize;
            let length = le32(&fork, entry + 4).ok_or("the block table is truncated")? as usize;
            ranges.push((base.checked_add(offset).ok_or("offset overflow")?, length));
        }
    } else {
        // A list of block start offsets, one more than there are blocks.
        for index in 0..blocks {
            let start = le32(&fork, index * 4).ok_or("the block table is truncated")? as usize;
            let end = le32(&fork, index * 4 + 4).ok_or("the block table is truncated")? as usize;
            ranges.push((start, end.checked_sub(start).ok_or("block offsets are not ascending")?));
        }
    }
    let mut out = Vec::with_capacity(size.min(64 * 1024 * 1024));
    for (index, (offset, length)) in ranges.into_iter().enumerate() {
        let source = slice(&fork, offset, length).ok_or("a block lies outside the resource fork")?;
        let expected = (size - index * BLOCK).min(BLOCK);
        out.extend_from_slice(&block(codec, source, expected)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn attribute(kind: u32, size: u64, inline: &[u8]) -> Vec<u8> {
        let mut out = b"fpmc".to_vec();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(inline);
        out
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).expect("write");
        encoder.finish().expect("finish")
    }

    fn no_fork() -> Result<Vec<u8>, String> {
        Err("no resource fork".into())
    }

    #[test]
    fn inline_types() {
        assert_eq!(expand(&attribute(1, 3, b"abc"), no_fork).expect("plain"), b"abc");
        assert_eq!(expand(&attribute(3, 5, &deflate(b"hello")), no_fork).expect("zlib"), b"hello");
        assert_eq!(expand(&attribute(3, 2, &[0xff, b'h', b'i']), no_fork).expect("stored"), b"hi");
        assert_eq!(expand(&attribute(7, 2, &[0x06, b'h', b'i']), no_fork).expect("stored lzvn"), b"hi");
        assert_eq!(expand(&attribute(3, 0, &[]), no_fork).expect("empty"), b"");
    }

    #[test]
    fn zlib_resource_fork_with_two_blocks() {
        let content: Vec<u8> = (0..BLOCK + 100).map(|i| (i % 251) as u8).collect();
        let (first, second) = (deflate(&content[..BLOCK]), deflate(&content[BLOCK..]));
        let mut fork = vec![0u8; 0x100];
        fork[..4].copy_from_slice(&0x100u32.to_be_bytes());
        fork.extend_from_slice(&0u32.to_be_bytes());
        fork.extend_from_slice(&2u32.to_le_bytes());
        let table = 4 + 16;
        fork.extend_from_slice(&(table as u32).to_le_bytes());
        fork.extend_from_slice(&(first.len() as u32).to_le_bytes());
        fork.extend_from_slice(&((table + first.len()) as u32).to_le_bytes());
        fork.extend_from_slice(&(second.len() as u32).to_le_bytes());
        fork.extend_from_slice(&first);
        fork.extend_from_slice(&second);
        let attr = attribute(4, content.len() as u64, &[]);
        assert_eq!(expand(&attr, || Ok(fork.clone())).expect("fork"), content);
        for cut in [0, 3, 0x100, 0x108, 0x110, fork.len() - 1] {
            assert!(expand(&attr, || Ok(fork[..cut].to_vec())).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn malformed_attributes_are_errors() {
        assert!(expand(b"", no_fork).is_err());
        assert!(expand(b"fpmc", no_fork).is_err());
        assert!(expand(&attribute(3, 10, &[]), no_fork).is_err());
        assert!(expand(&attribute(3, u64::MAX, &[1]), no_fork).is_err());
        assert!(expand(&attribute(99, 1, &[1]), no_fork).is_err());
        assert!(expand(&attribute(1, 10, b"abc"), no_fork).is_err());
        assert!(expand(&attribute(8, 10, &[]), || Ok(vec![0xff; 6])).is_err());
        assert!(expand(&attribute(7, 100, &[0xe0, 1, 2]), no_fork).is_err());
    }
}
