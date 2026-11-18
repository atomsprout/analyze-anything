//! The string pool chunk shared by binary XML and resource tables.

use crate::reader::{slice_at, u16_at, u32_at};

pub const CHUNK_STRING_POOL: u16 = 0x0001;
const FLAG_UTF8: u32 = 0x100;
/// Longest string decoded; anything longer is cut. Real pools hold short strings.
const MAX_STRING_BYTES: usize = 1 << 20;

/// A parsed pool header; strings are decoded on demand.
pub struct StringPool<'a> {
    chunk: &'a [u8],
    utf8: bool,
    /// Offset of the offsets array inside the chunk.
    offsets_at: usize,
    count: usize,
    strings_start: usize,
    /// Things about the header that a well-formed file would not have.
    pub anomalies: Vec<&'static str>,
}

impl<'a> StringPool<'a> {
    /// Parses the pool whose chunk (header included) is `chunk`.
    pub fn parse(chunk: &'a [u8]) -> Option<Self> {
        let header_size = usize::from(u16_at(chunk, 2)?);
        let declared = u32_at(chunk, 8)? as usize;
        let flags = u32_at(chunk, 16)?;
        let strings_start = u32_at(chunk, 20)? as usize;
        let mut anomalies = Vec::new();
        if header_size < 28 || header_size > chunk.len() {
            return None;
        }
        if flags & !(FLAG_UTF8 | 1) != 0 {
            anomalies.push("string pool has unknown flag bits");
        }
        // The offsets array lies between the header and the string data, whatever the count says.
        let room_end = if strings_start >= header_size && strings_start <= chunk.len() { strings_start } else { chunk.len() };
        let room = (room_end - header_size) / 4;
        let count = declared.min(room);
        if declared > room {
            anomalies.push("string pool declares more strings than it has room for");
        }
        if strings_start < header_size || strings_start > chunk.len() {
            anomalies.push("string pool data offset is outside the chunk");
        }
        Some(StringPool { chunk, utf8: flags & FLAG_UTF8 != 0, offsets_at: header_size, count, strings_start, anomalies })
    }

    /// Number of strings in the pool.
    pub fn count(&self) -> usize {
        self.count
    }

    /// The string at `index`, or `None` when the index or its data is out of range.
    pub fn get(&self, index: u32) -> Option<String> {
        let index = index as usize;
        if index >= self.count {
            return None;
        }
        let offset = u32_at(self.chunk, self.offsets_at.checked_add(index.checked_mul(4)?)?)? as usize;
        let at = self.strings_start.checked_add(offset)?;
        if self.utf8 { self.utf8_at(at) } else { self.utf16_at(at) }
    }

    fn utf8_at(&self, at: usize) -> Option<String> {
        let data = self.chunk;
        // Two lengths, each one or two bytes: the length in UTF-16 units, then in bytes.
        let mut pos = at;
        let mut length = 0usize;
        for _ in 0..2 {
            let first = usize::from(*data.get(pos)?);
            pos += 1;
            length = if first & 0x80 != 0 {
                let second = usize::from(*data.get(pos)?);
                pos += 1;
                ((first & 0x7f) << 8) | second
            } else {
                first
            };
        }
        let rest = data.get(pos..)?;
        // A wrong byte length is a known trick: fall back to the terminator.
        let bytes = match rest.get(length) {
            Some(0) => &rest[..length],
            _ => {
                let limit = rest.len().min(MAX_STRING_BYTES);
                let end = rest[..limit].iter().position(|b| *b == 0).unwrap_or(limit);
                &rest[..end]
            }
        };
        Some(decode_mutf8(&bytes[..bytes.len().min(MAX_STRING_BYTES)]))
    }

    fn utf16_at(&self, at: usize) -> Option<String> {
        let data = self.chunk;
        let mut pos = at;
        let mut length = usize::from(u16_at(data, pos)?);
        pos += 2;
        if length & 0x8000 != 0 {
            length = ((length & 0x7fff) << 16) | usize::from(u16_at(data, pos)?);
            pos += 2;
        }
        let available = data.len().saturating_sub(pos) / 2;
        let length = length.min(available).min(MAX_STRING_BYTES / 2);
        let raw = slice_at(data, pos, length * 2)?;
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        Some(String::from_utf16_lossy(&units))
    }
}

/// Decodes Java's modified UTF-8 (surrogates as two three-byte sequences, NUL as `C0 80`),
/// replacing what cannot be decoded.
pub fn decode_mutf8(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let cont = |k: usize| bytes.get(i + k).filter(|c| **c & 0xc0 == 0x80).map(|c| u32::from(*c & 0x3f));
        if b < 0x80 {
            units.push(u16::from(b));
            i += 1;
        } else if b & 0xe0 == 0xc0
            && let Some(c1) = cont(1)
        {
            units.push(((u32::from(b & 0x1f) << 6) | c1) as u16);
            i += 2;
        } else if b & 0xf0 == 0xe0
            && let (Some(c1), Some(c2)) = (cont(1), cont(2))
        {
            units.push(((u32::from(b & 0x0f) << 12) | (c1 << 6) | c2) as u16);
            i += 3;
        } else if b & 0xf8 == 0xf0
            && let (Some(c1), Some(c2), Some(c3)) = (cont(1), cont(2), cont(3))
        {
            let scalar = (u32::from(b & 0x07) << 18) | (c1 << 12) | (c2 << 6) | c3;
            match char::from_u32(scalar) {
                Some(ch) => {
                    let mut buffer = [0u16; 2];
                    units.extend_from_slice(ch.encode_utf16(&mut buffer));
                }
                None => units.push(0xfffd),
            }
            i += 4;
        } else {
            units.push(0xfffd);
            i += 1;
        }
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Builds a pool chunk from `strings`.
    pub fn build_pool(strings: &[&str], utf8: bool) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offsets = Vec::new();
        for s in strings {
            offsets.push(data.len() as u32);
            if utf8 {
                data.push(s.chars().count() as u8);
                data.push(s.len() as u8);
                data.extend_from_slice(s.as_bytes());
                data.push(0);
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                data.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for u in units {
                    data.extend_from_slice(&u.to_le_bytes());
                }
                data.extend_from_slice(&[0, 0]);
            }
        }
        while data.len() % 4 != 0 {
            data.push(0);
        }
        let strings_start = 28 + 4 * strings.len();
        let mut chunk = Vec::new();
        chunk.extend_from_slice(&CHUNK_STRING_POOL.to_le_bytes());
        chunk.extend_from_slice(&28u16.to_le_bytes());
        chunk.extend_from_slice(&((strings_start + data.len()) as u32).to_le_bytes());
        chunk.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        chunk.extend_from_slice(&(if utf8 { FLAG_UTF8 } else { 0 }).to_le_bytes());
        chunk.extend_from_slice(&(strings_start as u32).to_le_bytes());
        chunk.extend_from_slice(&0u32.to_le_bytes());
        for o in offsets {
            chunk.extend_from_slice(&o.to_le_bytes());
        }
        chunk.extend_from_slice(&data);
        chunk
    }

    #[test]
    fn decodes_both_encodings() {
        for utf8 in [true, false] {
            let chunk = build_pool(&["manifest", "应用", ""], utf8);
            let pool = StringPool::parse(&chunk).expect("pool");
            assert_eq!(pool.count(), 3);
            assert_eq!(pool.get(0).as_deref(), Some("manifest"));
            assert_eq!(pool.get(1).as_deref(), Some("应用"));
            assert_eq!(pool.get(2).as_deref(), Some(""));
            assert_eq!(pool.get(3), None);
            assert!(pool.anomalies.is_empty());
        }
    }

    #[test]
    fn inflated_count_is_clamped() {
        let mut chunk = build_pool(&["a", "b"], true);
        chunk[8..12].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let pool = StringPool::parse(&chunk).expect("pool");
        assert_eq!(pool.count(), 2);
        assert_eq!(pool.get(1).as_deref(), Some("b"));
        assert!(!pool.anomalies.is_empty());
    }

    #[test]
    fn wrong_utf8_length_falls_back_to_the_terminator() {
        let mut chunk = build_pool(&["name"], true);
        let at = 28 + 4;
        chunk[at + 1] = 2; // byte length says 2, the data is 4 bytes and a NUL
        let pool = StringPool::parse(&chunk).expect("pool");
        assert_eq!(pool.get(0).as_deref(), Some("name"));
    }

    #[test]
    fn truncations_and_garbage_do_not_panic() {
        let chunk = build_pool(&["manifest", "package", "应用"], false);
        for cut in 0..chunk.len() {
            if let Some(pool) = StringPool::parse(&chunk[..cut]) {
                for i in 0..5 {
                    let _ = pool.get(i);
                }
            }
        }
        let mut bad = chunk.clone();
        bad[20..24].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        let pool = StringPool::parse(&bad).expect("pool");
        assert_eq!(pool.get(0), None);
        let mut bad = chunk;
        bad[28..32].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        assert_eq!(StringPool::parse(&bad).expect("pool").get(0), None);
    }

    #[test]
    fn mutf8_surrogate_pairs_and_bad_bytes() {
        // U+1F600 as a CESU-8 surrogate pair.
        assert_eq!(decode_mutf8(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80]), "\u{1F600}");
        assert_eq!(decode_mutf8(&[0xc0, 0x80]), "\0");
        assert_eq!(decode_mutf8(&[b'a', 0xff, b'b']), "a\u{fffd}b");
    }
}
