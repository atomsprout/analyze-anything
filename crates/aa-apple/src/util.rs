//! Bounds-checked readers for untrusted bytes. Every accessor returns `None` past the end.

pub fn slice(bytes: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(length)?)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    slice(bytes, offset, N)?.try_into().ok()
}

pub fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    array(bytes, offset).map(u16::from_be_bytes)
}

pub fn be32(bytes: &[u8], offset: usize) -> Option<u32> {
    array(bytes, offset).map(u32::from_be_bytes)
}

pub fn be64(bytes: &[u8], offset: usize) -> Option<u64> {
    array(bytes, offset).map(u64::from_be_bytes)
}

pub fn le16(bytes: &[u8], offset: usize) -> Option<u16> {
    array(bytes, offset).map(u16::from_le_bytes)
}

pub fn le32(bytes: &[u8], offset: usize) -> Option<u32> {
    array(bytes, offset).map(u32::from_le_bytes)
}

pub fn le64(bytes: &[u8], offset: usize) -> Option<u64> {
    array(bytes, offset).map(u64::from_le_bytes)
}

/// A 32-bit value in the byte order `big` selects.
pub fn u32_at(bytes: &[u8], offset: usize, big: bool) -> Option<u32> {
    if big { be32(bytes, offset) } else { le32(bytes, offset) }
}

/// A 64-bit value in the byte order `big` selects.
pub fn u64_at(bytes: &[u8], offset: usize, big: bool) -> Option<u64> {
    if big { be64(bytes, offset) } else { le64(bytes, offset) }
}

/// The text before the first NUL of a fixed-size field.
pub fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_refuse_out_of_range() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(be16(&bytes, 0), Some(0x0102));
        assert_eq!(le32(&bytes, 4), Some(0x0807_0605));
        assert_eq!(be64(&bytes, 0), Some(0x0102_0304_0506_0708));
        assert_eq!(be32(&bytes, 5), None);
        assert_eq!(le64(&bytes, 1), None);
        assert_eq!(slice(&bytes, usize::MAX, 2), None);
        assert_eq!(c_string(b"ab\0cd"), "ab");
    }
}
