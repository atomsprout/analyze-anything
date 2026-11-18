//! Bounds-checked little-endian reads. Every access returns `None` past the end; nothing panics.

/// A cursor over a byte slice.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    pub fn skip(&mut self, len: usize) -> Option<()> {
        self.bytes(len).map(|_| ())
    }

    pub fn u8(&mut self) -> Option<u8> {
        self.bytes(1).map(|b| b[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        self.bytes(2).map(|b| u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.bytes(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.bytes(8).map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }

    /// A slice prefixed by its length as a little-endian `u32` (APK Signing Block style).
    pub fn lp32(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    /// An unsigned LEB128 number of at most five bytes (DEX style).
    pub fn uleb128(&mut self) -> Option<u32> {
        let mut result = 0u32;
        for shift in [0u32, 7, 14, 21, 28] {
            let byte = self.u8()?;
            result |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
        }
        Some(result)
    }
}

pub fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    let b = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

pub fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let b = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    let b = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// `data[offset..offset + len]`, or `None` when that is out of range.
pub fn slice_at(data: &[u8], offset: usize, len: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(len)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_stop_at_the_end() {
        let mut r = Reader::new(&[1, 0, 0, 0, 5]);
        assert_eq!(r.u32(), Some(1));
        assert_eq!(r.u16(), None);
        assert_eq!(r.u8(), Some(5));
        assert_eq!(r.u8(), None);
        assert_eq!(u32_at(&[1, 2, 3], usize::MAX), None);
        assert_eq!(slice_at(&[1, 2, 3], 2, usize::MAX), None);
    }

    #[test]
    fn length_prefix_cannot_run_past_the_data() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 1, 2]);
        assert!(r.lp32().is_none());
        let mut r = Reader::new(&[2, 0, 0, 0, 1, 2]);
        assert_eq!(r.lp32(), Some(&[1u8, 2][..]));
    }

    #[test]
    fn uleb128_is_bounded() {
        let mut r = Reader::new(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(r.uleb128().is_some());
        assert_eq!(r.pos, 5);
        assert_eq!(Reader::new(&[0xe5, 0x8e, 0x26]).uleb128(), Some(624_485));
    }
}
