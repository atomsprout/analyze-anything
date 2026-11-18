//! A minimal protobuf wire-format reader, enough for the manifest and resource table of an app
//! bundle. Messages are walked field by field; nothing is allocated from a length in the input.

/// One field of a message.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Field<'a> {
    Varint(u64),
    Fixed64(u64),
    Bytes(&'a [u8]),
    Fixed32(u32),
}

impl<'a> Field<'a> {
    pub fn bytes(self) -> Option<&'a [u8]> {
        match self {
            Field::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn string(self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn varint(self) -> Option<u64> {
        match self {
            Field::Varint(v) => Some(v),
            _ => None,
        }
    }
}

/// Iterates the fields of one message. Stops at the first malformed field.
pub struct Fields<'a> {
    data: &'a [u8],
    pos: usize,
    /// Set when iteration stopped because the bytes were not valid wire format.
    pub malformed: bool,
}

pub fn fields(data: &[u8]) -> Fields<'_> {
    Fields { data, pos: 0, malformed: false }
}

impl<'a> Fields<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut result = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.data.get(self.pos)?;
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(result);
            }
        }
        None
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let slice = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn field(&mut self) -> Option<(u32, Field<'a>)> {
        let key = self.varint()?;
        let number = u32::try_from(key >> 3).ok().filter(|n| *n != 0)?;
        let field = match key & 7 {
            0 => Field::Varint(self.varint()?),
            1 => Field::Fixed64(u64::from_le_bytes(self.take(8)?.try_into().ok()?)),
            2 => {
                let len = usize::try_from(self.varint()?).ok()?;
                Field::Bytes(self.take(len)?)
            }
            5 => Field::Fixed32(u32::from_le_bytes(self.take(4)?.try_into().ok()?)),
            _ => return None,
        };
        Some((number, field))
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = (u32, Field<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.malformed || self.pos >= self.data.len() {
            return None;
        }
        let field = self.field();
        if field.is_none() {
            self.malformed = true;
        }
        field
    }
}

/// The first field numbered `number`.
pub fn first(data: &[u8], number: u32) -> Option<Field<'_>> {
    fields(data).find(|(n, _)| *n == number).map(|(_, f)| f)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    pub fn bytes_field(number: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint(u64::from(number) << 3 | 2, &mut out);
        varint(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    pub fn varint_field(number: u32, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        varint(u64::from(number) << 3, &mut out);
        varint(value, &mut out);
        out
    }

    #[test]
    fn reads_fields_of_each_wire_type() {
        let mut message = varint_field(1, 300);
        message.extend(bytes_field(2, b"hello"));
        message.extend([0x1d, 1, 0, 0, 0]); // field 3, fixed32
        let all: Vec<_> = fields(&message).collect();
        assert_eq!(all, vec![(1, Field::Varint(300)), (2, Field::Bytes(b"hello")), (3, Field::Fixed32(1))]);
        assert_eq!(first(&message, 2).and_then(Field::string).as_deref(), Some("hello"));
    }

    #[test]
    fn malformed_input_stops_cleanly() {
        // Length runs past the end.
        let mut it = fields(&[0x12, 0xff, 0xff, 0xff, 0x7f, 1]);
        assert!(it.next().is_none());
        assert!(it.malformed);
        // Endless varint.
        let mut it = fields(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert!(it.next().is_none());
        assert!(it.malformed);
        // Field number zero and unsupported wire types.
        assert!(fields(&[0x00, 0x00]).next().is_none());
        assert!(fields(&[0x0b]).next().is_none());
        for cut in 0..8 {
            let message = bytes_field(1, b"abcdef");
            let _ = fields(&message[..cut]).count();
        }
    }
}
