//! A small DER/BER reader for certificates and PKCS #7 signatures.
//!
//! It accepts what real signing tools emit, including BER indefinite lengths in old `.RSA`
//! files, and nothing here trusts a length: every slice is checked against the data it is cut from.

/// One tag-length-value item.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The contents, without tag and length (and without the end marker of an indefinite length).
    pub value: &'a [u8],
    /// The whole item as encoded.
    pub raw: &'a [u8],
}

pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
const MAX_DEPTH: usize = 32;

/// Reads the item at the start of `data`. Returns it and the bytes after it.
pub fn read(data: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    read_depth(data, 0)
}

fn read_depth(data: &[u8], depth: usize) -> Option<(Tlv<'_>, &[u8])> {
    let tag = *data.first()?;
    if tag & 0x1f == 0x1f {
        return None; // multi-byte tags do not occur in the structures read here
    }
    let first = *data.get(1)?;
    let (header, length) = if first < 0x80 {
        (2usize, Some(usize::from(first)))
    } else if first == 0x80 {
        (2, None)
    } else {
        let count = usize::from(first & 0x7f);
        if count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        let mut length = 0usize;
        for b in bytes {
            length = (length << 8) | usize::from(*b);
        }
        (2 + count, Some(length))
    };
    match length {
        Some(length) => {
            let end = header.checked_add(length)?;
            let raw = data.get(..end)?;
            Some((Tlv { tag, value: &raw[header..], raw }, &data[end..]))
        }
        None => {
            // Indefinite length: only valid for constructed items; ends at a 00 00 marker.
            if tag & 0x20 == 0 || depth >= MAX_DEPTH {
                return None;
            }
            let mut rest = data.get(header..)?;
            loop {
                if rest.starts_with(&[0, 0]) {
                    let consumed = data.len() - rest.len();
                    return Some((Tlv { tag, value: &data[header..consumed], raw: &data[..consumed + 2] }, &rest[2..]));
                }
                let (_, after) = read_depth(rest, depth + 1)?;
                rest = after;
            }
        }
    }
}

/// Iterates the items inside a constructed value.
pub struct Items<'a> {
    rest: &'a [u8],
}

pub fn items(value: &[u8]) -> Items<'_> {
    Items { rest: value }
}

impl<'a> Iterator for Items<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Tlv<'a>> {
        if self.rest.is_empty() {
            return None;
        }
        match read(self.rest) {
            Some((tlv, rest)) => {
                self.rest = rest;
                Some(tlv)
            }
            None => {
                self.rest = &[];
                None
            }
        }
    }
}

/// An object identifier in dotted form.
pub fn oid_string(value: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut current = 0u64;
    for (i, byte) in value.iter().take(64).enumerate() {
        current = (current << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            if parts.is_empty() && i < 10 {
                let first = (current / 40).min(2);
                parts.push(first);
                parts.push(current - first * 40);
            } else {
                parts.push(current);
            }
            current = 0;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// The magnitude bytes of an INTEGER, without a leading zero.
pub fn unsigned(value: &[u8]) -> &[u8] {
    let mut v = value;
    while v.len() > 1 && v[0] == 0 {
        v = &v[1..];
    }
    v
}

/// Number of significant bits in a big-endian magnitude.
pub fn bit_len(magnitude: &[u8]) -> usize {
    let m = unsigned(magnitude);
    match m.first() {
        Some(first) if *first != 0 => (m.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn definite_and_long_lengths() {
        let (tlv, rest) = read(&[0x30, 0x03, 0x02, 0x01, 0x05, 0xff]).expect("tlv");
        assert_eq!(tlv.tag, SEQUENCE);
        assert_eq!(tlv.value, &[0x02, 0x01, 0x05]);
        assert_eq!(rest, &[0xff]);
        let mut long = vec![0x04, 0x82, 0x01, 0x00];
        long.extend(vec![7u8; 256]);
        assert_eq!(read(&long).expect("tlv").0.value.len(), 256);
        assert!(read(&long[..100]).is_none());
        assert!(read(&[0x04, 0x85, 1, 1, 1, 1, 1]).is_none());
    }

    #[test]
    fn indefinite_length() {
        let data = [0x30, 0x80, 0x02, 0x01, 0x05, 0x30, 0x80, 0x00, 0x00, 0x00, 0x00, 0xaa];
        let (tlv, rest) = read(&data).expect("tlv");
        assert_eq!(items(tlv.value).count(), 2);
        assert_eq!(rest, &[0xaa]);
        // Unterminated, and nested too deep.
        assert!(read(&[0x30, 0x80, 0x02, 0x01, 0x05]).is_none());
        let deep: Vec<u8> = std::iter::repeat_n([0x30u8, 0x80], 100).flatten().collect();
        assert!(read(&deep).is_none());
    }

    #[test]
    fn oids_and_integers() {
        assert_eq!(oid_string(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]), "1.2.840.113549.1.1.11");
        assert_eq!(oid_string(&[0x55, 0x04, 0x03]), "2.5.4.3");
        assert_eq!(bit_len(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bit_len(&[0x00]), 0);
        assert_eq!(unsigned(&[0, 0, 1]), &[1]);
    }
}
