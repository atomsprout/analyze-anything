//! A minimal BER/DER reader for the PKCS#7 and X.509 structures of Authenticode.
//!
//! It keeps the raw bytes of every element, because signatures are computed over exact
//! encodings, and it accepts BER indefinite lengths, which some signing tools emit.

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;

/// Nesting allowed while looking for the end of an indefinite-length element.
const MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// The identifier octet: class, constructed bit and tag number.
    pub tag: u8,
    /// The content octets (for indefinite lengths, without the end-of-contents marker).
    pub content: &'a [u8],
    /// Identifier, length and content octets together.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn children(&self) -> Reader<'a> {
        Reader { data: self.content }
    }

    pub fn is_context(&self, number: u8) -> bool {
        self.tag & 0xc0 == 0x80 && self.tag & 0x1f == number
    }

    /// The dotted form of an OBJECT IDENTIFIER.
    pub fn oid(&self) -> Option<String> {
        if self.tag != TAG_OID || self.content.is_empty() || self.content.len() > 64 {
            return None;
        }
        let mut arcs: Vec<u64> = Vec::new();
        let mut value: u64 = 0;
        for &byte in self.content {
            value = value.checked_mul(128)?.checked_add(u64::from(byte & 0x7f))?;
            if byte & 0x80 == 0 {
                if arcs.is_empty() {
                    let first = (value / 40).min(2);
                    arcs.push(first);
                    arcs.push(value - first * 40);
                } else {
                    arcs.push(value);
                }
                value = 0;
            }
        }
        Some(arcs.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
    }

    /// An INTEGER's magnitude bytes without the leading zero that marks it positive.
    pub fn integer_bytes(&self) -> Option<&'a [u8]> {
        if self.tag != TAG_INTEGER {
            return None;
        }
        let mut bytes = self.content;
        while bytes.len() > 1 && bytes[0] == 0 {
            bytes = &bytes[1..];
        }
        Some(bytes)
    }

    /// A small non-negative INTEGER.
    pub fn small_integer(&self) -> Option<u64> {
        let bytes = self.integer_bytes()?;
        if bytes.len() > 8 || self.content.first().is_some_and(|b| b & 0x80 != 0) {
            return None;
        }
        Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// The bytes of a BIT STRING with no unused bits.
    pub fn bit_string(&self) -> Option<&'a [u8]> {
        if self.tag != TAG_BIT_STRING {
            return None;
        }
        match self.content.split_first() {
            Some((0, rest)) => Some(rest),
            _ => None,
        }
    }

    /// The bytes of an OCTET STRING. A constructed one (BER) is joined from its parts.
    pub fn octet_string(&self) -> Option<Vec<u8>> {
        match self.tag {
            TAG_OCTET_STRING => Some(self.content.to_vec()),
            0x24 => {
                let mut joined = Vec::new();
                for part in self.children() {
                    joined.extend_from_slice(&part.ok()?.octet_string()?);
                }
                Some(joined)
            }
            _ => None,
        }
    }

    /// The text of any of the ASN.1 string types.
    pub fn text(&self) -> Option<String> {
        match self.tag {
            // UTF8String, NumericString, PrintableString, IA5String, VisibleString
            0x0c | 0x12 | 0x13 | 0x16 | 0x1a => Some(String::from_utf8_lossy(self.content).into_owned()),
            // TeletexString: read as Latin-1, which is what signers put there in practice.
            0x14 => Some(self.content.iter().map(|&b| b as char).collect()),
            // BMPString: UTF-16 big endian.
            0x1e => {
                let units: Vec<u16> = self.content.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(String::from_utf16_lossy(&units))
            }
            // UniversalString: UTF-32 big endian.
            0x1c => Some(
                self.content
                    .chunks_exact(4)
                    .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{fffd}'))
                    .collect(),
            ),
            _ => None,
        }
    }

    /// A UTCTime or GeneralizedTime as `YYYY-MM-DDTHH:MM:SSZ`. Only UTC ("Z") times are accepted.
    pub fn time(&self) -> Option<String> {
        let text = std::str::from_utf8(self.content).ok()?;
        let digits = text.strip_suffix('Z')?;
        // Fractional seconds are dropped.
        let digits = digits.split('.').next()?;
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let (year, rest) = match self.tag {
            0x17 if digits.len() == 12 || digits.len() == 10 => {
                let two: u32 = digits[..2].parse().ok()?;
                (if two >= 50 { 1900 + two } else { 2000 + two }, &digits[2..])
            }
            0x18 if digits.len() == 14 || digits.len() == 12 => (digits[..4].parse().ok()?, &digits[4..]),
            _ => return None,
        };
        let seconds = if rest.len() == 10 { &rest[8..10] } else { "00" };
        Some(format!("{year:04}-{}-{}T{}:{}:{}Z", &rest[0..2], &rest[2..4], &rest[4..6], &rest[6..8], seconds))
    }
}

/// Reads the elements of a byte string one after another.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The bytes not yet read.
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The next element, whatever it is.
    pub fn any(&mut self) -> Result<Tlv<'a>, String> {
        let (tlv, used) = read(self.data, 0)?;
        self.data = &self.data[used..];
        Ok(tlv)
    }

    /// The next element, which must have `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, String> {
        let tlv = self.any()?;
        if tlv.tag == tag { Ok(tlv) } else { Err(format!("expected tag {tag:#04x}, found {:#04x}", tlv.tag)) }
    }

    /// The next element if it has `tag`; otherwise nothing is consumed.
    pub fn optional(&mut self, tag: u8) -> Option<Tlv<'a>> {
        let (tlv, used) = read(self.data, 0).ok()?;
        if tlv.tag != tag {
            return None;
        }
        self.data = &self.data[used..];
        Some(tlv)
    }

    /// The tag of the next element, without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Tlv<'a>, String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let item = self.any();
        if item.is_err() {
            // Stop after the first error instead of reporting it forever.
            self.data = &[];
        }
        Some(item)
    }
}

/// Reads one element at the start of `data`; returns it and the bytes it occupies.
fn read(data: &[u8], depth: u32) -> Result<(Tlv<'_>, usize), String> {
    if depth > MAX_DEPTH {
        return Err("nesting too deep".into());
    }
    let (&tag, after_tag) = data.split_first().ok_or("unexpected end of data")?;
    if tag & 0x1f == 0x1f {
        return Err("multi-byte tags are not supported".into());
    }
    let (&first, after_length) = after_tag.split_first().ok_or("unexpected end of data")?;
    if first == 0x80 {
        // Indefinite length: the content runs to an end-of-contents marker (00 00).
        if tag & 0x20 == 0 {
            return Err("indefinite length on a primitive element".into());
        }
        let mut position = 0usize;
        loop {
            let rest = after_length.get(position..).ok_or("unexpected end of data")?;
            if rest.starts_with(&[0, 0]) {
                let total = 2 + position + 2;
                return Ok((Tlv { tag, content: &after_length[..position], raw: &data[..total] }, total));
            }
            let (_, used) = read(rest, depth + 1)?;
            position += used;
        }
    }
    let (length, header) = if first < 0x80 {
        (first as usize, 2usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count > 4 {
            return Err("length field too long".into());
        }
        let bytes = after_length.get(..count).ok_or("unexpected end of data")?;
        (bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize), 2 + count)
    };
    let end = header.checked_add(length).ok_or("length overflow")?;
    let raw = data.get(..end).ok_or_else(|| format!("element of {length} bytes runs past the end of the data"))?;
    Ok((Tlv { tag, content: &raw[header..], raw }, end))
}

/// Parses exactly one element at the start of `data` and returns it with the bytes that follow.
pub fn parse_prefix(data: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    let (tlv, used) = read(data, 0)?;
    Ok((tlv, &data[used..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_definite_and_indefinite_lengths() {
        let (tlv, rest) = parse_prefix(&[0x30, 0x03, 0x02, 0x01, 0x05, 0xff]).expect("definite");
        assert_eq!(tlv.content, &[0x02, 0x01, 0x05]);
        assert_eq!(rest, &[0xff]);
        assert_eq!(tlv.children().any().expect("child").small_integer(), Some(5));

        let (tlv, rest) = parse_prefix(&[0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0xaa]).expect("indefinite");
        assert_eq!(tlv.content, &[0x02, 0x01, 0x05]);
        assert_eq!(tlv.raw.len(), 7);
        assert_eq!(rest, &[0xaa]);
    }

    #[test]
    fn decodes_oids_and_times() {
        let (oid, _) = parse_prefix(&[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02]).expect("oid");
        assert_eq!(oid.oid().as_deref(), Some("1.2.840.113549.1.7.2"));
        let (utc, _) = parse_prefix(b"\x17\x0d231114221320Z").expect("utc");
        assert_eq!(utc.time().as_deref(), Some("2023-11-14T22:13:20Z"));
        let (general, _) = parse_prefix(b"\x18\x0f20501114221320Z").expect("generalized");
        assert_eq!(general.time().as_deref(), Some("2050-11-14T22:13:20Z"));
        let (bad, _) = parse_prefix(b"\x17\x0d2311142213+01").expect("utc with offset");
        assert_eq!(bad.time(), None);
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        for bytes in [
            &[][..],
            &[0x30],
            &[0x30, 0x05, 0x01],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            &[0x30, 0x85, 1, 1, 1, 1, 1],
            &[0x30, 0x80, 0x30, 0x80, 0x30, 0x80],
            &[0x1f, 0x81, 0x01, 0x00],
            &[0x04, 0x80, 0x00, 0x00],
        ] {
            assert!(parse_prefix(bytes).is_err(), "{bytes:02x?}");
        }
        // Deep indefinite nesting must stop at the depth limit.
        let deep: Vec<u8> = std::iter::repeat_n([0x30u8, 0x80], 10_000).flatten().collect();
        assert!(parse_prefix(&deep).is_err());
    }
}
