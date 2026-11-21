//! Qualified Windows reverse-X.500 subject spelling, without an OS name/locale registry.

use crate::der::{self, TAG_OID, TAG_SEQUENCE, TAG_SET};
use serde_json::{Value, json};

pub(super) const PROFILE: &str = "windows-x500-reverse-qualified-v1";

fn key(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "S",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.13" => "Description",
        "2.5.4.17" => "PostalCode",
        "2.5.4.42" => "G",
        "2.5.4.43" => "I",
        _ => return None,
    })
}

fn text(value: der::Tlv<'_>) -> Result<String, &'static str> {
    if value.content.len() > 16384 {
        return Err("subject attribute byte limit");
    }
    let text = match value.tag {
        0x0c => std::str::from_utf8(value.content).map(str::to_string).map_err(|_| "invalid subject UTF8String")?,
        0x13 | 0x14 | 0x16 if value.content.is_ascii() => {
            std::str::from_utf8(value.content).map(str::to_string).map_err(|_| "invalid subject ASCII text")?
        }
        0x1e if value.content.len().is_multiple_of(2) => {
            let units: Vec<_> = value.content.chunks_exact(2).map(|p| u16::from_be_bytes([p[0], p[1]])).collect();
            String::from_utf16(&units).map_err(|_| "invalid subject BMPString")?
        }
        _ => return Err("subject value type or legacy character encoding is outside qualified profile"),
    };
    if text.chars().any(char::is_control) {
        return Err("subject control characters are outside qualified profile");
    }
    if text.chars().next().into_iter().chain(text.chars().next_back()).any(|c| c != ' ' && c.is_whitespace()) {
        return Err("subject edge whitespace is outside qualified profile");
    }
    let quote = text.is_empty()
        || text.starts_with(' ')
        || text.ends_with(' ')
        || text.chars().any(|c| matches!(c, ',' | '+' | '=' | '"' | '<' | '>' | '#' | ';'));
    Ok(if quote { format!("\"{}\"", text.replace('"', "\"\"")) } else { text })
}

pub(super) fn render(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.len() > 16384 {
        return Err("subject DER byte limit");
    }
    crate::catalog::bounded_asn1(bytes).map_err(|_| "subject is outside bounded minimal DER profile")?;
    let (root, rest) = der::parse_prefix(bytes).map_err(|_| "subject DER is unreadable")?;
    if root.tag != TAG_SEQUENCE || !rest.is_empty() {
        return Err("subject is not one Name sequence");
    }
    let mut groups = Vec::new();
    let mut output_bytes = 0usize;
    for (position, rdn) in root.children().enumerate() {
        if position >= 32 {
            return Err("subject RDN count limit");
        }
        let rdn = rdn.map_err(|_| "subject RDN is unreadable")?;
        if rdn.tag != TAG_SET {
            return Err("subject RDN is not a set");
        }
        let mut attributes = Vec::new();
        let mut previous = None;
        for (position, pair) in rdn.children().enumerate() {
            if position >= 8 {
                return Err("subject RDN attribute count limit");
            }
            let pair = pair.map_err(|_| "subject attribute is unreadable")?;
            if pair.tag != TAG_SEQUENCE || previous.is_some_and(|p: &[u8]| p > pair.raw) {
                return Err("subject RDN is outside ordered DER profile");
            }
            previous = Some(pair.raw);
            let mut fields = pair.children();
            let oid = fields.expect(TAG_OID).map_err(|_| "subject attribute OID absent")?.oid().ok_or("subject OID invalid")?;
            let key = key(&oid).ok_or("subject OID key is outside qualified static alias profile")?;
            let value = text(fields.any().map_err(|_| "subject value absent")?)?;
            if fields.next().is_some() {
                return Err("extra subject attribute fields");
            }
            output_bytes = output_bytes.checked_add(key.len() + value.len() + 4).ok_or("subject spelling overflow")?;
            if output_bytes > 8192 {
                return Err("subject spelling byte limit");
            }
            attributes.push(format!("{key}={value}"));
        }
        if attributes.is_empty() {
            return Err("empty subject RDN");
        }
        groups.push(attributes.join(" + "));
    }
    if groups.is_empty() {
        return Err("empty certificate subject");
    }
    groups.reverse();
    Ok(groups.join(", "))
}

pub(super) fn projection(bytes: &[u8]) -> Value {
    let digest = aa_core::sha256_hex(bytes);
    match render(bytes) {
        Ok(value) => match aa_core::text::redact_sensitive_text(&value) {
            Ok(redacted) if redacted == value => json!({"profile":PROFILE,"status":"projected","value":value,"subject_sha256":digest}),
            _ => json!({"profile":PROFILE,"status":"unresolved","reason":"subject spelling requires redaction","subject_sha256":digest}),
        },
        Err(reason) => json!({"profile":PROFILE,"status":"unresolved","reason":reason,"subject_sha256":digest}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        if body.len() < 128 {
            bytes.push(body.len() as u8);
        } else {
            let length = (body.len() as u32).to_be_bytes();
            let first = length.iter().position(|b| *b != 0).expect("nonzero long length");
            bytes.push(0x80 | (4 - first) as u8);
            bytes.extend_from_slice(&length[first..]);
        }
        bytes.extend_from_slice(body);
        bytes
    }

    fn attribute(value: &[u8]) -> Vec<u8> {
        tlv(TAG_SEQUENCE, &[tlv(TAG_OID, &[0x55, 4, 3]), tlv(0x0c, value)].concat())
    }

    #[test]
    fn redaction_and_rdn_attribute_and_spelling_budgets_do_not_publish_partial_values() {
        let sensitive = format!("sk-proj-{}", "x".repeat(32));
        let bytes = tlv(TAG_SEQUENCE, &tlv(TAG_SET, &attribute(sensitive.as_bytes())));
        let fact = projection(&bytes);
        assert_eq!(fact["status"], "unresolved");
        assert_eq!(fact["reason"], "subject spelling requires redaction");
        assert!(!fact.to_string().contains(&sensitive));
        let pair = attribute(b"value");
        let rdn = tlv(TAG_SET, &pair);
        assert!(render(&tlv(TAG_SEQUENCE, &rdn.repeat(32))).is_ok());
        assert!(render(&tlv(TAG_SEQUENCE, &rdn.repeat(33))).is_err());
        assert!(render(&tlv(TAG_SEQUENCE, &tlv(TAG_SET, &pair.repeat(8)))).is_ok());
        assert!(render(&tlv(TAG_SEQUENCE, &tlv(TAG_SET, &pair.repeat(9)))).is_err());
        assert!(render(&tlv(TAG_SEQUENCE, &tlv(TAG_SET, &attribute(&vec![b'a'; 8192])))).is_err());
    }

    #[test]
    fn subject_spellings_match_native_windows_references_with_explicit_exclusions() {
        let rows: Value = serde_json::from_str(include_str!("../tests/data/msix-publisher-subjects.ref.json")).expect("native references");
        for row in rows.as_array().expect("reference rows") {
            let bytes = hex::decode(row["der"].as_str().expect("DER hex")).expect("DER bytes");
            if row["supported"] == true {
                assert_eq!(render(&bytes).expect("qualified subject"), row["windows"].as_str().expect("native spelling"));
            } else {
                assert!(render(&bytes).is_err(), "{row}");
            }
            for cut in 0..bytes.len() {
                assert!(render(&bytes[..cut]).is_err());
            }
        }
    }

    #[test]
    fn malformed_empty_and_oversized_names_remain_unresolved() {
        for bytes in [&[0x30, 0][..], &[0x30, 2, 0x31, 0], &[0x30, 0x81, 0]] {
            assert!(render(bytes).is_err());
            assert_eq!(projection(bytes)["status"], "unresolved");
        }
        assert!(render(&vec![0; 16385]).is_err());
        let bmp = hex::decode("300f310d300b06035504031e04004f004b").expect("BMP subject");
        assert_eq!(render(&bmp).expect("bounded BMP"), "CN=OK");
        let mut invalid = bmp;
        invalid[13..].copy_from_slice(&[0xd8, 0, 0, 0x4b]);
        assert!(render(&invalid).is_err());
    }
}
