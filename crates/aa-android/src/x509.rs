//! The fields of an X.509 certificate that the report shows, read with the tolerant DER reader.
//! Signing certificates in the wild break strict parsers (negative serials, odd string types),
//! so nothing beyond the outer structure is required to be well-formed.

use serde_json::{Value as Json, json};
use sha2::Digest;

use crate::der::{self, Tlv};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    Rsa { bits: usize },
    Ec { curve: String, bits: Option<usize> },
    Dsa { bits: usize },
    Other(String),
}

impl KeyAlgorithm {
    pub fn describe(&self) -> String {
        match self {
            KeyAlgorithm::Rsa { bits } => format!("RSA {bits}"),
            KeyAlgorithm::Ec { curve, .. } => format!("EC {curve}"),
            KeyAlgorithm::Dsa { bits } => format!("DSA {bits}"),
            KeyAlgorithm::Other(oid) => format!("OID {oid}"),
        }
    }

    pub fn bits(&self) -> Option<usize> {
        match self {
            KeyAlgorithm::Rsa { bits } | KeyAlgorithm::Dsa { bits } => Some(*bits),
            KeyAlgorithm::Ec { bits, .. } => *bits,
            KeyAlgorithm::Other(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Certificate {
    /// Distinguished names in RFC 2253 order (most specific first), as apksigner and keytool print them.
    pub subject: String,
    pub issuer: String,
    /// Serial number in hex.
    pub serial: String,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub signature_algorithm: String,
    pub signature_algorithm_oid: String,
    pub key: KeyAlgorithm,
    /// The certificate's subjectPublicKeyInfo, DER encoded.
    pub spki: Vec<u8>,
    pub self_issued: bool,
    pub sha1: String,
    pub sha256: String,
    pub md5: String,
    /// The signed part, the signature algorithm and the signature, for checking a self-signature.
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
    pub issuer_raw: Vec<u8>,
    pub serial_raw: Vec<u8>,
}

pub fn signature_algorithm_name(oid: &str) -> &'static str {
    match oid {
        "1.2.840.113549.1.1.2" => "MD2withRSA",
        "1.2.840.113549.1.1.4" => "MD5withRSA",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "SHA1withRSA",
        "1.2.840.113549.1.1.14" => "SHA224withRSA",
        "1.2.840.113549.1.1.11" => "SHA256withRSA",
        "1.2.840.113549.1.1.12" => "SHA384withRSA",
        "1.2.840.113549.1.1.13" => "SHA512withRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "SHA1withECDSA",
        "1.2.840.10045.4.3.1" => "SHA224withECDSA",
        "1.2.840.10045.4.3.2" => "SHA256withECDSA",
        "1.2.840.10045.4.3.3" => "SHA384withECDSA",
        "1.2.840.10045.4.3.4" => "SHA512withECDSA",
        "1.2.840.10040.4.3" => "SHA1withDSA",
        "2.16.840.1.101.3.4.3.1" => "SHA224withDSA",
        "2.16.840.1.101.3.4.3.2" => "SHA256withDSA",
        "1.3.101.112" => "Ed25519",
        _ => "",
    }
}

fn attribute_name(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SURNAME",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "T",
        "2.5.4.42" => "GIVENNAME",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        "0.9.2342.19200300.100.1.25" => "DC",
        "0.9.2342.19200300.100.1.1" => "UID",
        _ => return None,
    })
}

fn string_value(tlv: &Tlv) -> String {
    match tlv.tag {
        // BMPString: UTF-16 big endian.
        0x1e => {
            let units: Vec<u16> = tlv.value.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        }
        // UniversalString: UTF-32 big endian.
        0x1c => tlv
            .value
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]])).unwrap_or('\u{fffd}'))
            .collect(),
        // T61String is treated as Latin-1, as most tools do.
        0x14 => tlv.value.iter().map(|b| *b as char).collect(),
        _ => String::from_utf8_lossy(tlv.value).into_owned(),
    }
}

/// A distinguished name as text, most specific attribute first.
pub fn name_string(name_value: &[u8]) -> String {
    let mut parts = Vec::new();
    for rdn in der::items(name_value).take(64) {
        let mut inner = Vec::new();
        for attribute in der::items(rdn.value).take(16) {
            let mut fields = der::items(attribute.value);
            let (Some(oid), Some(value)) = (fields.next(), fields.next()) else { continue };
            let oid = der::oid_string(oid.value);
            let key = attribute_name(&oid).map(str::to_string).unwrap_or(oid);
            let text: String = string_value(&value).chars().take(512).collect();
            // RFC 2253 escaping of the characters that would change how the name reads.
            let needs_escape = |c: char| matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';');
            let escaped: String = text.chars().flat_map(|c| if needs_escape(c) { vec!['\\', c] } else { vec![c] }).collect();
            inner.push(format!("{key}={escaped}"));
        }
        if !inner.is_empty() {
            parts.push(inner.join("+"));
        }
    }
    parts.reverse();
    parts.join(", ")
}

fn time_string(tlv: &Tlv) -> Option<String> {
    let text = std::str::from_utf8(tlv.value).ok()?;
    let digits = text.trim_end_matches('Z');
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match tlv.tag {
        0x17 if digits.len() >= 10 => {
            let yy: u32 = digits[..2].parse().ok()?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
        }
        0x18 if digits.len() >= 12 => (digits[..4].parse().ok()?, &digits[4..]),
        _ => return None,
    };
    let seconds = rest.get(8..10).unwrap_or("00");
    Some(format!("{year:04}-{}-{}T{}:{}:{}Z", &rest[..2], &rest[2..4], &rest[4..6], &rest[6..8], seconds))
}

/// Reads the key algorithm and size out of a subjectPublicKeyInfo.
pub fn key_algorithm(spki: &[u8]) -> Option<KeyAlgorithm> {
    let (outer, _) = der::read(spki)?;
    let mut fields = der::items(outer.value);
    let algorithm = fields.next()?;
    let key_bits = fields.next().filter(|t| t.tag == der::BIT_STRING)?;
    let mut alg_fields = der::items(algorithm.value);
    let oid = der::oid_string(alg_fields.next()?.value);
    let params = alg_fields.next();
    let key = key_bits.value.get(1..)?;
    Some(match oid.as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            let (sequence, _) = der::read(key)?;
            let modulus = der::items(sequence.value).next()?;
            KeyAlgorithm::Rsa { bits: der::bit_len(modulus.value) }
        }
        "1.2.840.10045.2.1" => {
            let curve_oid = params.filter(|p| p.tag == der::OID).map(|p| der::oid_string(p.value)).unwrap_or_default();
            let (curve, bits) = match curve_oid.as_str() {
                "1.2.840.10045.3.1.7" => ("P-256", Some(256)),
                "1.3.132.0.34" => ("P-384", Some(384)),
                "1.3.132.0.35" => ("P-521", Some(521)),
                "1.3.132.0.10" => ("secp256k1", Some(256)),
                _ => ("", None),
            };
            KeyAlgorithm::Ec { curve: if curve.is_empty() { format!("curve {curve_oid}") } else { curve.to_string() }, bits }
        }
        "1.2.840.10040.4.1" => {
            let p = params.and_then(|p| der::items(p.value).next())?;
            KeyAlgorithm::Dsa { bits: der::bit_len(p.value) }
        }
        _ => KeyAlgorithm::Other(oid),
    })
}

pub fn parse(der_bytes: &[u8]) -> Option<Certificate> {
    let (certificate, _) = der::read(der_bytes)?;
    if certificate.tag != der::SEQUENCE {
        return None;
    }
    let mut outer = der::items(certificate.value);
    let tbs = outer.next().filter(|t| t.tag == der::SEQUENCE)?;
    let signature_algorithm = outer.next()?;
    let signature = outer.next().filter(|t| t.tag == der::BIT_STRING)?;
    let mut fields = der::items(tbs.value).peekable();
    if fields.peek().is_some_and(|t| t.tag == 0xa0) {
        fields.next();
    }
    let serial = fields.next().filter(|t| t.tag == der::INTEGER)?;
    let _inner_algorithm = fields.next()?;
    let issuer = fields.next()?;
    let validity = fields.next()?;
    let subject = fields.next()?;
    let spki = fields.next().filter(|t| t.tag == der::SEQUENCE)?;
    let mut times = der::items(validity.value);
    let not_before = times.next().and_then(|t| time_string(&t));
    let not_after = times.next().and_then(|t| time_string(&t));
    let oid = der::items(signature_algorithm.value).next().map(|t| der::oid_string(t.value)).unwrap_or_default();
    let name = signature_algorithm_name(&oid);
    // Use the certificate as encoded, not trailing bytes after it, for the fingerprints.
    let encoded = certificate.raw;
    Some(Certificate {
        subject: name_string(subject.value),
        issuer: name_string(issuer.value),
        serial: hex::encode(serial.value),
        not_before,
        not_after,
        signature_algorithm: if name.is_empty() { format!("OID {oid}") } else { name.to_string() },
        signature_algorithm_oid: oid,
        key: key_algorithm(spki.raw).unwrap_or(KeyAlgorithm::Other(String::new())),
        spki: spki.raw.to_vec(),
        self_issued: issuer.raw == subject.raw,
        sha1: hex::encode(sha1::Sha1::digest(encoded)),
        sha256: hex::encode(sha2::Sha256::digest(encoded)),
        md5: hex::encode(md5::Md5::digest(encoded)),
        tbs: tbs.raw.to_vec(),
        signature: signature.value.get(1..).unwrap_or_default().to_vec(),
        issuer_raw: issuer.raw.to_vec(),
        serial_raw: serial.value.to_vec(),
    })
}

impl Certificate {
    pub fn to_json(&self) -> Json {
        json!({
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.signature_algorithm,
            "key_algorithm": self.key.describe(),
            "key_bits": self.key.bits(),
            "self_issued": self.self_issued,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "md5": self.md5,
        })
    }
}
