//! Measures an artifact's bytes: size, digests, entropy and detected type.

use aa_core::{Detected, Digests};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Leading bytes used for type detection.
const HEAD_LENGTH: usize = 8192;

pub struct Scanned {
    pub digests: Digests,
    /// `None` for an empty artifact.
    pub entropy: Option<f64>,
    pub detected: Detected,
}

pub fn scan(bytes: &[u8]) -> Scanned {
    let (mut md5, mut sha1, mut sha256) = (Md5::new(), Sha1::new(), Sha256::new());
    let mut counts = [0u64; 256];
    for chunk in bytes.chunks(1024 * 1024) {
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
        for byte in chunk {
            counts[*byte as usize] += 1;
        }
    }
    Scanned {
        digests: Digests { md5: hex::encode(md5.finalize()), sha1: hex::encode(sha1.finalize()), sha256: hex::encode(sha256.finalize()) },
        entropy: entropy(&counts, bytes.len() as u64),
        detected: detect(&bytes[..bytes.len().min(HEAD_LENGTH)]),
    }
}

/// Shannon entropy in bits per byte, rounded to four decimals so reports compare exactly.
fn entropy(counts: &[u64; 256], size: u64) -> Option<f64> {
    if size == 0 {
        return None;
    }
    let total = size as f64;
    let bits: f64 = counts.iter().filter(|c| **c > 0).map(|c| *c as f64 / total).map(|p| -p * p.log2()).sum();
    Some((bits * 10_000.0).round() / 10_000.0)
}

fn detect(head: &[u8]) -> Detected {
    let inferred = infer::get(head);
    // The general detector calls anything that opens with a tag or a comment HTML, so text is
    // classified here instead. Formats that merely contain readable text (PDF, RTF) keep its answer.
    if looks_like_text(head) && inferred.is_none_or(|kind| kind.mime_type().starts_with("text/")) {
        return Detected { mime: text_kind(head).to_string(), usual_extension: None };
    }
    if let Some(kind) = inferred {
        return Detected { mime: kind.mime_type().to_string(), usual_extension: Some(kind.extension().to_string()) };
    }
    let mime = if head.is_empty() { "application/x-empty" } else { "application/octet-stream" };
    Detected { mime: mime.to_string(), usual_extension: None }
}

/// The kind of a text file, from how it begins. Leading comments are skipped: a Markdown file that
/// opens with `<!-- … -->` is not HTML.
fn text_kind(head: &[u8]) -> &'static str {
    let text = String::from_utf8_lossy(head);
    let mut rest = text.trim_start_matches('\u{feff}').trim_start();
    if rest.starts_with("#!") {
        return "text/x-shellscript";
    }
    let declared_xml = rest.starts_with("<?xml");
    if declared_xml {
        rest = rest.split_once("?>").map(|(_, after)| after).unwrap_or("").trim_start();
    }
    while let Some(after) = rest.strip_prefix("<!--") {
        rest = after.split_once("-->").map(|(_, after)| after).unwrap_or("").trim_start();
    }
    let opening: String = rest.chars().take(14).collect::<String>().to_ascii_lowercase();
    if opening.starts_with("<svg") || opening.starts_with("<!doctype svg") {
        "image/svg+xml"
    } else if opening.starts_with("<!doctype html") || opening.starts_with("<html") {
        "text/html"
    } else if declared_xml {
        "text/xml"
    } else {
        "text/plain"
    }
}

/// True for UTF-8 without control characters other than whitespace. The head may end mid-character.
fn looks_like_text(head: &[u8]) -> bool {
    let text = match std::str::from_utf8(head) {
        Ok(text) => text,
        Err(error) if head.len() - error.valid_up_to() < 4 && error.error_len().is_none() => {
            std::str::from_utf8(&head[..error.valid_up_to()]).unwrap_or("")
        }
        Err(_) => return false,
    };
    !text.is_empty() && !text.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t' | '\x0c'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_one_repeated_byte_is_zero() {
        let mut counts = [0u64; 256];
        counts[65] = 1000;
        assert_eq!(entropy(&counts, 1000), Some(0.0));
    }

    #[test]
    fn entropy_of_all_bytes_equally_is_eight() {
        assert_eq!(entropy(&[4u64; 256], 1024), Some(8.0));
    }

    #[test]
    fn entropy_of_nothing_is_unknown() {
        assert_eq!(entropy(&[0u64; 256], 0), None);
    }

    #[test]
    fn text_is_classified_by_how_it_begins() {
        let mime = |bytes: &[u8]| detect(bytes).mime;
        assert_eq!(mime(b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"), "image/svg+xml");
        assert_eq!(mime(b"<!-- icon -->\n<svg></svg>"), "image/svg+xml");
        assert_eq!(mime(b"<?xml version=\"1.0\"?>\n<!-- c -->\n<svg></svg>"), "image/svg+xml");
        assert_eq!(mime(b"<?xml version=\"1.0\"?><plist></plist>"), "text/xml");
        assert_eq!(mime(b"<!DOCTYPE html><html></html>"), "text/html");
        assert_eq!(mime(b"<!-- note -->\n# Title\n"), "text/plain");
        assert_eq!(mime(b"#!/bin/sh\necho hi\n"), "text/x-shellscript");
        assert_eq!(mime(b""), "application/x-empty");
        assert_eq!(mime(b"%PDF-1.7\n1 0 obj\n"), "application/pdf");
    }

    #[test]
    fn text_cut_inside_a_character_is_still_text() {
        let bytes = "分析".as_bytes();
        assert!(looks_like_text(&bytes[..bytes.len() - 1]));
        assert!(!looks_like_text(&[0x00, 0x01, 0x02]));
        assert!(!looks_like_text(&[0xff, 0xfe, 0x41]));
    }
}
