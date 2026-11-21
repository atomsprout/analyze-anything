//! Recognizes a literal PowerShell host argument and decodes its representation.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

pub(super) const MAX_DECODED_BYTES: usize = 16 * 1024;
const MAX_BASE64_BYTES: usize = MAX_DECODED_BYTES.div_ceil(3) * 4;

pub(super) struct Operand<'a> {
    pub(super) value: Option<&'a str>,
    pub(super) offset: usize,
    pub(super) length: usize,
}

pub(super) struct Budget {
    remaining: usize,
    attempts: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self { remaining: 64 * 1024, attempts: 8 }
    }
}

/// Preserve only the declared operand span and facts from decoded syntax.
pub(super) fn inspect(args: &[Operand<'_>], budget: &mut Budget) -> Option<Value> {
    let values: Vec<_> = args.iter().map(|arg| arg.value).collect();
    let index = match select(&values) {
        Selection::Absent => return None,
        Selection::Argument(index) => index,
        Selection::Unresolved(reason) => return Some(json!({"status":"unresolved","reason":reason})),
    };
    let operand = args.get(index)?;
    let span = json!({"utf8_offset":operand.offset,"utf8_length":operand.length});
    if budget.attempts == 0 {
        return Some(json!({"status":"unresolved","operand":span,"reason":"EncodedCommand attempt budget"}));
    }
    budget.attempts -= 1;
    let encoded = operand.value?;
    let decoded = match decode(encoded, &mut budget.remaining) {
        Ok(decoded) => decoded,
        Err(reason) => return Some(json!({"status":"unresolved","operand":span,"reason":reason})),
    };
    Some(json!({"status":"decoded","operand":span,"encoding":"base64-utf16le",
        "decoded_sha256":decoded.sha256,"decoded_byte_length":decoded.byte_length,
        "syntax":crate::powershell::inspect_decoded(&decoded.text)}))
}

pub(super) fn literal(raw: &str) -> Option<&str> {
    let value = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(raw);
    (!value.is_empty()
        && value.len() <= MAX_BASE64_BYTES
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+' | b'/' | b'=' | b'.')))
    .then_some(value)
}

pub(super) fn finding(file: &Artifact, commands: &[Value], out: &mut Output) {
    let decoded: Vec<_> = commands.iter().filter(|row| row["encoded_command"]["status"] == "decoded").collect();
    if decoded.is_empty() {
        return;
    }
    let witnesses: Vec<_> = decoded.iter().take(4).map(|row| {
        let encoded = &row["encoded_command"];
        json!({"host":row["name"],"operand":encoded["operand"],"encoding":encoded["encoding"],"decoded_sha256":encoded["decoded_sha256"],
            "decoded_byte_length":encoded["decoded_byte_length"],"syntax_status":encoded["syntax"]["status"]})
    }).collect();
    out.finding(
        Finding::new(Section::Structure, "windows", "windows.powershell-encoded-command", Confidence::Verified, Severity::Info)
            .param("count", decoded.len())
            .evidence(Evidence::field(file, "PowerShell EncodedCommand operands in decoded UTF-8 source", json!(witnesses))),
    );
}

pub(super) fn host(name: &str) -> bool {
    name.rsplit(['/', '\\'])
        .next()
        .is_some_and(|base| ["powershell", "powershell.exe", "pwsh", "pwsh.exe"].iter().any(|known| base.eq_ignore_ascii_case(known)))
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Selection {
    Absent,
    Argument(usize),
    Unresolved(&'static str),
}

pub(super) fn select(args: &[Option<&str>]) -> Selection {
    let encoded = |name: &str| name.eq_ignore_ascii_case("-EncodedCommand");
    if !args.iter().flatten().any(|name| encoded(name)) {
        return Selection::Absent;
    }
    let mut index = 0;
    while let Some(value) = args.get(index) {
        let Some(value) = value else { return Selection::Unresolved("dynamic host option before EncodedCommand") };
        if encoded(value) {
            return match (args.get(index + 1), args.len() == index + 2) {
                (Some(Some(_)), true) => Selection::Argument(index + 1),
                (None | Some(None), _) => Selection::Unresolved("EncodedCommand operand is absent or dynamic"),
                _ => Selection::Unresolved("trailing or repeated PowerShell host arguments are outside the checked profile"),
            };
        }
        if ["-File", "-Command", "-CommandWithArgs", "--", "--%"].iter().any(|name| value.eq_ignore_ascii_case(name))
            || !value.starts_with('-')
        {
            return Selection::Absent;
        }
        if ["-NoLogo", "-NoProfile", "-NonInteractive", "-NoExit", "-STA", "-MTA"].iter().any(|name| value.eq_ignore_ascii_case(name)) {
            index += 1;
        } else {
            return Selection::Unresolved("unrecognized PowerShell host option before EncodedCommand");
        }
    }
    Selection::Absent
}

pub(super) struct Decoded {
    pub(super) sha256: String,
    pub(super) byte_length: usize,
    pub(super) text: String,
}

pub(super) fn decode(encoded: &str, remaining: &mut usize) -> Result<Decoded, &'static str> {
    if encoded.is_empty() || encoded.len() > MAX_BASE64_BYTES {
        return Err("EncodedCommand text is absent or exceeds its byte budget");
    }
    let bytes = STANDARD.decode(encoded).map_err(|_| "EncodedCommand is outside standard Base64")?;
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) || bytes.len() > MAX_DECODED_BYTES || bytes.len() > *remaining {
        return Err("EncodedCommand byte length is outside its UTF-16LE or aggregate budget");
    }
    *remaining -= bytes.len();
    // Allow a leading LE BOM in the encoded text and reject unrelated encodings.
    if bytes.starts_with(&[0xfe, 0xff]) {
        return Err("EncodedCommand uses a big-endian byte order mark");
    }
    let body = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(&bytes);
    let units: Vec<_> = body.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let text = String::from_utf16(&units).map_err(|_| "EncodedCommand contains invalid UTF-16LE")?;
    if text.trim().is_empty() || text.contains('\0') {
        return Err("EncodedCommand text is empty or contains a NUL character");
    }
    Ok(Decoded { sha256: aa_core::sha256_hex(&bytes), byte_length: bytes.len(), text })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_operand_requires_a_qualified_literal_argument_position() {
        assert!(host(r"C:\Tools\pwsh.exe"));
        assert!(!host("not-pwsh.exe"));
        assert_eq!(select(&[Some("-NoProfile"), Some("-EncodedCommand"), Some("YQA=")]), Selection::Argument(2));
        assert_eq!(select(&[Some("-File"), Some("test.ps1"), Some("-EncodedCommand"), Some("YQA=")]), Selection::Absent);
        assert!(matches!(select(&[Some("-EncodedCommand"), None]), Selection::Unresolved(_)));
        assert!(matches!(select(&[None, Some("-EncodedCommand"), Some("YQA=")]), Selection::Unresolved(_)));
        assert!(matches!(select(&[Some("-EncodedCommand"), Some("YQA="), Some("tail")]), Selection::Unresolved(_)));
    }

    #[test]
    fn requires_standard_base64_and_bounded_utf16_le() {
        let mut budget = 2;
        let result = decode("YQA=", &mut budget).expect("one UTF-16LE code unit");
        assert_eq!(result.text, "a");
        assert_eq!(result.sha256, aa_core::sha256_hex(b"a\0"));
        assert_eq!(result.byte_length, 2);
        assert_eq!(budget, 0);
        assert!(decode("YQA=", &mut budget).is_err());
        for malformed in ["=a", "YQ==", "/v8=", "ANg=", "AAA="] {
            assert!(decode(malformed, &mut { MAX_DECODED_BYTES }).is_err());
        }
    }

    #[test]
    fn native_reference_has_decoded_digest_and_syntax_without_raw_content() {
        let fixture: Value = serde_json::from_str(include_str!("../tests/data/powershell-encoded.ref.json")).expect("native reference");
        let operand = fixture["encoded"].as_str().expect("fixture operand");
        let args = [
            Operand { value: Some("-EncodedCommand"), offset: 5, length: 15 },
            Operand { value: Some(operand), offset: 21, length: operand.len() },
        ];
        let mut budget = Budget::default();
        let result = inspect(&args, &mut budget).expect("declared host option");
        assert_eq!(result["operand"]["utf8_offset"], 21);
        assert_eq!(result["decoded_sha256"], fixture["decoded_sha256"]);
        assert_eq!(result["syntax"]["commands"][0]["name"], fixture["commands"][0]);
        assert!(!result.to_string().contains(operand));
        assert!(!result.to_string().contains("fixture only"));
        for _ in 1..8 {
            assert_eq!(inspect(&args, &mut budget).expect("within work budget")["status"], "decoded");
        }
        assert_eq!(inspect(&args, &mut budget).expect("exhausted work budget")["status"], "unresolved");
    }
}
