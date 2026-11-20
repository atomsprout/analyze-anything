//! Deterministic decoding for Windows text formats; the host code page is never consulted.

pub fn decode(bytes: &[u8], maximum: usize) -> Result<String, &'static str> {
    if bytes.len() > maximum {
        return Err("text exceeds the reader's byte limit");
    }
    let text = if let Some(body) = bytes.strip_prefix(&[0xff, 0xfe]).or_else(|| bytes.strip_prefix(&[0xfe, 0xff])) {
        if !body.len().is_multiple_of(2) {
            return Err("truncated UTF-16 text");
        }
        let little = bytes.starts_with(&[0xff, 0xfe]);
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|b| if little { u16::from_le_bytes([b[0], b[1]]) } else { u16::from_be_bytes([b[0], b[1]]) })
            .collect();
        String::from_utf16(&units).map_err(|_| "invalid UTF-16 text")?
    } else {
        let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        std::str::from_utf8(body).map(str::to_string).map_err(|_| "unknown text encoding; no host code page is assumed")?
    };
    if text.contains('\0') {
        return Err("text contains a NUL character or an unmarked UTF-16 encoding");
    }
    Ok(text)
}
