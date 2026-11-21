//! Strict, bounded MSIX XML text decoding; declarations never select a host code page.

pub(super) fn decode(bytes: &[u8], maximum: usize) -> Result<String, &'static str> {
    let text = crate::text::decode(bytes, maximum)?;
    // Callers disable DTDs in the XML parser. A textual scan would also reject harmless
    // comments or CDATA containing the same characters.
    if let Some(header) = text.strip_prefix("<?xml").and_then(|s| s.split_once("?>").map(|p| p.0))
        && let Some(encoding) = header.split_once("encoding").map(|p| p.1.trim_start())
    {
        let value = encoding.strip_prefix('=').map(str::trim_start).ok_or("invalid XML encoding declaration")?;
        let quote = value.chars().next().filter(|q| matches!(q, '\'' | '"')).ok_or("invalid XML encoding declaration")?;
        let declared = value.get(1..).and_then(|s| s.split(quote).next()).unwrap_or("").to_ascii_lowercase();
        let matches = if bytes.starts_with(&[255, 254]) {
            matches!(declared.as_str(), "utf-16" | "utf-16le")
        } else if bytes.starts_with(&[254, 255]) {
            matches!(declared.as_str(), "utf-16" | "utf-16be")
        } else {
            matches!(declared.as_str(), "utf-8" | "utf8")
        };
        if !matches {
            return Err("MSIX XML declaration and byte encoding do not match the supported profile");
        }
    }
    Ok(text)
}
