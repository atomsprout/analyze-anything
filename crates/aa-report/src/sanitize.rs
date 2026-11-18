//! Makes characters that could mislead a reader visible.
//!
//! Report text comes from the analyzed input and may be hostile: a file name can carry a
//! right-to-left override so that `evil\u{202e}fdp.exe` reads as `evilexe.pdf`, or invisible
//! characters that make two different names look the same. Readable outputs show such characters
//! as their code point instead of letting them act.

use std::borrow::Cow;

/// True for characters that are invisible or change how the text around them is laid out.
pub(crate) fn is_deceptive(c: char) -> bool {
    matches!(
        c,
        '\u{0000}'..='\u{0008}'
            | '\u{000b}'..='\u{001f}'
            | '\u{007f}'..='\u{009f}'
            | '\u{00ad}'
            | '\u{061c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// Writes `c` as its code point in brackets, e.g. `[U+202E]`. Plain ASCII, so every font and
/// every output format can show it.
fn push_visible(out: &mut String, c: char) {
    out.push_str(&format!("[U+{:04X}]", c as u32));
}

/// `text` with every deceptive character replaced by a visible stand-in. Line feeds and tabs stay.
pub fn visible(text: &str) -> Cow<'_, str> {
    if !text.chars().any(is_deceptive) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if is_deceptive(c) { push_visible(&mut out, c) } else { out.push(c) }
    }
    Cow::Owned(out)
}

/// Like [`visible`], for text that must stay on one line: line feeds and tabs become stand-ins too.
pub fn visible_line(text: &str) -> Cow<'_, str> {
    if !text.chars().any(|c| is_deceptive(c) || c == '\n' || c == '\t') {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if is_deceptive(c) || c == '\n' || c == '\t' { push_visible(&mut out, c) } else { out.push(c) }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_text_is_untouched() {
        assert!(matches!(visible("报告 report.pdf\n\tline"), Cow::Borrowed(_)));
    }

    #[test]
    fn bidi_overrides_and_controls_become_visible() {
        assert_eq!(visible("a\u{202e}b\u{0000}c\u{007f}\u{200b}"), "a[U+202E]b[U+0000]c[U+007F][U+200B]");
        assert_eq!(visible_line("a\nb\tc"), "a[U+000A]b[U+0009]c");
        assert_eq!(visible("\u{e0041}"), "[U+E0041]");
    }
}
