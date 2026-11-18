//! Makes characters that could mislead a reader visible.
//!
//! Report text comes from the analyzed input and may be hostile: a file name can carry a
//! right-to-left override so that `evil\u{202e}fdp.exe` reads as `evilexe.pdf`, or invisible
//! characters that make two different names look the same. Readable outputs show such characters
//! as their code point instead of letting them act.

use std::borrow::Cow;

/// True for characters that are invisible or change how the text around them is laid out.
fn is_deceptive(c: char) -> bool {
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

fn push_visible(out: &mut String, c: char) {
    match c {
        // The Unicode "control pictures" block mirrors the C0 controls one to one.
        '\u{0000}'..='\u{001f}' => out.push(char::from_u32(0x2400 + c as u32).unwrap_or('\u{fffd}')),
        '\u{007f}' => out.push('\u{2421}'),
        _ => {
            out.push_str("\u{27e6}U+");
            out.push_str(&format!("{:04X}", c as u32));
            out.push('\u{27e7}');
        }
    }
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
        assert_eq!(visible("a\u{202e}b\u{0000}c\u{007f}\u{200b}"), "a⟦U+202E⟧b␀c␡⟦U+200B⟧");
        assert_eq!(visible_line("a\nb\tc"), "a␊b␉c");
        assert_eq!(visible("\u{e0041}"), "⟦U+E0041⟧");
    }
}
