//! Plain-text output: the same document as Markdown, with no markup at all.

use std::fmt::Write as _;

use crate::doc::{Block, Doc};

fn clean(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

pub fn write(doc: &Doc) -> String {
    let mut out = String::new();
    let mut in_list = false;
    for block in &doc.blocks {
        let is_item = matches!(block, Block::Item(..));
        if !out.is_empty() && !(is_item && in_list) {
            out.push('\n');
        }
        in_list = is_item;
        // Writing to a String cannot fail, so the results are discarded.
        let _ = match block {
            Block::Heading(level, text) => {
                let text = clean(text);
                let rule = match level {
                    1 => "=",
                    2 => "-",
                    _ => "",
                };
                let width = text.chars().count().max(4);
                if rule.is_empty() { writeln!(out, "{text}") } else { writeln!(out, "{text}\n{}", rule.repeat(width)) }
            }
            Block::Paragraph(text) => writeln!(out, "{}", clean(text)),
            Block::Item(level, text) => writeln!(out, "{}* {}", "    ".repeat(*level as usize), clean(text)),
            Block::Table { head, rows } => {
                let _ = writeln!(out, "{}", head.iter().map(|c| clean(c)).collect::<Vec<_>>().join("\t"));
                rows.iter().try_for_each(|row| writeln!(out, "{}", row.iter().map(|c| clean(c)).collect::<Vec<_>>().join("\t")))
            }
        };
    }
    out
}
