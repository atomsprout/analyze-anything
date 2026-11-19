//! Markdown output.

use std::fmt::Write as _;

use crate::doc::{Block, Doc};

/// Escapes the characters Markdown would read as markup. Report text is data, never markup.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '|' | '#' | '~' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
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
            Block::Heading(level, text) => writeln!(out, "{} {}", "#".repeat(*level as usize), escape(text)),
            Block::Paragraph(text) => writeln!(out, "{}", escape(text)),
            Block::Item(level, text) => writeln!(out, "{}- {}", "  ".repeat(*level as usize), escape(text)),
            Block::Table { head, rows } => {
                let line = |cells: &[String]| format!("| {} |", cells.iter().map(|c| escape(c)).collect::<Vec<_>>().join(" | "));
                let _ = writeln!(out, "{}", line(head));
                let _ = writeln!(out, "|{}", "---|".repeat(head.len()));
                rows.iter().try_for_each(|row| writeln!(out, "{}", line(row)))
            }
        };
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_characters_in_data_are_escaped() {
        let doc = Doc { blocks: vec![Block::Item(0, "a_b*c|d`e<script>".into())] };
        assert_eq!(write(&doc), "- a\\_b\\*c\\|d\\`e\\<script\\>\n");
    }

    #[test]
    fn tables_keep_their_shape_whatever_the_cells_hold() {
        let doc =
            Doc { blocks: vec![Block::Table { head: vec!["a".into(), "b".into()], rows: vec![vec!["x|y".into(), "line\nbreak".into()]] }] };
        assert_eq!(write(&doc), "| a | b |\n|---|---|\n| x\\|y | line break |\n");
    }
}
