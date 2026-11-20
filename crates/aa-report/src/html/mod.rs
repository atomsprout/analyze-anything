//! HTML output: one file that holds the whole report and needs nothing else.
//!
//! The page carries the report twice. As data: the report JSON, plus a small block of view data
//! (the fixed words in both languages and every finding's sentence with its params filled in),
//! from which the script in `app.js` builds the interactive view — filters, search, the file
//! tree, the language switch. And as plain HTML written here from the same [`doc::Doc`] the
//! Markdown and text outputs use, so the report reads the same with scripts off; the script
//! removes that copy once the interactive view is up.
//!
//! Everything in a report is untrusted. Text is HTML-escaped here and reaches the page through
//! text nodes in the script; the embedded JSON is escaped so that it cannot end its `<script>`
//! block; characters that hide or reorder text are shown as code points; and the page's content
//! security policy allows nothing to load and only the shipped style sheet and script to run.

use aa_core::{Finding, Report, Section, Severity};
use serde_json::{Map, Value, json};

use crate::doc::{self, Block};
use crate::group;
use crate::sanitize::{is_deceptive, visible, visible_line};
use crate::words::{self, ui};
use crate::{Lang, RenderError};

const TEMPLATE: &str = include_str!("template.html");
const STYLE: &str = include_str!("style.css");
const SCRIPT: &str = include_str!("app.js");

/// Renders `report` as a self-contained HTML page that opens in `lang`.
pub fn render(report: &Report, lang: Lang) -> Result<String, RenderError> {
    // A browser reads CRLF inside <style> and <script> as LF; hash what it will see.
    let style = STYLE.replace("\r\n", "\n");
    let script = SCRIPT.replace("\r\n", "\n");
    let title = format!("{}: {}", words::words(lang).title, visible_line(&report.input.name));
    let parts = [
        ("html_lang", lang_tag(lang).to_string()),
        ("title", escape(&title)),
        ("generator", escape(&visible_line(&format!("{} {}", report.tool.name, report.tool.version)))),
        ("style_hash", csp_hash(&style)),
        ("script_hash", csp_hash(&script)),
        ("noscript", escape(ui(lang, "noscript"))),
        ("script_failed", escape(ui(lang, "script_failed"))),
        ("static", static_content(report, lang)),
        ("report", embed(&serde_json::to_string(report)?)),
        ("view", embed(&serde_json::to_string(&view(report, lang)?)?)),
        ("style", style),
        ("script", script),
    ];
    Ok(fill_template(&parts))
}

fn lang_tag(lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => "zh-CN",
        Lang::En => "en",
    }
}

fn lang_key(lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => "zh",
        Lang::En => "en",
    }
}

/// Replaces each `{{name}}` of the template in one pass, so a value that happens to contain
/// `{{…}}` is never looked at again.
fn fill_template(parts: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(TEMPLATE.len() + parts.iter().map(|(_, value)| value.len()).sum::<usize>());
    let mut rest = TEMPLATE;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            rest = after;
            continue;
        };
        if let Some((_, value)) = parts.iter().find(|(name, _)| *name == &after[..close]) {
            out.push_str(value);
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

/// Text for an HTML text node or a quoted attribute value.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 8);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// JSON for a `<script type="application/json">` block.
///
/// `<`, `>` and `&` are written as `\uXXXX`, so the data can never close its script element, open
/// a comment or be read as markup; so are the line separators U+2028/2029 and every character
/// that hides or reorders text, so the file itself holds none of them. All of these can only
/// occur inside JSON strings, where `\uXXXX` means the same character.
fn embed(json: &str) -> String {
    let mut out = String::with_capacity(json.len() + json.len() / 16);
    let mut units = [0u16; 2];
    for c in json.chars() {
        if matches!(c, '<' | '>' | '&') || (is_deceptive(c) && !c.is_ascii()) {
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The `'sha256-…'` source that lets exactly this inline style sheet or script through the policy.
fn csp_hash(content: &str) -> String {
    let hex = aa_core::sha256_hex(content.as_bytes());
    let digest: Vec<u8> = (0..hex.len() / 2).filter_map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()).collect();
    format!("sha256-{}", base64(&digest))
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The report as plain HTML, from the same document the Markdown and text outputs are written
/// from. This is what a reader sees with scripts off, and what stays if the script fails.
fn static_content(report: &Report, lang: Lang) -> String {
    let text = |text: &str| escape(&visible(text));
    let mut out = String::new();
    // Number of lists open; an item at level n sits in list n + 1.
    let mut depth = 0usize;
    for block in &doc::build(report, lang).blocks {
        let target = match block {
            Block::Item(level, _) => *level as usize + 1,
            _ => 0,
        };
        while depth > target {
            out.push_str("</li></ul>\n");
            depth -= 1;
        }
        match block {
            Block::Heading(level, heading) => {
                let level = (*level).clamp(1, 6);
                out.push_str(&format!("<h{level}>{}</h{level}>\n", text(heading)));
            }
            Block::Paragraph(paragraph) => out.push_str(&format!("<p>{}</p>\n", text(paragraph))),
            Block::Item(_, item) => {
                if depth == target {
                    out.push_str("</li>\n");
                }
                while depth < target {
                    out.push_str("<ul>");
                    depth += 1;
                }
                out.push_str(&format!("<li>{}", text(item)));
            }
            Block::Table { head, rows } => {
                out.push_str("<div class=\"tablewrap\"><table><thead><tr>");
                head.iter().for_each(|cell| out.push_str(&format!("<th>{}</th>", text(cell))));
                out.push_str("</tr></thead><tbody>\n");
                for row in rows {
                    out.push_str("<tr>");
                    row.iter().for_each(|cell| out.push_str(&format!("<td>{}</td>", text(cell))));
                    out.push_str("</tr>\n");
                }
                out.push_str("</tbody></table></div>\n");
            }
        }
    }
    while depth > 0 {
        out.push_str("</li></ul>\n");
        depth -= 1;
    }
    out
}

/// Every fixed word of the page in `lang`, by key.
fn page_words(lang: Lang) -> Result<Value, RenderError> {
    let mut map = match serde_json::to_value(words::words(lang))? {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    for (key, _, _) in words::UI {
        map.insert((*key).to_string(), json!(ui(lang, key)));
    }
    let sections: Map<String, Value> =
        Section::ALL.into_iter().map(|s| (words::section_key(s).to_string(), json!(words::section(lang, s)))).collect();
    let severities: Map<String, Value> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .into_iter()
        .map(|s| (words::severity_key(s).to_string(), json!(words::severity(lang, s))))
        .collect();
    let confidences: Map<String, Value> = [aa_core::Confidence::Verified, aa_core::Confidence::Derived, aa_core::Confidence::Heuristic]
        .into_iter()
        .map(|c| (words::confidence_key(c).to_string(), json!(words::confidence(lang, c))))
        .collect();
    map.insert("sections".into(), Value::Object(sections));
    map.insert("severities".into(), Value::Object(severities));
    map.insert("confidences".into(), Value::Object(confidences));
    map.insert(
        "input_kinds".into(),
        json!({
            "file": words::input_kind(lang, aa_core::InputKind::File),
            "directory": words::input_kind(lang, aa_core::InputKind::Directory),
        }),
    );
    Ok(Value::Object(map))
}

/// What the script needs besides the report itself.
///
/// The sentences of the findings are filled in here rather than in the script, and numbers a
/// script cannot hold exactly are carried as text, so the page shows the same characters as the
/// other outputs: JavaScript would print `8.0` as `8` and round integers above 2^53.
fn view(report: &Report, lang: Lang) -> Result<Value, RenderError> {
    let texts: Vec<Value> =
        report.findings.iter().map(|f| json!([doc::finding_text(report, Lang::Zh, f), doc::finding_text(report, Lang::En, f)])).collect();
    let mut values = Map::new();
    for (index, finding) in report.findings.iter().enumerate() {
        if let Some(shown) = evidence_values(finding) {
            values.insert(index.to_string(), shown);
        }
    }
    let mut exact = Map::new();
    for (key, value) in &report.summary {
        exact_numbers(value, &mut pointer("s", key), &mut exact);
    }
    for (index, artifact) in report.artifacts.iter().enumerate() {
        for (key, value) in &artifact.facts {
            exact_numbers(value, &mut pointer(&format!("a{index}"), key), &mut exact);
        }
    }
    // What the script needs to show the findings of a rule as one entry exactly as the other
    // outputs do: each finding's shortened subject. The order comes from the report itself.
    let mut subjects = vec![Value::Null; report.findings.len()];
    for section in Section::ALL {
        for group in group::chapter(report, lang, section) {
            for instance in group.instances() {
                subjects[instance.index] = json!(instance.subject);
            }
        }
    }
    Ok(json!({
        "lang": lang_key(lang),
        "subjects": subjects,
        "words": { "zh": page_words(Lang::Zh)?, "en": page_words(Lang::En)? },
        "texts": texts,
        "values": values,
        "exact": exact,
        "inventory_rows": doc::INVENTORY_ROWS,
        // The closing line: its words in both languages and the tool's address, or nothing.
        "credit": crate::credit().map(|url| json!({ "zh": words::words(Lang::Zh).generated_by, "en": words::words(Lang::En).generated_by, "url": url })),
    }))
}

/// The evidence values of `finding` that are not strings, as the JSON text the report holds;
/// `None` when every value is a string and the script can show them as they are.
fn evidence_values(finding: &Finding) -> Option<Value> {
    if finding.evidence.iter().all(|e| e.value.is_string()) {
        return None;
    }
    Some(finding.evidence.iter().map(|e| if e.value.is_string() { Value::Null } else { json!(e.value.to_string()) }).collect())
}

/// `base` extended by `key`, written like a JSON pointer.
fn pointer(base: &str, key: &str) -> String {
    format!("{base}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// Records, by pointer, the text of every number under `value` that JavaScript would show
/// differently: integers beyond ±2^53 and floats it prints in another form.
fn exact_numbers(value: &Value, at: &mut String, out: &mut Map<String, Value>) {
    const SAFE: u64 = 1 << 53;
    match value {
        Value::Number(number) => {
            let differs = if let Some(unsigned) = number.as_u64() {
                unsigned > SAFE
            } else if let Some(signed) = number.as_i64() {
                signed.unsigned_abs() > SAFE
            } else {
                number.as_f64().is_some_and(|f| f.fract() == 0.0 || f.abs() >= 1e15 || f.abs() < 1e-4)
            };
            if differs {
                out.insert(at.clone(), json!(number.to_string()));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let length = at.len();
                at.push_str(&format!("/{index}"));
                exact_numbers(item, at, out);
                at.truncate(length);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                let mut next = pointer(at, key);
                exact_numbers(item, &mut next, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn embedded_json_cannot_leave_its_script_block() {
        let json = serde_json::to_string(&json!({ "a": "</script><!-- & \u{2028}\u{202e}\u{e0041}" })).expect("json");
        let embedded = embed(&json);
        assert!(!embedded.contains('<') && !embedded.contains('>') && !embedded.contains('&'));
        assert!(!embedded.chars().any(|c| is_deceptive(c) && !c.is_ascii()));
        let back: Value = serde_json::from_str(&embedded).expect("still JSON");
        assert_eq!(back["a"], "</script><!-- & \u{2028}\u{202e}\u{e0041}");
    }

    #[test]
    fn the_shipped_style_and_script_cannot_end_their_own_element() {
        assert!(!STYLE.to_ascii_lowercase().contains("</style"));
        assert!(!SCRIPT.to_ascii_lowercase().contains("</script"));
        assert!(!SCRIPT.contains("<!--"));
    }

    #[test]
    fn the_script_never_writes_markup_or_runs_text() {
        for forbidden in ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "srcdoc"] {
            // The header comment names what the script does not use.
            let code: String = SCRIPT.lines().filter(|line| !line.trim_start().starts_with(['*', '/'])).collect::<Vec<_>>().join("\n");
            assert!(!code.contains(forbidden), "app.js uses {forbidden}");
        }
    }

    #[test]
    fn every_word_the_script_asks_for_exists_in_both_languages() {
        let zh = page_words(Lang::Zh).expect("words");
        let en = page_words(Lang::En).expect("words");
        let mut rest = SCRIPT;
        let mut asked = 0;
        while let Some(at) = rest.find("t('") {
            let after = &rest[at + 3..];
            let key = &after[..after.find('\'').expect("closing quote")];
            let preceded_by_name = rest[..at].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_');
            if !preceded_by_name {
                assert!(zh.get(key).is_some_and(Value::is_string), "no zh word for {key}");
                assert!(en.get(key).is_some_and(Value::is_string), "no en word for {key}");
                asked += 1;
            }
            rest = after;
        }
        assert!(asked > 50);
    }

    #[test]
    fn numbers_javascript_would_change_are_kept_as_text() {
        let mut out = Map::new();
        let value = json!({ "a/b": [1, 1.5, 8.0, 18446744073709551615u64, { "n": -9007199254740993i64 }] });
        exact_numbers(&value, &mut String::from("s"), &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(out["s/a~1b/2"], "8.0");
        assert_eq!(out["s/a~1b/3"], "18446744073709551615");
        assert_eq!(out["s/a~1b/4/n"], "-9007199254740993");
    }
}
