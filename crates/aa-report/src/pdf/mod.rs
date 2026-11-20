//! PDF output, typeset by an embedded Typst.
//!
//! The layout is the fixed template `report.typ`. The report reaches it as one JSON file that
//! only this module can serve, so no text from the report is ever part of Typst source: a hostile
//! file name is a string value to the template, never markup or code. The template's world holds
//! exactly two files and two fonts and refuses everything else — no disk, no packages, no network.
//!
//! The PDF is a reading document. Long lists are cut and say so; report.json and report.html hold
//! everything. The same report always gives the same bytes: no dates, a fixed document id, fonts
//! from the binary.

use std::sync::OnceLock;

use aa_core::{Finding, Report, Section, Severity};
use serde_json::{Value, json};
use typst::diag::{FileError, FileResult, SourceDiagnostic};
use typst::foundations::{Bytes, Datetime, Smart};
use typst::layout::PagedDocument;
use typst::syntax::{FileId, Source, VirtualPath};
use typst::text::{Font, FontBook};
use typst::utils::LazyHash;
use typst::{Library, LibraryExt, World};

use crate::group::{self, Group, Row};
use crate::sanitize::{visible, visible_line};
use crate::words::{self, ui};
use crate::{Lang, RenderError, doc};

/// Entries (a rule's findings as one group, or a single finding) typeset per chapter before the
/// rest are counted.
pub const FINDINGS_PER_CHAPTER: usize = 200;
/// Evidence lines typeset per finding before the rest are counted.
pub const EVIDENCE_PER_FINDING: usize = 5;
/// Characters of a finding's title and of its sentence typeset before they are cut. With the
/// evidence limit, this keeps every finding shorter than a page.
const TITLE_LENGTH: usize = 200;
const TEXT_LENGTH: usize = 1500;
/// Characters of any other single line (a path in the inventory, a limitation) before it is cut.
const LINE_LENGTH: usize = 400;
/// Characters of the input name shown in the running page header.
const HEADER_NAME_LENGTH: usize = 70;

const TEMPLATE: &str = include_str!("report.typ");
const FONT_TEXT: &[u8] = include_bytes!("../../fonts/NotoSansSC-Regular.otf");
const FONT_MONO: &[u8] = include_bytes!("../../fonts/JetBrainsMono-Regular.ttf");

struct Fonts {
    book: LazyHash<FontBook>,
    fonts: Vec<Font>,
}

/// The embedded fonts, parsed once per process.
fn fonts() -> &'static Fonts {
    static FONTS: OnceLock<Fonts> = OnceLock::new();
    FONTS.get_or_init(|| {
        let fonts: Vec<Font> = [FONT_TEXT, FONT_MONO].into_iter().flat_map(|data| Font::iter(Bytes::new(data))).collect();
        Fonts { book: LazyHash::new(FontBook::from_fonts(&fonts)), fonts }
    })
}

/// Everything the template can see: itself, the report data, and fonts.
struct ReportWorld {
    library: LazyHash<Library>,
    main: Source,
    data_id: FileId,
    data: Bytes,
    /// The embedded fonts followed by any the caller added; `None` when only the embedded ones are used.
    extended: Option<Fonts>,
}

impl ReportWorld {
    fn new(data: Vec<u8>, extra: &[Font]) -> Self {
        let main_id = FileId::new(None, VirtualPath::new("/report.typ"));
        let extended = (!extra.is_empty()).then(|| {
            let all: Vec<Font> = fonts().fonts.iter().cloned().chain(extra.iter().cloned()).collect();
            Fonts { book: LazyHash::new(FontBook::from_fonts(&all)), fonts: all }
        });
        ReportWorld {
            library: LazyHash::new(Library::default()),
            main: Source::new(main_id, TEMPLATE.to_string()),
            data_id: FileId::new(None, VirtualPath::new("/report.json")),
            data: Bytes::new(data),
            extended,
        }
    }

    fn fonts(&self) -> &Fonts {
        self.extended.as_ref().unwrap_or_else(|| fonts())
    }
}

impl World for ReportWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &self.fonts().book
    }

    fn main(&self) -> FileId {
        self.main.id()
    }

    fn source(&self, id: FileId) -> FileResult<Source> {
        if id == self.main.id() { Ok(self.main.clone()) } else { Err(FileError::AccessDenied) }
    }

    fn file(&self, id: FileId) -> FileResult<Bytes> {
        if id == self.data_id { Ok(self.data.clone()) } else { Err(FileError::AccessDenied) }
    }

    fn font(&self, index: usize) -> Option<Font> {
        self.fonts().fonts.get(index).cloned()
    }

    /// No clock: a report must not depend on when it was rendered.
    fn today(&self, _offset: Option<i64>) -> Option<Datetime> {
        None
    }
}

fn message(diagnostics: &[SourceDiagnostic]) -> String {
    diagnostics.iter().map(|d| d.message.as_str()).collect::<Vec<_>>().join("; ")
}

/// Typesets `report` into pages. `extra_fonts` are font files tried after the embedded ones, for
/// characters those do not cover.
fn compile(report: &Report, lang: Lang, extra_fonts: &[Vec<u8>]) -> Result<PagedDocument, RenderError> {
    let mut extra: Vec<Font> = Vec::new();
    for (index, data) in extra_fonts.iter().enumerate() {
        let parsed: Vec<Font> = Font::iter(Bytes::new(data.clone())).collect();
        if parsed.is_empty() {
            return Err(RenderError::Pdf(format!("extra font {} is not a font file this program can read", index + 1)));
        }
        extra.extend(parsed);
    }
    // Family names in the order given, each once; the template appends them to its font lists.
    let mut families: Vec<String> = Vec::new();
    for font in &extra {
        if !families.contains(&font.info().family) {
            families.push(font.info().family.clone());
        }
    }
    let mut data = view(report, lang);
    data["extra_fonts"] = json!(families);
    let world = ReportWorld::new(serde_json::to_vec(&data)?, &extra);
    typst::compile::<PagedDocument>(&world).output.map_err(|errors| RenderError::Pdf(message(&errors)))
}

/// Renders `report` as a PDF in `lang`.
pub fn render(report: &Report, lang: Lang) -> Result<Vec<u8>, RenderError> {
    render_with_fonts(report, lang, &[])
}

/// Renders `report` as a PDF in `lang`, falling back to `extra_fonts` for characters the embedded
/// fonts lack. The output then depends on those font files as well as on the report.
pub fn render_with_fonts(report: &Report, lang: Lang, extra_fonts: &[Vec<u8>]) -> Result<Vec<u8>, RenderError> {
    let result = compile(report, lang, extra_fonts).and_then(|document| {
        let options = typst_pdf::PdfOptions {
            // A fixed identifier and no timestamp: the bytes depend on the report alone.
            ident: Smart::Custom("analyze-anything-report"),
            timestamp: None,
            ..Default::default()
        };
        typst_pdf::pdf(&document, &options).map_err(|errors| RenderError::Pdf(message(&errors)))
    });
    // Typst keeps what it computed for the next compilation; a report is rendered once.
    typst::comemo::evict(0);
    result
}

fn cut(text: &str, length: usize) -> String {
    let mut out: String = text.chars().take(length).collect();
    if text.chars().count() > length {
        out.push('…');
    }
    out
}

/// Characters in a row without a place to break the line before the row is split.
const UNBROKEN_RUN: usize = 16;
/// Characters between two break points inside a split row.
const PIECE_LENGTH: usize = 8;

/// True for characters a line never needs help breaking at: spaces, and CJK text, which may break
/// between any two characters.
fn breaks_itself(c: char) -> bool {
    c.is_whitespace() || c >= '\u{2e80}'
}

/// True for marks that attach to the character before them and must stay with it.
fn is_combining(c: char) -> bool {
    matches!(c, '\u{0300}'..='\u{036f}' | '\u{1ab0}'..='\u{1aff}' | '\u{1dc0}'..='\u{1dff}' | '\u{20d0}'..='\u{20ff}')
}

/// Splits `text` into pieces between which the template allows a line break.
///
/// Hashes and paths have no spaces, and Typst would let them run off the page. Marking the break
/// points with zero-width spaces would put those characters into the PDF's text, so a search for
/// a hash would fail; pieces joined by gaps too small to see leave the text as it is. Only long
/// rows of characters without a natural break are split.
fn pieces(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut piece = String::new();
    let mut i = 0;
    while i < chars.len() {
        if breaks_itself(chars[i]) {
            piece.push(chars[i]);
            i += 1;
            continue;
        }
        let end = chars[i..].iter().position(|c| breaks_itself(*c)).map_or(chars.len(), |n| i + n);
        if end - i <= UNBROKEN_RUN {
            piece.extend(&chars[i..end]);
        } else {
            // Break after separators where there are any; where a stretch has none (a hash), every
            // few characters.
            let mut since_break = 0;
            let mut since_separator = 0;
            for (j, c) in chars[i..end].iter().enumerate() {
                piece.push(*c);
                since_break += 1;
                since_separator += 1;
                let at_separator = matches!(c, '/' | '\\' | '.' | '_' | '-' | '=' | ':' | ',' | ';' | '@' | '&' | '?' | '+' | '%' | '|');
                if at_separator {
                    since_separator = 0;
                }
                let next = chars.get(i + j + 1).copied().filter(|_| i + j + 1 < end);
                let wanted = (at_separator && since_break >= 2) || (since_separator >= UNBROKEN_RUN && since_break >= PIECE_LENGTH);
                if wanted && next.is_some_and(|n| !is_combining(n)) {
                    out.push(std::mem::take(&mut piece));
                    since_break = 0;
                }
            }
        }
        i = end;
    }
    if !piece.is_empty() {
        out.push(piece);
    }
    out
}

/// Report text for a single line of the template: deceptive characters shown, break points marked.
fn line(text: &str) -> Value {
    json!(pieces(&visible_line(text)))
}

/// Report text that may hold line breaks of its own.
fn prose(text: &str) -> Value {
    json!(pieces(&visible(text)))
}

fn pairs(items: Vec<(String, String)>) -> Value {
    items.into_iter().map(|(label, value)| json!([label, line(&value)])).collect()
}

fn finding_view(report: &Report, lang: Lang, finding: &Finding) -> Value {
    let evidence: Vec<Value> = finding.evidence.iter().take(EVIDENCE_PER_FINDING).map(|e| line(&doc::evidence_line(e))).collect();
    let more = finding.evidence.len().saturating_sub(EVIDENCE_PER_FINDING);
    json!({
        "group": false,
        "severity": words::severity_key(finding.severity),
        "severity_label": words::severity(lang, finding.severity),
        "confidence": words::confidence_key(finding.confidence),
        "confidence_label": words::confidence(lang, finding.confidence),
        "title": line(&cut(&doc::rule_title(report, lang, &finding.rule), TITLE_LENGTH)),
        "text": prose(&cut(&doc::finding_text(report, lang, finding), TEXT_LENGTH)),
        "evidence": evidence,
        "more_evidence": (more > 0).then(|| ui(lang, "more_evidence").replace("{n}", &more.to_string())),
        "references": line(&cut(&finding.references.join(", "), LINE_LENGTH)),
        "id": line(&finding.id.chars().take(16).collect::<String>()),
    })
}

/// A group of several findings: its head and the rows the reading formats list.
fn group_view(lang: Lang, group: &Group) -> Value {
    let listing = group::listing(group);
    let rows: Vec<Value> = listing
        .rows
        .iter()
        .map(|row| match row {
            Row::Single { subject, text } => json!({
                "subject": line(subject.as_deref().unwrap_or(ui(lang, "subject_none"))),
                "text": prose(&cut(text, TEXT_LENGTH)),
                "subjects": Value::Null,
            }),
            Row::Shared { text, count, subjects, cut: cut_short } => json!({
                "subject": Value::Null,
                "text": prose(&cut(text, TEXT_LENGTH)),
                "note": group::shared_note(lang, *count),
                "subjects": line(&format!("{}{}", subjects.join(", "), if *cut_short { " …" } else { "" })),
            }),
        })
        .collect();
    json!({
        "group": true,
        "severity": words::severity_key(group.severity),
        "label": group::label(lang, group),
        "title": line(&cut(&group.title, TITLE_LENGTH)),
        "count": words::agree(&ui(lang, "group_count").replace("{n}", &group::thousands(group.count))),
        "rows": rows,
        "not_shown": (listing.not_shown > 0).then(|| group::not_shown_note(lang, listing.not_shown)),
    })
}

/// A chapter: its heading with both counts and its first [`FINDINGS_PER_CHAPTER`] entries.
fn chapter_view(report: &Report, lang: Lang, title: &str, groups: &[Group]) -> Value {
    let note = (groups.len() > FINDINGS_PER_CHAPTER).then(|| {
        ui(lang, "pdf_findings_capped").replace("{n}", &groups.len().to_string()).replace("{m}", &FINDINGS_PER_CHAPTER.to_string())
    });
    let entries: Vec<Value> = groups
        .iter()
        .take(FINDINGS_PER_CHAPTER)
        .map(|group| match (group.count, group.instances().next()) {
            (1, Some(only)) => finding_view(report, lang, only.finding),
            _ => group_view(lang, group),
        })
        .collect();
    json!({ "title": group::heading(lang, title, groups), "count": groups.len(), "note": note, "findings": entries })
}

/// The report as the template reads it: every string already worded, cut and made safe to show.
fn view(report: &Report, lang: Lang) -> Value {
    let w = words::words(lang);
    let count = |severity: Severity| report.findings.iter().filter(|f| f.severity == severity).count();
    let chapters: Vec<Value> = Section::ALL
        .into_iter()
        .map(|section| chapter_view(report, lang, words::section(lang, section), &group::chapter(report, lang, section)))
        .collect();
    let attention = group::attention(report, lang);
    let mut attention_view = chapter_view(report, lang, ui(lang, "attention"), &attention);
    attention_view["text"] = json!(ui(lang, if attention.is_empty() { "attention_none" } else { "attention_text" }));
    let severities: Vec<Value> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .into_iter()
        .map(|s| json!({ "key": words::severity_key(s), "label": words::severity(lang, s), "count": count(s) }))
        .collect();
    let inventory = doc::inventory(report, lang);
    let inventory_rows: Vec<Vec<Value>> =
        inventory.rows.iter().map(|row| row.iter().map(|cell| line(&cut(cell, LINE_LENGTH))).collect()).collect();
    let limitations: Vec<Value> = doc::limitation_groups(report, lang)
        .into_iter()
        .map(|group| {
            json!({
                "title": line(&cut(&group.title, TITLE_LENGTH)),
                "text": prose(&cut(&group.text, TEXT_LENGTH)),
                "items": group.items.iter().map(|item| line(&cut(item, LINE_LENGTH))).collect::<Vec<_>>(),
                "more": group.more,
            })
        })
        .collect();
    json!({
        "lang": match lang { Lang::Zh => "zh", Lang::En => "en" },
        "words": {
            "title": w.title,
            "summary": w.summary,
            "contents": ui(lang, "contents"),
            "reading_guide": w.reading_guide,
            "reading_guide_text": w.reading_guide_text,
            "grouping_guide": ui(lang, "grouping_guide"),
            "scope": ui(lang, "pdf_scope"),
            "no_findings_here": w.no_findings_here,
            "evidence": w.evidence,
            "references": w.references,
            "finding_id": w.finding_id,
            "inventory": w.inventory,
            "coverage": w.coverage,
            "no_limitations": w.no_limitations,
            "generated_by": w.generated_by,
        },
        "document_title": format!("{}: {}", w.title, visible_line(&report.input.name)),
        "input_name": line(&cut(&report.input.name, TITLE_LENGTH)),
        "header_name": line(&cut(&report.input.name, HEADER_NAME_LENGTH)),
        "tool": line(&format!("{} {}", report.tool.name, report.tool.version)),
        "project": crate::credit(),
        "header": pairs(doc::header_items(report, lang)),
        "summary": pairs(doc::summary_items(report, lang)),
        "severities": severities,
        "attention": attention_view,
        "chapters": chapters,
        "inventory": {
            "head": inventory.head,
            "rows": inventory_rows,
            "note": inventory.note,
        },
        "coverage": {
            "truncated": report.coverage.truncated,
            "status": if report.coverage.truncated { w.truncated } else { w.complete },
            "limitations": limitations,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aa_core::{Artifact, Confidence, Coverage, Evidence, Input, InputKind, RuleText, Tool};
    use typst::layout::{Frame, FrameItem};

    use super::*;

    fn artifact(path: &str) -> Artifact {
        Artifact {
            path: path.to_string(),
            parent: None,
            size: 3,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn report(name: &str, artifacts: Vec<Artifact>, findings: Vec<Finding>) -> Report {
        let text =
            RuleText {
                title_zh: "标题".into(), title_en: "Title".into(), text_zh: "看到 {what}。".into(), text_en: "Saw {what}.".into()
            };
        Report {
            schema_version: aa_core::SCHEMA_VERSION,
            tool: Tool { name: "analyze-anything".into(), version: "0.0.1".into() },
            input: Input { name: name.to_string(), kind: InputKind::File, sha256: Some("ab".repeat(32)) },
            summary: BTreeMap::new(),
            coverage: Coverage {
                artifacts_total: artifacts.len() as u64,
                artifacts_analyzed: artifacts.len() as u64,
                ..Default::default()
            },
            artifacts,
            findings,
            limitations: Vec::new(),
            rules: BTreeMap::from([("test.rule".to_string(), text)]),
        }
    }

    fn finding(artifact: &Artifact, section: Section, severity: Severity, what: &str) -> Finding {
        Finding::new(section, "test", "test.rule", Confidence::Heuristic, severity)
            .param("what", what)
            .evidence(Evidence::field(artifact, what, what))
            .seal()
    }

    fn frame_text(frame: &Frame, out: &mut String) {
        for (_, item) in frame.items() {
            match item {
                FrameItem::Text(text) => out.push_str(&text.text),
                FrameItem::Group(group) => frame_text(&group.frame, out),
                _ => {}
            }
        }
    }

    /// Everything the pages show, in drawing order, with nothing between the pieces.
    fn typeset(report: &Report, lang: Lang) -> (usize, String) {
        let document = compile(report, lang, &[]).expect("the report typesets");
        let mut text = String::new();
        document.pages.iter().for_each(|page| frame_text(&page.frame, &mut text));
        (document.pages.len(), text.split_whitespace().collect())
    }

    fn squeeze(text: &str) -> String {
        text.split_whitespace().collect()
    }

    #[test]
    fn pieces_put_the_text_back_together() {
        for text in [
            "",
            "short",
            "一段没有空格的中文不需要帮助",
            &"a".repeat(100),
            "dir/sub.dir/file-name_with.parts=1&x",
            "e\u{0301}".repeat(30).as_str(),
        ] {
            let pieces = pieces(text);
            assert_eq!(pieces.concat(), *text);
            assert!(pieces.iter().all(|piece| !piece.is_empty()));
        }
        assert_eq!(pieces("short and usual words"), ["short and usual words"]);
        assert!(pieces(&"f".repeat(64)).iter().all(|piece| piece.chars().count() <= UNBROKEN_RUN));
        assert_eq!(pieces("application/x-executable"), ["application/", "x-", "executable"]);
        assert!(pieces(&"e\u{0301}".repeat(30)).iter().all(|piece| !piece.starts_with('\u{0301}')));
    }

    #[test]
    fn markup_in_report_text_is_typeset_as_the_characters_it_is() {
        let hostile = [
            "#eval(\"1+1\") *bold* _emph_ $x^2$ `raw` <label> @cite",
            "#import \"@preview/cetz:0.3.0\": *",
            "#read(\"/etc/passwd\") #include \"report.json\"",
            "] ) } // /* \\ #panic(\"x\")",
        ];
        let artifacts: Vec<Artifact> = hostile.iter().map(|text| artifact(&format!("dir/{text}"))).collect();
        let findings = artifacts.iter().zip(hostile).map(|(a, text)| finding(a, Section::Anomalies, Severity::High, text)).collect();
        let mut report = report(hostile[0], artifacts, findings);
        report.rules.insert(
            "test.rule".into(),
            RuleText {
                title_zh: hostile[0].into(),
                title_en: hostile[0].into(),
                text_zh: format!("{} {{what}}", hostile[1]),
                text_en: format!("{} {{what}}", hostile[1]),
            },
        );
        report.limitations.push(aa_core::Limitation::new(hostile[2], Some(hostile[3]), Some(hostile[0].into())));
        for lang in [Lang::Zh, Lang::En] {
            let (_, text) = typeset(&report, lang);
            for raw in hostile {
                assert!(text.contains(&squeeze(raw)), "{raw} was not typeset literally");
            }
        }
    }

    #[test]
    fn characters_that_hide_or_reorder_text_are_spelled_out() {
        let file = artifact("evil\u{202e}fdp.exe");
        let findings = vec![finding(&file, Section::Anomalies, Severity::Medium, "a\u{200b}b")];
        let (_, text) = typeset(&report("x\u{2066}y", vec![file], findings), Lang::En);
        assert!(text.contains("evil[U+202E]fdp.exe") && text.contains("a[U+200B]b") && text.contains("x[U+2066]y"));
        assert!(!text.contains(['\u{202e}', '\u{200b}', '\u{2066}']));
    }

    #[test]
    fn both_languages_are_typeset_with_their_own_words() {
        let file = artifact("a.bin");
        let report = report("a.bin", vec![file.clone()], vec![finding(&file, Section::Network, Severity::Low, "x")]);
        let (_, zh) = typeset(&report, Lang::Zh);
        let (_, en) = typeset(&report, Lang::En);
        for word in ["分析报告", "摘要", "目录", "网络与端点", "覆盖度与局限", "看到x。", "启发式"] {
            assert!(zh.contains(word), "no {word} in the Chinese PDF");
        }
        for word in ["Analysisreport", "Contents", "Networkandendpoints", "Coverageandlimitations", "Sawx.", "Heuristic"] {
            assert!(en.contains(word), "no {word} in the English PDF");
        }
        // The page footer counts pages: "1 / n".
        assert!(en.contains("1/"));
    }

    #[test]
    fn a_rule_with_many_findings_is_one_entry_that_says_what_it_leaves_out() {
        let file = artifact("dir/a.bin");
        let mut findings: Vec<Finding> = (0..25).map(|i| finding(&file, Section::Network, Severity::Info, &format!("info-{i}"))).collect();
        findings.push(finding(&file, Section::Network, Severity::High, "the-high-one"));
        let mut report = report("a.bin", vec![file.clone()], findings);
        report.rules.insert("other.rule".into(), report.rules["test.rule"].clone());
        report
            .findings
            .push(Finding::new(Section::Network, "test", "other.rule", Confidence::Verified, Severity::Low).param("what", "alone").seal());
        let view = view(&report, Lang::En);
        let chapter = &view["chapters"][7];
        assert_eq!(chapter["title"], json!("Network and endpoints · 2 kinds / 27 findings"));
        let entries = chapter["findings"].as_array().expect("entries");
        assert_eq!(entries.len(), 2);
        // The group holding a High comes first; with 26 findings it is under the cap of 30.
        assert_eq!(entries[0]["group"], true);
        assert_eq!(entries[0]["severity"], "high");
        assert_eq!(entries[0]["label"], "High × 1 · Info × 25 · Heuristic");
        assert_eq!(entries[0]["rows"].as_array().map(Vec::len), Some(26));
        assert!(entries[0]["not_shown"].is_null());
        // A rule with one finding is typeset as a finding, as before.
        assert_eq!(entries[1]["group"], false);
        assert_eq!(view["attention"]["title"], json!("Needs attention · 2 kinds / 2 findings"));
        assert!(view["chapters"][0]["note"].is_null());

        // A group of neutral facts lists ten and counts the rest.
        report.findings.retain(|f| f.severity == Severity::Info);
        let view = super::view(&report, Lang::En);
        let entry = &view["chapters"][7]["findings"][0];
        assert_eq!(entry["rows"].as_array().map(Vec::len), Some(group::LISTED_INFO));
        assert!(entry["not_shown"].as_str().is_some_and(|note| note.starts_with("15 more")));
        assert_eq!(view["attention"]["findings"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn the_world_serves_nothing_but_the_template_and_the_report() {
        let world = ReportWorld::new(b"{}".to_vec(), &[]);
        let other = FileId::new(None, VirtualPath::new("/etc/passwd"));
        assert!(world.source(other).is_err() && world.file(other).is_err());
        assert!(world.file(world.main()).is_err(), "the template is source, not data");
        assert!(world.source(world.data_id).is_err(), "the data is not source");
        assert!(world.today(None).is_none());
        assert_eq!(fonts().fonts.len(), 2);
    }
}
