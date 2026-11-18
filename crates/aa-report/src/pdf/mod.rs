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

use crate::sanitize::{visible, visible_line};
use crate::words::{self, ui};
use crate::{Lang, RenderError, doc};

/// Findings typeset per chapter before the rest are counted.
pub const FINDINGS_PER_CHAPTER: usize = 200;
/// Evidence lines typeset per finding before the rest are counted.
pub const EVIDENCE_PER_FINDING: usize = 5;
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

/// Everything the template can see: itself and the report data.
struct ReportWorld {
    library: LazyHash<Library>,
    main: Source,
    data_id: FileId,
    data: Bytes,
}

impl ReportWorld {
    fn new(data: Vec<u8>) -> Self {
        let main_id = FileId::new(None, VirtualPath::new("/report.typ"));
        ReportWorld {
            library: LazyHash::new(Library::default()),
            main: Source::new(main_id, TEMPLATE.to_string()),
            data_id: FileId::new(None, VirtualPath::new("/report.json")),
            data: Bytes::new(data),
        }
    }
}

impl World for ReportWorld {
    fn library(&self) -> &LazyHash<Library> {
        &self.library
    }

    fn book(&self) -> &LazyHash<FontBook> {
        &fonts().book
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
        fonts().fonts.get(index).cloned()
    }

    /// No clock: a report must not depend on when it was rendered.
    fn today(&self, _offset: Option<i64>) -> Option<Datetime> {
        None
    }
}

fn message(diagnostics: &[SourceDiagnostic]) -> String {
    diagnostics.iter().map(|d| d.message.as_str()).collect::<Vec<_>>().join("; ")
}

/// Renders `report` as a PDF in `lang`.
pub fn render(report: &Report, lang: Lang) -> Result<Vec<u8>, RenderError> {
    let world = ReportWorld::new(serde_json::to_vec(&view(report, lang))?);
    let compiled = typst::compile::<PagedDocument>(&world).output;
    let result = compiled.map_err(|errors| RenderError::Pdf(message(&errors))).and_then(|document| {
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

fn pairs(items: Vec<(String, String)>) -> Value {
    items.into_iter().map(|(label, value)| json!([label, visible_line(&value)])).collect()
}

/// Findings of `section`, most severe first, otherwise in report order.
pub(crate) fn chapter_findings(report: &Report, section: Section) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = report.findings.iter().filter(|f| f.section == section).collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

fn finding_view(report: &Report, lang: Lang, finding: &Finding) -> Value {
    let evidence: Vec<String> =
        finding.evidence.iter().take(EVIDENCE_PER_FINDING).map(|e| visible_line(&doc::evidence_line(e)).into_owned()).collect();
    let more = finding.evidence.len().saturating_sub(EVIDENCE_PER_FINDING);
    json!({
        "severity": words::severity_key(finding.severity),
        "severity_label": words::severity(lang, finding.severity),
        "confidence": words::confidence_key(finding.confidence),
        "confidence_label": words::confidence(lang, finding.confidence),
        "title": visible_line(&doc::rule_title(report, lang, &finding.rule)),
        "text": visible(&doc::finding_text(report, lang, finding)),
        "evidence": evidence,
        "more_evidence": (more > 0).then(|| ui(lang, "more_evidence").replace("{n}", &more.to_string())),
        "references": visible_line(&finding.references.join(", ")),
        "id": visible_line(&finding.id.chars().take(16).collect::<String>()),
    })
}

/// The report as the template reads it: every string already worded, cut and made safe to show.
fn view(report: &Report, lang: Lang) -> Value {
    let w = words::words(lang);
    let count = |severity: Severity| report.findings.iter().filter(|f| f.severity == severity).count();
    let chapters: Vec<Value> = Section::ALL
        .into_iter()
        .map(|section| {
            let findings = chapter_findings(report, section);
            let note = (findings.len() > FINDINGS_PER_CHAPTER).then(|| {
                ui(lang, "pdf_findings_capped")
                    .replace("{n}", &findings.len().to_string())
                    .replace("{m}", &FINDINGS_PER_CHAPTER.to_string())
            });
            json!({
                "title": words::section(lang, section),
                "count": findings.len(),
                "note": note,
                "findings": findings.iter().take(FINDINGS_PER_CHAPTER).map(|f| finding_view(report, lang, f)).collect::<Vec<_>>(),
            })
        })
        .collect();
    let severities: Vec<Value> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .into_iter()
        .map(|s| json!({ "key": words::severity_key(s), "label": words::severity(lang, s), "count": count(s) }))
        .collect();
    let inventory = doc::inventory(report, lang);
    let inventory_rows: Vec<Vec<String>> =
        inventory.rows.iter().map(|row| row.iter().map(|cell| visible_line(cell).into_owned()).collect()).collect();
    let limitations: Vec<Value> = doc::limitation_groups(report, lang)
        .into_iter()
        .map(|group| {
            json!({
                "title": visible_line(&group.title),
                "text": visible(&group.text),
                "items": group.items.iter().map(|item| visible_line(item).into_owned()).collect::<Vec<_>>(),
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
            "scope": ui(lang, "pdf_scope"),
            "no_findings_here": w.no_findings_here,
            "evidence": w.evidence,
            "references": w.references,
            "finding_id": w.finding_id,
            "inventory": w.inventory,
            "coverage": w.coverage,
            "no_limitations": w.no_limitations,
        },
        "input_name": visible_line(&report.input.name),
        "header_name": visible_line(&cut(&report.input.name, HEADER_NAME_LENGTH)),
        "tool": visible_line(&format!("{} {}", report.tool.name, report.tool.version)),
        "header": pairs(doc::header_items(report, lang)),
        "summary": pairs(doc::summary_items(report, lang)),
        "severities": severities,
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
