//! The report as a sequence of headings, paragraphs, lists and tables, before any markup.
//!
//! Every text renderer writes this same document, so the formats cannot drift apart.

use aa_core::{Finding, Limitation, Location, Report, Section, Severity, fill};

use crate::Lang;
use crate::words::{self, Words};

/// Rows shown in the inventory table. The JSON report always holds every file.
pub const INVENTORY_ROWS: usize = 300;
/// Artifacts listed under one limitation before the rest are counted.
const LIMITATION_ARTIFACTS: usize = 30;
/// Characters of an evidence value shown before it is cut.
const VALUE_LENGTH: usize = 160;

#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    /// A heading; level 1 is the document title.
    Heading(u8, String),
    Paragraph(String),
    /// A list item; level 0 is the outermost.
    Item(u8, String),
    Table {
        head: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Doc {
    pub blocks: Vec<Block>,
}

impl Doc {
    fn heading(&mut self, level: u8, text: impl Into<String>) {
        self.blocks.push(Block::Heading(level, text.into()));
    }

    fn paragraph(&mut self, text: impl Into<String>) {
        self.blocks.push(Block::Paragraph(text.into()));
    }

    fn item(&mut self, level: u8, text: impl Into<String>) {
        self.blocks.push(Block::Item(level, text.into()));
    }
}

/// The title of a rule or limitation code in `lang`; the id itself when the report has no text for it.
pub fn rule_title(report: &Report, lang: Lang, id: &str) -> String {
    match (report.rules.get(id), lang) {
        (Some(rule), Lang::Zh) => rule.title_zh.clone(),
        (Some(rule), Lang::En) => rule.title_en.clone(),
        (None, _) => id.to_string(),
    }
}

/// The sentence of a finding in `lang`, with its params filled in.
pub fn finding_text(report: &Report, lang: Lang, finding: &Finding) -> String {
    match (report.rules.get(&finding.rule), lang) {
        (Some(rule), Lang::Zh) => fill(&rule.text_zh, &finding.params),
        (Some(rule), Lang::En) => fill(&rule.text_en, &finding.params),
        (None, _) => aa_core::canonical_json(&finding.params),
    }
}

/// The sentence of a limitation code in `lang`.
pub fn limitation_text(report: &Report, lang: Lang, code: &str) -> String {
    match (report.rules.get(code), lang) {
        (Some(rule), Lang::Zh) => rule.text_zh.clone(),
        (Some(rule), Lang::En) => rule.text_en.clone(),
        (None, _) => String::new(),
    }
}

/// One line for a piece of evidence: where it was read and what was there.
pub fn evidence_line(evidence: &aa_core::Evidence) -> String {
    let place = match &evidence.location {
        Location::Bytes { offset, length } => format!(" @ {offset}+{length}"),
        Location::Field(field) => format!(" @ {field}"),
        Location::Whole => String::new(),
    };
    let value = match &evidence.value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let mut shown: String = value.chars().take(VALUE_LENGTH).map(|c| if c.is_control() { ' ' } else { c }).collect();
    if value.chars().count() > VALUE_LENGTH {
        shown.push('…');
    }
    format!("{}{place} = {shown}", evidence.artifact)
}

pub fn build(report: &Report, lang: Lang) -> Doc {
    let w = words::words(lang);
    let mut doc = Doc::default();
    doc.heading(1, format!("{}: {}", w.title, report.input.name));
    doc.item(0, format!("{}: {} {}", w.tool, report.tool.name, report.tool.version));
    let input_sha256 = match (&report.input.sha256, report.input.kind) {
        (Some(sha256), _) => sha256.clone(),
        (None, aa_core::InputKind::Directory) => w.not_applicable.to_string(),
        (None, aa_core::InputKind::File) => w.unknown.to_string(),
    };
    doc.item(0, format!("{}: {input_sha256}", w.input_sha256));

    doc.heading(2, w.summary);
    doc.item(0, format!("{}: {}", w.input, words::input_kind(lang, report.input.kind)));
    doc.item(0, format!("{}: {} / {}", w.artifacts, report.coverage.artifacts_analyzed, report.coverage.artifacts_total));
    doc.item(0, format!("{}: {}", w.containers, report.coverage.containers_unpacked));
    doc.item(0, format!("{}: {}", w.bytes_read, report.coverage.bytes_analyzed));
    let count = |severity| report.findings.iter().filter(|f| f.severity == severity).count();
    let by_severity = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .map(|s| format!("{} {}", words::severity(lang, s), count(s)))
        .join(" · ");
    doc.item(0, format!("{}: {} ({}: {by_severity})", w.findings, report.findings.len(), w.by_severity));
    doc.heading(3, w.reading_guide);
    doc.paragraph(w.reading_guide_text);

    for section in Section::ALL {
        doc.heading(2, words::section(lang, section));
        let findings: Vec<&Finding> = report.findings.iter().filter(|f| f.section == section).collect();
        if findings.is_empty() {
            doc.paragraph(w.no_findings_here);
        }
        for finding in findings {
            finding_blocks(&mut doc, report, lang, &w, finding);
        }
    }

    doc.heading(2, w.inventory);
    let rows = report
        .artifacts
        .iter()
        .take(INVENTORY_ROWS)
        .map(|a| {
            let kind = match (&a.kind, &a.detected) {
                (Some(kind), Some(detected)) => format!("{kind} ({})", detected.mime),
                (Some(kind), None) => kind.clone(),
                (None, Some(detected)) => detected.mime.clone(),
                (None, None) => w.unknown.to_string(),
            };
            vec![
                a.path.clone(),
                a.size.to_string(),
                kind,
                a.entropy.map(|e| format!("{e:.4}")).unwrap_or(w.unknown.to_string()),
                a.digests.as_ref().map(|d| d.sha256.clone()).unwrap_or(w.unknown.to_string()),
            ]
        })
        .collect();
    let head = [w.path, w.size, w.kind, w.entropy, "SHA-256"].map(str::to_string).to_vec();
    doc.blocks.push(Block::Table { head, rows });
    if report.artifacts.len() > INVENTORY_ROWS {
        doc.paragraph(match lang {
            Lang::Zh => format!("上表只列出前 {INVENTORY_ROWS} 个文件，共 {} 个；完整清单见 report.json。", report.artifacts.len()),
            Lang::En => {
                format!("The table shows the first {INVENTORY_ROWS} of {} files; report.json lists them all.", report.artifacts.len())
            }
        });
    }

    doc.heading(2, w.coverage);
    doc.paragraph(if report.coverage.truncated { w.truncated } else { w.complete });
    if report.limitations.is_empty() {
        doc.paragraph(w.no_limitations);
    }
    let mut codes: Vec<&str> = report.limitations.iter().map(|l| l.code.as_str()).collect();
    codes.dedup();
    codes.sort();
    codes.dedup();
    for code in codes {
        let of_code: Vec<&Limitation> = report.limitations.iter().filter(|l| l.code == code).collect();
        doc.heading(3, format!("{} ({})", rule_title(report, lang, code), of_code.len()));
        let text = limitation_text(report, lang, code);
        if !text.is_empty() {
            doc.paragraph(text);
        }
        for limitation in of_code.iter().take(LIMITATION_ARTIFACTS) {
            let subject = limitation.artifact.as_deref().unwrap_or(w.whole_run);
            let detail = limitation.detail.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
            doc.item(0, format!("{}: {subject}{detail}", w.affected));
        }
        if of_code.len() > LIMITATION_ARTIFACTS {
            doc.item(0, format!("… +{}", of_code.len() - LIMITATION_ARTIFACTS));
        }
    }
    doc
}

fn finding_blocks(doc: &mut Doc, report: &Report, lang: Lang, w: &Words, finding: &Finding) {
    let title = rule_title(report, lang, &finding.rule);
    let text = finding_text(report, lang, finding);
    let label = format!("[{} · {}]", words::severity(lang, finding.severity), words::confidence(lang, finding.confidence));
    doc.item(0, format!("{label} {title}: {text}"));
    for evidence in &finding.evidence {
        doc.item(1, format!("{}: {}", w.evidence, evidence_line(evidence)));
    }
    if !finding.references.is_empty() {
        doc.item(1, format!("{}: {}", w.references, finding.references.join(", ")));
    }
    doc.item(1, format!("{}: {}", w.finding_id, &finding.id[..finding.id.len().min(16)]));
}
