//! The report as a sequence of headings, paragraphs, lists and tables, before any markup.
//!
//! Every text renderer writes this same document, so the formats cannot drift apart.

use aa_core::{Finding, Limitation, Location, Report, Section, Severity, fill};

use crate::Lang;
use crate::group::{self, Group, Row};
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

/// The lines under the title: which tool wrote the report and the digest of the input.
pub fn header_items(report: &Report, lang: Lang) -> Vec<(String, String)> {
    let w = words::words(lang);
    let input_sha256 = match (&report.input.sha256, report.input.kind) {
        (Some(sha256), _) => sha256.clone(),
        (None, aa_core::InputKind::Directory) => w.not_applicable.to_string(),
        (None, aa_core::InputKind::File) => w.unknown.to_string(),
    };
    vec![(w.tool.to_string(), format!("{} {}", report.tool.name, report.tool.version)), (w.input_sha256.to_string(), input_sha256)]
}

/// The lines of the summary: what the input is, how much was read, how many findings.
pub fn summary_items(report: &Report, lang: Lang) -> Vec<(String, String)> {
    let w = words::words(lang);
    let count = |severity| report.findings.iter().filter(|f| f.severity == severity).count();
    let by_severity = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .map(|s| format!("{} {}", words::severity(lang, s), count(s)))
        .join(" · ");
    vec![
        (w.input.to_string(), words::input_kind(lang, report.input.kind).to_string()),
        (w.artifacts.to_string(), format!("{} / {}", report.coverage.artifacts_analyzed, report.coverage.artifacts_total)),
        (w.containers.to_string(), report.coverage.containers_unpacked.to_string()),
        (w.bytes_read.to_string(), report.coverage.bytes_analyzed.to_string()),
        (w.findings.to_string(), format!("{} ({}: {by_severity})", report.findings.len(), w.by_severity)),
    ]
}

/// The inventory table: its head, its rows, and a note when the rows were cut.
pub struct Inventory {
    pub head: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub note: Option<String>,
}

/// The first [`INVENTORY_ROWS`] artifacts as table rows.
pub fn inventory(report: &Report, lang: Lang) -> Inventory {
    let w = words::words(lang);
    let rows = report
        .artifacts
        .iter()
        .take(INVENTORY_ROWS)
        .map(|a| {
            let mut kind = match (&a.kind, &a.detected) {
                (Some(kind), Some(detected)) => format!("{kind} ({})", detected.mime),
                (Some(kind), None) => kind.clone(),
                (None, Some(detected)) => detected.mime.clone(),
                (None, None) => w.unknown.to_string(),
            };
            // A container's kind may be the generic file type; the unpacker says what it really is.
            if let Some(unpacker) = &a.unpacked_by {
                kind.push_str(&format!(" · {}", words::ui(lang, "unpacked_by_note").replace("{n}", unpacker)));
            }
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
    let note = (report.artifacts.len() > INVENTORY_ROWS).then(|| match lang {
        Lang::Zh => format!("上表只列出前 {INVENTORY_ROWS} 个文件，共 {} 个；完整清单见 report.json。", report.artifacts.len()),
        Lang::En => {
            format!("The table shows the first {INVENTORY_ROWS} of {} files; report.json lists them all.", report.artifacts.len())
        }
    });
    Inventory { head, rows, note }
}

/// The limitations that share one code.
pub struct LimitationGroup {
    /// Title of the code, with the number of limitations in brackets.
    pub title: String,
    /// What the code means; empty when the report has no text for it.
    pub text: String,
    /// One line per limitation, the first [`LIMITATION_ARTIFACTS`] of them.
    pub items: Vec<String>,
    /// How many more there are, when the items were cut.
    pub more: Option<String>,
}

/// The limitations grouped by code, codes in sorted order.
pub fn limitation_groups(report: &Report, lang: Lang) -> Vec<LimitationGroup> {
    let w = words::words(lang);
    let mut codes: Vec<&str> = report.limitations.iter().map(|l| l.code.as_str()).collect();
    codes.sort();
    codes.dedup();
    codes
        .into_iter()
        .map(|code| {
            let of_code: Vec<&Limitation> = report.limitations.iter().filter(|l| l.code == code).collect();
            let items = of_code
                .iter()
                .take(LIMITATION_ARTIFACTS)
                .map(|limitation| {
                    let subject = limitation.artifact.as_deref().unwrap_or(w.whole_run);
                    let detail = limitation.detail.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
                    format!("{}: {subject}{detail}", w.affected)
                })
                .collect();
            LimitationGroup {
                title: format!("{} ({})", rule_title(report, lang, code), of_code.len()),
                text: limitation_text(report, lang, code),
                items,
                more: (of_code.len() > LIMITATION_ARTIFACTS).then(|| format!("… +{}", of_code.len() - LIMITATION_ARTIFACTS)),
            }
        })
        .collect()
}

pub fn build(report: &Report, lang: Lang) -> Doc {
    let w = words::words(lang);
    let mut doc = Doc::default();
    doc.heading(1, format!("{}: {}", w.title, report.input.name));
    for (label, value) in header_items(report, lang) {
        doc.item(0, format!("{label}: {value}"));
    }

    doc.heading(2, w.summary);
    for (label, value) in summary_items(report, lang) {
        doc.item(0, format!("{label}: {value}"));
    }
    doc.heading(3, w.reading_guide);
    doc.paragraph(w.reading_guide_text);
    doc.paragraph(words::ui(lang, "grouping_guide"));

    for section in Section::ALL {
        let groups = group::chapter(report, lang, section);
        doc.heading(2, group::heading(lang, words::section(lang, section), &groups));
        if groups.is_empty() {
            doc.paragraph(w.no_findings_here);
        }
        for group in &groups {
            group_blocks(&mut doc, report, lang, &w, group);
        }
        // The overview is the opening summary; what needs attention follows it directly.
        if section == Section::Overview {
            let attention = group::attention(report, lang);
            doc.heading(2, group::heading(lang, words::ui(lang, "attention"), &attention));
            doc.paragraph(words::ui(lang, if attention.is_empty() { "attention_none" } else { "attention_text" }));
            for group in &attention {
                group_blocks(&mut doc, report, lang, &w, group);
            }
        }
    }

    doc.heading(2, w.inventory);
    let inventory = inventory(report, lang);
    doc.blocks.push(Block::Table { head: inventory.head, rows: inventory.rows });
    if let Some(note) = inventory.note {
        doc.paragraph(note);
    }

    doc.heading(2, w.coverage);
    doc.paragraph(if report.coverage.truncated { w.truncated } else { w.complete });
    if report.limitations.is_empty() {
        doc.paragraph(w.no_limitations);
    }
    for group in limitation_groups(report, lang) {
        doc.heading(3, group.title);
        if !group.text.is_empty() {
            doc.paragraph(group.text);
        }
        for item in group.items {
            doc.item(0, item);
        }
        if let Some(more) = group.more {
            doc.item(0, more);
        }
    }
    if let Some(project) = crate::credit() {
        doc.paragraph(format!("{} {} {} · {project}", w.generated_by, report.tool.name, report.tool.version));
    }
    doc
}

/// A group as list items: a single finding in full, several as one entry with a row per sentence.
fn group_blocks(doc: &mut Doc, report: &Report, lang: Lang, w: &Words, group: &Group) {
    if let (1, Some(only)) = (group.count, group.instances().next()) {
        return finding_blocks(doc, report, lang, w, only.finding);
    }
    let count = words::ui(lang, "group_count").replace("{n}", &group::thousands(group.count));
    doc.item(0, format!("[{}] {} — {count}", group::label(lang, group), group.title));
    let listing = group::listing(group);
    for row in listing.rows {
        match row {
            Row::Single { subject, text } => {
                doc.item(1, format!("{}: {text}", subject.as_deref().unwrap_or(words::ui(lang, "subject_none"))))
            }
            Row::Shared { text, count, subjects, cut } => {
                let more = if cut { " …" } else { "" };
                doc.item(1, format!("{text} — {}: {}{more}", group::shared_note(lang, count), subjects.join(", ")));
            }
        }
    }
    if listing.not_shown > 0 {
        doc.item(1, group::not_shown_note(lang, listing.not_shown));
    }
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
    doc.item(1, format!("{}: {}", w.finding_id, finding.id.chars().take(16).collect::<String>()));
}
