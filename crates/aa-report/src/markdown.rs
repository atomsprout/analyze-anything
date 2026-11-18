//! Markdown output.

use std::fmt::Write as _;

use aa_core::{InputKind, Location, Report};

use crate::Lang;
use crate::text;

/// Rows shown in the inventory table. The JSON report always holds every file.
const INVENTORY_ROWS: usize = 200;

/// Text for a code span: backticks and line breaks would end the span or the table row.
fn code(text: &str) -> String {
    let cleaned: String = text.chars().map(|c| if c == '`' || c.is_control() { '?' } else { c }).collect();
    format!("`{}`", cleaned.replace('|', "\\|"))
}

pub fn render(report: &Report, lang: Lang) -> String {
    let w = text::words(lang);
    let mut out = String::new();
    // Writing to a String cannot fail, so the results are discarded.
    let _ = writeln!(out, "# {}: {}\n", w.title, code(&report.input.name));
    let _ = writeln!(out, "- {}: {} {}", w.tool, report.tool.name, report.tool.version);
    let input_sha256 = match (&report.input.sha256, report.input.kind) {
        (Some(sha256), _) => code(sha256),
        (None, InputKind::Directory) => w.not_applicable.to_string(),
        (None, InputKind::File) => w.unknown.to_string(),
    };
    let _ = writeln!(out, "- {}: {}", w.input_sha256, input_sha256);

    let _ = writeln!(out, "\n## {}\n", w.summary);
    let _ = writeln!(out, "- {}: {}", w.input, text::input_kind(lang, report.input.kind));
    let _ = writeln!(out, "- {}: {} / {}", w.files, report.coverage.artifacts_analyzed, report.coverage.artifacts_total);
    let _ = writeln!(out, "- {}: {}", w.bytes_read, report.coverage.bytes_analyzed);
    let _ = writeln!(out, "- {}: {}", w.findings, report.findings.len());

    let _ = writeln!(out, "\n## {}\n", w.findings);
    if report.findings.is_empty() {
        let _ = writeln!(out, "{}", w.none);
    }
    for finding in &report.findings {
        let _ = writeln!(out, "### [{}] {}\n", text::severity(lang, finding.severity), code(&finding.rule));
        let _ = writeln!(out, "{}\n", text::finding(lang, finding));
        let _ = writeln!(out, "- {}: {}", w.confidence, text::confidence(lang, finding.confidence));
        for evidence in &finding.evidence {
            let place = match &evidence.location {
                Location::Bytes { offset, length } => format!(" @ {offset}+{length}"),
                Location::Field(field) => format!(" @ {field}"),
                Location::Whole => String::new(),
            };
            let _ = writeln!(out, "- {}: {}{} = {}", w.evidence, code(&evidence.artifact), place, code(&evidence.value.to_string()));
        }
        let _ = writeln!(out, "- {}: {}\n", w.finding_id, code(&finding.id));
    }

    let _ = writeln!(out, "\n## {}\n", w.inventory);
    let _ = writeln!(out, "| {} | {} | {} | {} | SHA-256 |", w.path, w.size, w.kind, w.entropy);
    let _ = writeln!(out, "|---|---:|---|---:|---|");
    for artifact in report.artifacts.iter().take(INVENTORY_ROWS) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            code(&artifact.path),
            artifact.size,
            artifact.detected.as_ref().map(|d| d.mime.as_str()).unwrap_or(w.unknown),
            artifact.entropy.map(|e| format!("{e:.4}")).unwrap_or(w.unknown.to_string()),
            artifact.digests.as_ref().map(|d| code(&d.sha256)).unwrap_or(w.unknown.to_string()),
        );
    }
    if report.artifacts.len() > INVENTORY_ROWS {
        let _ = match lang {
            Lang::Zh => writeln!(out, "\n上表只列出前 {INVENTORY_ROWS} 个文件，共 {} 个；完整清单见 report.json。", report.artifacts.len()),
            Lang::En => {
                writeln!(
                    out,
                    "\nThe table shows the first {INVENTORY_ROWS} of {} files; report.json lists them all.",
                    report.artifacts.len()
                )
            }
        };
    }

    let _ = writeln!(out, "\n## {}\n", w.coverage);
    let _ = writeln!(out, "{}\n", if report.coverage.truncated { w.truncated } else { w.complete });
    let _ = writeln!(out, "### {}\n", w.limitations);
    if report.limitations.is_empty() {
        let _ = writeln!(out, "{}", w.no_limitations);
    }
    for limitation in &report.limitations {
        let subject = limitation.artifact.as_deref().map(|a| format!("{}: ", code(a))).unwrap_or_default();
        let detail = limitation.detail.as_deref().map(|d| format!(" ({})", code(d))).unwrap_or_default();
        let _ = writeln!(out, "- {}{}{}", subject, text::limitation(lang, limitation), detail);
    }
    out
}
