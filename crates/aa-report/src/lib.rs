//! Turns a [`Report`] into files people read.
//!
//! Renderers only restate what the report holds: every sentence about the input comes from an
//! artifact, a finding or a limitation in it, worded by the rule text the report carries.
//!
//! Markdown and plain text are written from one [`doc::Doc`], so they always say the same thing.
//! HTML is one self-contained file that carries the whole report and shows it interactively; PDF
//! is a reading document typeset by an embedded Typst (cargo feature `pdf`, on by default).

pub mod doc;
pub mod group;
mod html;
mod markdown;
#[cfg(feature = "pdf")]
mod pdf;
mod plain;
pub mod sanitize;
pub mod words;

use aa_core::Report;

/// Where the tool lives; written at the end of a report with the tool's name.
pub const PROJECT_URL: &str = env!("CARGO_PKG_REPOSITORY");

static CREDIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Says whether the reports this process writes for people (HTML, PDF, Markdown, text) end with
/// a line naming the tool and its address. They do unless this is called with `false`.
pub fn set_credit(shown: bool) {
    CREDIT.store(shown, std::sync::atomic::Ordering::Relaxed);
}

/// The closing line's address, or `None` when the line was turned off.
pub(crate) fn credit() -> Option<&'static str> {
    CREDIT.load(std::sync::atomic::Ordering::Relaxed).then_some(PROJECT_URL)
}

/// Output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
    Text,
    Html,
    Pdf,
}

impl Format {
    /// File extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Markdown => "md",
            Format::Text => "txt",
            Format::Html => "html",
            Format::Pdf => "pdf",
        }
    }
}

/// Language of the human-readable outputs. English unless another is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    Zh,
    #[default]
    En,
}

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("cannot write the report as JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cannot typeset the report as PDF: {0}")]
    Pdf(String),
    #[error("this build has no PDF support (it was built without the `pdf` feature)")]
    PdfNotBuilt,
}

/// Renders `report` as a PDF, using `extra_fonts` (font file contents) for characters the embedded
/// fonts do not cover.
#[cfg(feature = "pdf")]
pub fn render_pdf_with_fonts(report: &Report, lang: Lang, extra_fonts: &[Vec<u8>]) -> Result<Vec<u8>, RenderError> {
    pdf::render_with_fonts(report, lang, extra_fonts)
}

/// Renders `report` in `format`. JSON ignores `lang`: it is data, not prose.
pub fn render(report: &Report, format: Format, lang: Lang) -> Result<Vec<u8>, RenderError> {
    match format {
        Format::Json => {
            let mut bytes = serde_json::to_vec_pretty(report)?;
            bytes.push(b'\n');
            Ok(bytes)
        }
        Format::Markdown => Ok(markdown::write(&doc::build(report, lang)).into_bytes()),
        Format::Text => Ok(plain::write(&doc::build(report, lang)).into_bytes()),
        Format::Html => Ok(html::render(report, lang)?.into_bytes()),
        #[cfg(feature = "pdf")]
        Format::Pdf => pdf::render(report, lang),
        #[cfg(not(feature = "pdf"))]
        Format::Pdf => Err(RenderError::PdfNotBuilt),
    }
}
