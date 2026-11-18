//! Turns a [`Report`] into files people read.
//!
//! Renderers only restate what the report holds: every sentence about the input comes from an
//! artifact, a finding or a limitation in it, worded by the rule text the report carries.
//!
//! Markdown and plain text are written from one [`doc::Doc`], so they always say the same thing.
//! HTML is one self-contained file that carries the whole report and shows it interactively; PDF
//! is a reading document typeset by an embedded Typst (cargo feature `pdf`, on by default).

pub mod doc;
mod html;
mod markdown;
#[cfg(feature = "pdf")]
mod pdf;
mod plain;
pub mod sanitize;
pub mod words;

use aa_core::Report;

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

/// Language of the human-readable outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    Zh,
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
