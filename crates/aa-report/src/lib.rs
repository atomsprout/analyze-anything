//! Turns a [`Report`] into files people read.
//!
//! Renderers only restate what the report holds: every sentence about the input comes from an
//! artifact, a finding or a limitation in it.

mod markdown;
mod text;

use aa_core::Report;

/// Output formats available so far. Plain text, HTML and PDF follow in the next milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Markdown,
}

impl Format {
    /// File extension, without the dot.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Json => "json",
            Format::Markdown => "md",
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
}

/// Renders `report` in `format`. JSON ignores `lang`: it is data, not prose.
pub fn render(report: &Report, format: Format, lang: Lang) -> Result<Vec<u8>, RenderError> {
    match format {
        Format::Json => {
            let mut bytes = serde_json::to_vec_pretty(report)?;
            bytes.push(b'\n');
            Ok(bytes)
        }
        Format::Markdown => Ok(markdown::render(report, lang).into_bytes()),
    }
}
