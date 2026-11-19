//! A report as the bytes of each output file.

use std::path::{Path, PathBuf};

use aa_core::Report;
use aa_export::manifest::{self, Manifest};
use aa_export::sarif;
use aa_report::Format;
pub use aa_report::Lang;

/// An output file a report can be written as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Json,
    Markdown,
    Text,
    Html,
    Pdf,
    Sarif,
    /// A CycloneDX software bill of materials.
    Sbom,
}

impl Kind {
    pub const ALL: [Kind; 7] = [Kind::Json, Kind::Html, Kind::Pdf, Kind::Markdown, Kind::Text, Kind::Sarif, Kind::Sbom];

    /// The short name used on the command line and between the app's two halves.
    pub fn id(self) -> &'static str {
        match self {
            Kind::Json => "json",
            Kind::Markdown => "md",
            Kind::Text => "txt",
            Kind::Html => "html",
            Kind::Pdf => "pdf",
            Kind::Sarif => "sarif",
            Kind::Sbom => "sbom",
        }
    }

    pub fn from_id(id: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// The name the file has in an output folder.
    pub fn file_name(self) -> &'static str {
        match self {
            Kind::Json => "report.json",
            Kind::Markdown => "report.md",
            Kind::Text => "report.txt",
            Kind::Html => "report.html",
            Kind::Pdf => "report.pdf",
            Kind::Sarif => "report.sarif",
            Kind::Sbom => "sbom.cdx.json",
        }
    }

    /// The extension of [`Kind::file_name`], for a save dialog.
    pub fn extension(self) -> &'static str {
        match self {
            Kind::Sbom => "json",
            other => other.file_name().rsplit('.').next().unwrap_or(""),
        }
    }

    /// True when this build can write the format.
    pub fn available(self) -> bool {
        self != Kind::Pdf || cfg!(feature = "pdf")
    }
}

/// The bytes of `report` as `kind`. `fonts` are extra font files for PDF text the built-in fonts
/// cannot show; other formats ignore them, and JSON, SARIF and the SBOM ignore `lang`.
pub fn render(report: &Report, kind: Kind, lang: Lang, fonts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let readable = |format| aa_report::render(report, format, lang).map_err(|e| e.to_string());
    let pretty = |value: &serde_json::Value| {
        let mut bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        Ok(bytes)
    };
    match kind {
        Kind::Json => readable(Format::Json),
        Kind::Markdown => readable(Format::Markdown),
        Kind::Text => readable(Format::Text),
        Kind::Html => readable(Format::Html),
        Kind::Pdf if fonts.is_empty() => readable(Format::Pdf),
        Kind::Pdf => pdf_with_fonts(report, lang, fonts),
        Kind::Sarif => {
            let language = match lang {
                Lang::Zh => sarif::Language::Zh,
                Lang::En => sarif::Language::En,
            };
            pretty(&sarif::sarif(report, language))
        }
        Kind::Sbom => pretty(&aa_export::cyclonedx::cyclonedx(report)),
    }
}

#[cfg(feature = "pdf")]
fn pdf_with_fonts(report: &Report, lang: Lang, fonts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    aa_report::render_pdf_with_fonts(report, lang, fonts).map_err(|e| e.to_string())
}

#[cfg(not(feature = "pdf"))]
fn pdf_with_fonts(report: &Report, lang: Lang, _fonts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    aa_report::render(report, Format::Pdf, lang).map_err(|e| e.to_string())
}

/// Writes `report` into the folder `dir` as each of `kinds` (a kind named twice is written once),
/// with the manifest that lets `aa verify` check the folder later. Returns the files written, in
/// order, the manifest last.
pub fn write_folder(report: &Report, dir: &Path, kinds: &[Kind], lang: Lang, fonts: &[Vec<u8>]) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut listed = Manifest::new(report);
    let mut written = Vec::new();
    let mut done: Vec<Kind> = Vec::new();
    for kind in kinds {
        if done.contains(kind) {
            continue;
        }
        done.push(*kind);
        let path = dir.join(kind.file_name());
        std::fs::write(&path, render(report, *kind, lang, fonts)?).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        listed.add(dir, kind.file_name()).map_err(|e| e.to_string())?;
        written.push(path);
    }
    let path = dir.join(manifest::MANIFEST_NAME);
    std::fs::write(&path, listed.to_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    written.push(path);
    Ok(written)
}

/// Reads a `report.json`, refusing one written in a layout this program does not read.
pub fn load(path: &Path) -> Result<Report, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let report: Report = serde_json::from_slice(&bytes).map_err(|e| format!("{} is not a report: {e}", path.display()))?;
    if report.schema_version != aa_core::SCHEMA_VERSION {
        return Err(format!(
            "{} uses report layout {}, this program reads layout {}",
            path.display(),
            report.schema_version,
            aa_core::SCHEMA_VERSION
        ));
    }
    Ok(report)
}
