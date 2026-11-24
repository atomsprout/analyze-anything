//! Offline questions about finished reports. No input artifact, process, model or network.

pub mod mcp;
pub mod tools;

use serde::{Deserialize, Serialize};

/// Language of the report's stored rule text, independent of optional AI interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    En,
    Zh,
}

/// Read the schema header before the body, so unsupported reports fail with a version
/// diagnostic even when their remaining fields have an entirely different layout.
pub fn decode(bytes: &[u8]) -> Result<aa_core::Report, String> {
    #[derive(Deserialize)]
    struct Header {
        schema_version: u32,
    }
    let header: Header = serde_json::from_slice(bytes).map_err(|error| format!("invalid report schema header: {error}"))?;
    if header.schema_version != aa_core::SCHEMA_VERSION {
        return Err(format!(
            "report layout {} is unsupported; this program reads layout {}",
            header.schema_version,
            aa_core::SCHEMA_VERSION
        ));
    }
    serde_json::from_slice(bytes).map_err(|error| format!("invalid report body: {error}"))
}
