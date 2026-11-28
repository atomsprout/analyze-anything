//! A reading index over explicit relationship facts. No relationship is inferred here.

use aa_core::Report;
use serde::Serialize;
use serde_json::{Value, json};

/// Keep report previews bounded; the source facts retain the complete captured data.
pub const PREVIEW_ROWS: usize = 50;

#[derive(Debug, Serialize)]
pub struct Relationship {
    pub source: String,
    pub location: String,
    pub declaration: String,
    pub status: String,
    pub target: Option<String>,
    pub target_sha256: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Relationships {
    pub rows: Vec<Relationship>,
    /// Captured relationship rows, including those omitted from this preview.
    pub total: usize,
    /// At least one underlying fact was itself truncated.
    pub source_truncated: bool,
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

fn clipped(value: String) -> String {
    if value.chars().count() <= 400 { value } else { value.chars().take(400).chain(std::iter::once('…')).collect() }
}

impl Relationships {
    fn add(&mut self, source: &str, key: &str, ordinal: usize, row: &Value) {
        self.total += 1;
        if self.rows.len() == PREVIEW_ROWS {
            return;
        }
        self.rows.push(Relationship {
            source: source.into(),
            location: clipped(text(row, "field").unwrap_or_else(|| format!("{key}[{ordinal}]"))),
            declaration: clipped(
                text(row, "declared").or_else(|| text(row, "relative_path")).or_else(|| text(row, "id")).unwrap_or_default(),
            ),
            status: text(row, "status").map(clipped).unwrap_or_else(|| "unknown".into()),
            target: text(row, "target"),
            target_sha256: text(row, "target_sha256"),
            reason: text(row, "reason").map(clipped),
        });
    }
}

pub fn collect(report: &Report) -> Relationships {
    let mut result = Relationships::default();
    for artifact in &report.artifacts {
        if let Some(fact) = artifact.facts.get("snap.package") {
            result.source_truncated |= fact["references_truncated"] == true;
            for (ordinal, row) in fact["references"].as_array().into_iter().flatten().enumerate() {
                result.add(row["source"].as_str().unwrap_or(&artifact.path), "snap.package/references", ordinal, row);
            }
        }
        if let Some(fact) = artifact.facts.get("appimage.entry") {
            let mut row = fact.clone();
            if row["declared"].is_null() {
                row["declared"] = fact["source_entry"]["path"].clone();
            }
            result.add(&artifact.path, "appimage.entry", 0, &row);
        }
        for (key, list) in [
            ("windows.input-references", "references"),
            ("windows.source-files", "records"),
            ("windows.msi-action-targets", "references"),
            ("linux.supplied-file", "references"),
            ("composition.elf-library-references", "references"),
        ] {
            if let Some(fact) = artifact.facts.get(key) {
                result.source_truncated |= fact.get("truncated").and_then(Value::as_bool) == Some(true);
                for (ordinal, row) in fact[list].as_array().into_iter().flatten().enumerate() {
                    result.add(&artifact.path, &format!("{key}/{list}"), ordinal, row);
                }
            }
        }
        if let Some(fact) = artifact.facts.get("windows.catalog-membership") {
            result.source_truncated |= fact["entries_omitted"].as_u64().is_some_and(|n| n > 0);
            for (ordinal, entry) in fact["entries"].as_array().into_iter().flatten().enumerate() {
                result.source_truncated |= entry["matches_truncated"] == true;
                let matches = entry["matches"].as_array();
                let mut add_match = |target: Option<&Value>| {
                    result.add(
                        &artifact.path,
                        "windows.catalog-membership/entries",
                        ordinal,
                        &json!({
                            "declared": entry["declared_digest"],
                            "status": entry["status"],
                            "target": target.and_then(|m| m["path"].as_str()),
                            "target_sha256": target.and_then(|m| m["sha256"].as_str()),
                            "reason": json!({
                                "search_complete": entry["search_complete"],
                                "observed_match_count": entry["observed_match_count"],
                                "sip_hash_profile": entry["sip_hash_profile"],
                                "algorithm": entry["algorithm"],
                            }).to_string(),
                        }),
                    );
                };
                if let Some(matches) = matches.filter(|m| !m.is_empty()) {
                    for target in matches {
                        add_match(Some(target));
                    }
                } else {
                    add_match(None);
                }
            }
        }
    }
    if let Some(components) = report.summary.get("composition.components") {
        result.source_truncated |= components.get("truncated").and_then(Value::as_bool) == Some(true);
        for key in ["nuget_dependencies", "vsix_dependencies", "winget_dependencies"] {
            for (ordinal, row) in components[key].as_array().into_iter().flatten().enumerate() {
                result.add(
                    row["source_manifest"].as_str().or_else(|| row["source"].as_str()).unwrap_or(""),
                    &format!("composition.components/{key}"),
                    ordinal,
                    row,
                );
            }
        }
    }
    result
}
