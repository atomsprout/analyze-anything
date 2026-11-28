//! The built-in format catalogue used by the CLI and public support matrix.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Kept as data so documentation and the executable use the same family IDs and counts.
pub const CATALOGUE_JSON: &str = include_str!("formats.json");

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Catalogue {
    pub schema_version: u32,
    pub counting_policy: String,
    pub formats: Vec<Format>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Format {
    pub id: String,
    pub name: String,
    pub group: String,
    pub state: String,
    pub aliases: Vec<String>,
    pub profile: String,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
}

impl Catalogue {
    /// Count implemented families by group. Planned entries and aliases contribute nothing.
    pub fn counts(&self) -> BTreeMap<&str, usize> {
        let mut counts = BTreeMap::new();
        for format in self.formats.iter().filter(|format| format.state == "implemented") {
            *counts.entry(format.group.as_str()).or_insert(0) += 1;
        }
        counts
    }

    pub fn primary_total(&self) -> usize {
        let counts = self.counts();
        counts.get("primary").copied().unwrap_or_default() + counts.get("compression").copied().unwrap_or_default()
    }
}

pub fn catalogue() -> Result<Catalogue, serde_json::Error> {
    serde_json::from_str(CATALOGUE_JSON)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn catalogue_has_unique_families_and_explicit_scopes() {
        let catalogue = catalogue().expect("built-in catalogue parses");
        assert_eq!(catalogue.schema_version, 1);
        let mut ids = BTreeSet::new();
        for format in &catalogue.formats {
            assert!(ids.insert(&format.id), "duplicate family {}", format.id);
            assert!(["primary", "compression", "declaration"].contains(&format.group.as_str()));
            assert!(["implemented", "planned"].contains(&format.state.as_str()));
            assert!(!format.profile.is_empty());
            if format.state == "implemented" {
                assert!(!format.evidence.is_empty(), "{} needs scope evidence", format.id);
                assert!(!format.limitations.is_empty(), "{} needs explicit boundaries", format.id);
            }
        }
    }

    #[test]
    fn aliases_and_planned_formats_cannot_inflate_the_total() {
        let mut catalogue = catalogue().expect("built-in catalogue parses");
        let before = catalogue.primary_total();
        let mut format = catalogue.formats.first().expect("at least one format").clone();
        format.id = "future-test-format".into();
        format.state = "planned".into();
        format.aliases.extend(["another-extension".into(), "third-extension".into()]);
        catalogue.formats.push(format);
        assert_eq!(catalogue.primary_total(), before);
        catalogue.formats.last_mut().expect("new row").state = "implemented".into();
        assert_eq!(catalogue.primary_total(), before + 1);
    }
}
