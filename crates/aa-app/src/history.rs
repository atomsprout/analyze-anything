//! Finished reports, kept so they can be opened again.
//!
//! Each analysis gets a folder holding `report.json`, the `manifest.json` that lets it be
//! checked, and `entry.json` with what a list shows about it. Neither the analyzed file nor
//! anything unpacked from it is kept: a report opened from here can be read and exported, but
//! its evidence bytes can only be looked at by analyzing the input again.
//!
//! When an analysis happened is recorded here and nowhere in the report, which stays the same
//! bytes whenever it is made.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aa_core::{InputKind, Report, Severity};
use serde::{Deserialize, Serialize};

use crate::export::{self, Kind, Lang};

const ENTRY_NAME: &str = "entry.json";

/// What the list of past analyses shows about one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    /// Name of the analyzed file or folder.
    pub name: String,
    pub kind: InputKind,
    /// SHA-256 of the input when it was a single file.
    pub sha256: Option<String>,
    /// Seconds since 1970, UTC.
    pub analyzed_at: u64,
    pub tool_version: String,
    /// Where the input was, so it can be analyzed again. Kept on this computer only.
    pub source: Option<String>,
    pub artifacts: u64,
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    /// True when part of the input could not be analyzed.
    pub partial: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("no report is kept under the name {0}")]
    Unknown(String),
    #[error("{0}")]
    Unreadable(String),
}

/// The folder of kept reports.
#[derive(Debug, Clone)]
pub struct History {
    root: PathBuf,
}

impl History {
    /// Uses `root`, creating it when it is not there.
    pub fn open(root: &Path) -> Result<History, HistoryError> {
        std::fs::create_dir_all(root)?;
        Ok(History { root: root.to_path_buf() })
    }

    /// The folder of the entry `id`, if `id` is a name this module could have made. Ids arrive
    /// from the user interface, so anything else, a path in particular, is refused.
    fn folder(&self, id: &str) -> Result<PathBuf, HistoryError> {
        let plain = !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !plain {
            return Err(HistoryError::Unknown(id.to_string()));
        }
        Ok(self.root.join(id))
    }

    /// Keeps `report`, analyzed at `when` from the input at `source`. Returns its entry.
    pub fn add(&self, report: &Report, source: Option<&Path>, when: SystemTime) -> Result<Entry, HistoryError> {
        let analyzed_at = when.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let count = |severity| report.findings.iter().filter(|f| f.severity == severity).count() as u64;
        let coverage = &report.coverage;
        let mut entry = Entry {
            id: String::new(),
            name: report.input.name.clone(),
            kind: report.input.kind,
            sha256: report.input.sha256.clone(),
            analyzed_at,
            tool_version: report.tool.version.clone(),
            source: source.map(|path| path.to_string_lossy().into_owned()),
            artifacts: report.artifacts.len() as u64,
            high: count(Severity::High),
            medium: count(Severity::Medium),
            low: count(Severity::Low),
            info: count(Severity::Info),
            partial: coverage.truncated || coverage.content_lost > 0 || coverage.artifacts_analyzed < coverage.artifacts_total,
        };
        // The time makes the name sort by age; the counter keeps two in one second apart.
        let stamp = timestamp(analyzed_at);
        let (id, folder) = (0..10_000u32)
            .map(|n| if n == 0 { stamp.clone() } else { format!("{stamp}-{n}") })
            .find_map(|id| match std::fs::create_dir(self.root.join(&id)) {
                Ok(()) => Some(Ok((id.clone(), self.root.join(&id)))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            })
            .unwrap_or_else(|| Err(std::io::Error::other("no free name for the report")))?;
        entry.id = id;
        let written = export::write_folder(report, &folder, &[Kind::Json], Lang::Zh, &[])
            .and_then(|_| serde_json::to_vec_pretty(&entry).map_err(|e| e.to_string()))
            .and_then(|bytes| std::fs::write(folder.join(ENTRY_NAME), bytes).map_err(|e| e.to_string()));
        if let Err(message) = written {
            // Half an entry would show up as a broken one; leave nothing instead.
            let _ = std::fs::remove_dir_all(&folder);
            return Err(HistoryError::Unreadable(message));
        }
        Ok(entry)
    }

    /// Every kept report, newest first. Folders that are not readable entries are left out.
    pub fn list(&self) -> Vec<Entry> {
        let Ok(folders) = std::fs::read_dir(&self.root) else { return Vec::new() };
        let mut entries: Vec<Entry> = folders
            .flatten()
            .filter_map(|folder| {
                let bytes = std::fs::read(folder.path().join(ENTRY_NAME)).ok()?;
                let entry: Entry = serde_json::from_slice(&bytes).ok()?;
                // An entry is known by its folder; one whose file says otherwise was tampered with.
                (folder.file_name().to_str() == Some(entry.id.as_str())).then_some(entry)
            })
            .collect();
        entries.sort_by(|a, b| b.analyzed_at.cmp(&a.analyzed_at).then_with(|| b.id.cmp(&a.id)));
        entries
    }

    pub fn entry(&self, id: &str) -> Result<Entry, HistoryError> {
        let bytes = std::fs::read(self.folder(id)?.join(ENTRY_NAME)).map_err(|_| HistoryError::Unknown(id.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| HistoryError::Unreadable(e.to_string()))
    }

    /// The report kept as `id`. A report written in a layout this version does not read is an
    /// error that says so: the input has to be analyzed again.
    pub fn load(&self, id: &str) -> Result<Report, HistoryError> {
        let path = self.folder(id)?.join(Kind::Json.file_name());
        if !path.is_file() {
            return Err(HistoryError::Unknown(id.to_string()));
        }
        export::load(&path).map_err(HistoryError::Unreadable)
    }

    pub fn remove(&self, id: &str) -> Result<(), HistoryError> {
        let folder = self.folder(id)?;
        if !folder.is_dir() {
            return Err(HistoryError::Unknown(id.to_string()));
        }
        Ok(std::fs::remove_dir_all(folder)?)
    }

    /// Removes every kept report. Returns how many there were.
    pub fn clear(&self) -> Result<usize, HistoryError> {
        let entries = self.list();
        for entry in &entries {
            self.remove(&entry.id)?;
        }
        Ok(entries.len())
    }
}

/// `seconds` since 1970 as `YYYYMMDD-HHMMSS` in UTC.
fn timestamp(seconds: u64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    // Days to a calendar date, by the usual era arithmetic (proleptic Gregorian).
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}-{:02}{:02}{:02}", rest / 3600, rest % 3600 / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_calendar_dates() {
        assert_eq!(timestamp(0), "19700101-000000");
        assert_eq!(timestamp(951_782_400), "20000229-000000");
        assert_eq!(timestamp(1_795_219_199), "20261120-235959");
        assert_eq!(timestamp(4_102_444_800), "21000101-000000");
    }
}
