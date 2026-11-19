//! What the app remembers while it runs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, MutexGuard};

use aa_app::history::History;
use aa_app::run::{Program, Run};
use aa_core::Report;

/// Reports kept in memory at once. The one on screen and the two of a comparison fit.
const CACHED_REPORTS: usize = 4;

pub struct AppState {
    pub history: History,
    /// How a worker is started: this program again, as a worker.
    pub program: Program,
    /// Inputs the user chose through a dialog, by dropping them on the window, or by opening
    /// them with the app. The page may ask to analyze these paths and no others.
    allowed: Mutex<HashSet<PathBuf>>,
    /// The analysis that is running, or the finished one whose evidence can still be read.
    pub run: Mutex<Option<Arc<Run>>>,
    /// Counts analyses, so that updates from one that was replaced are ignored.
    pub generation: AtomicU64,
    /// The kept report that `run` belongs to, once it has finished.
    pub live: Mutex<Option<String>>,
    reports: Mutex<Vec<(String, Arc<Report>)>>,
    /// An input named when the app was started, until the page asks for it.
    pub initial: Mutex<Option<PathBuf>>,
    /// Set when the app was started to check itself; see `selftest.rs`.
    pub selftest: Option<crate::selftest::Plan>,
    /// True when the menus and dialogs are in English, false for Chinese.
    pub english: std::sync::atomic::AtomicBool,
}

/// A lock that keeps working after a thread panicked while holding it.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl AppState {
    pub fn new(history: History, program: Program, initial: Option<PathBuf>, selftest: Option<crate::selftest::Plan>) -> AppState {
        let state = AppState {
            history,
            program,
            allowed: Mutex::new(HashSet::new()),
            run: Mutex::new(None),
            generation: AtomicU64::new(0),
            live: Mutex::new(None),
            reports: Mutex::new(Vec::new()),
            initial: Mutex::new(None),
            selftest,
            english: std::sync::atomic::AtomicBool::new(false),
        };
        if let Some(path) = initial {
            state.allow(&path);
            *lock(&state.initial) = Some(path);
        }
        state
    }

    /// Records that the user chose `path` as an input.
    pub fn allow(&self, path: &Path) {
        lock(&self.allowed).insert(path.to_path_buf());
    }

    pub fn is_allowed(&self, path: &Path) -> bool {
        lock(&self.allowed).contains(path)
    }

    /// Keeps `report` in memory under `id`, forgetting the one used longest ago when full.
    pub fn remember(&self, id: &str, report: Arc<Report>) {
        let mut reports = lock(&self.reports);
        reports.retain(|(known, _)| known != id);
        reports.push((id.to_string(), report));
        if reports.len() > CACHED_REPORTS {
            reports.remove(0);
        }
    }

    pub fn forget(&self, id: &str) {
        lock(&self.reports).retain(|(known, _)| known != id);
    }

    pub fn forget_all(&self) {
        lock(&self.reports).clear();
    }

    /// The report kept as `id`, from memory or from the history folder.
    pub fn report(&self, id: &str) -> Result<Arc<Report>, String> {
        {
            let mut reports = lock(&self.reports);
            if let Some(position) = reports.iter().position(|(known, _)| known == id) {
                let found = reports.remove(position);
                let report = found.1.clone();
                reports.push(found);
                return Ok(report);
            }
        }
        let report = Arc::new(self.history.load(id).map_err(|e| e.to_string())?);
        self.remember(id, report.clone());
        Ok(report)
    }
}
