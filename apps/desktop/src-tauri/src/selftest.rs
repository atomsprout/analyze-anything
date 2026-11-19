//! The app checking itself in its real window.
//!
//! No tool can drive the system web view on macOS from outside, so the app can do it from
//! inside: started with `AA_DESKTOP_SELFTEST=<plan.json>`, the page goes through its own
//! screens the way a user would (opening inputs, reading the report, looking at bytes,
//! exporting, comparing, cancelling), records what it saw, and the app writes that down and
//! quits. In this mode the dialogs are not shown: "open" answers with the plan's inputs in turn
//! and "save" writes into the plan's folder. Without the variable none of this is reachable:
//! the three commands below refuse.
//!
//! The plan is a JSON object: `inputs` (paths to analyze, in order), `slow_input` (a large one,
//! for cancelling), and `out` (a folder for exports and for `result.json`).

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::Deserialize;
use tauri::{AppHandle, Emitter, State};

use crate::state::AppState;

#[derive(Deserialize)]
struct PlanFile {
    inputs: Vec<PathBuf>,
    slow_input: Option<PathBuf>,
    out: PathBuf,
}

pub struct Plan {
    file: PlanFile,
    /// How many "open" dialogs have been answered.
    answered: AtomicUsize,
}

impl Plan {
    /// The plan named by `AA_DESKTOP_SELFTEST`, if the variable is set and the file is a plan.
    pub fn from_environment() -> Option<Plan> {
        let path = std::env::var_os("AA_DESKTOP_SELFTEST")?;
        let file: PlanFile = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        Some(Plan { file, answered: AtomicUsize::new(0) })
    }

    /// What the next "open" dialog answers: the inputs in turn, then the slow one, then nothing.
    pub fn next_input(&self) -> Option<PathBuf> {
        let index = self.answered.fetch_add(1, Ordering::SeqCst);
        self.file.inputs.get(index).cloned().or_else(|| if index == self.file.inputs.len() { self.file.slow_input.clone() } else { None })
    }

    /// Where "save" dialogs write.
    pub fn export_folder(&self) -> Result<PathBuf, String> {
        let folder = self.file.out.join("exports");
        std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        Ok(folder)
    }
}

/// What the page needs to know to check itself; `None` in ordinary use.
#[tauri::command]
pub fn selftest_plan(state: State<'_, AppState>) -> Option<serde_json::Value> {
    let plan = state.selftest.as_ref()?;
    Some(serde_json::json!({ "inputs": plan.file.inputs.len(), "slow": plan.file.slow_input.is_some() }))
}

/// Chooses a menu item, as far as the page can tell.
#[tauri::command]
pub fn selftest_menu(app: AppHandle, state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.selftest.as_ref().ok_or("not checking itself")?;
    app.emit("menu", id).map_err(|e| e.to_string())
}

/// Writes down what the page found and quits.
#[tauri::command]
pub fn selftest_finish(app: AppHandle, state: State<'_, AppState>, result: serde_json::Value) -> Result<(), String> {
    let plan = state.selftest.as_ref().ok_or("not checking itself")?;
    std::fs::create_dir_all(&plan.file.out).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(&result).map_err(|e| e.to_string())?;
    std::fs::write(plan.file.out.join("result.json"), bytes).map_err(|e| e.to_string())?;
    app.exit(0);
    Ok(())
}
