//! The optional AI interpretation, in the window.
//!
//! It is the same thing as `analyze-anything interpret`: the settings come from the same file
//! (`~/.analyze-anything/config.toml`), a model explains a report that already exists, and only
//! statements that cite findings of that report are kept. Nothing happens until the user asks
//! for it on a report, and it is the only thing in the app that sends anything anywhere. What is
//! sent are findings of the report, never the analyzed files.
//!
//! An interpretation is kept next to the history, one per report and language, and goes when
//! the report goes.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aa_app::export::{self, Kind, Lang};
use aa_interpret::config::{self, Overrides};
use aa_interpret::delegate::Finished;
use aa_interpret::{Interpretation, Language, Net, Processes, Runner, Settings};
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use crate::state::AppState;

fn language(lang: &str) -> Language {
    if lang == "zh" { Language::Zh } else { Language::En }
}

fn settings() -> Result<Settings, String> {
    let path = config::default_path().ok_or("cannot tell where the home folder is")?;
    config::resolve(config::read_file(&path)?, Overrides::default(), &|name| std::env::var(name).ok())
}

/// Whether an interpretation can be asked for, and of whom.
#[derive(Serialize)]
pub struct Status {
    ready: bool,
    /// True when the settings file says something about it, whether or not it can run.
    configured: bool,
    /// Who would be asked, in words: the model and where it is, or the program.
    who: Option<String>,
    engine: Option<&'static str>,
    /// Why it cannot run, when it cannot.
    problem: Option<String>,
    /// The settings file, for the user to look at.
    config: String,
}

#[tauri::command]
pub fn ai_status() -> Status {
    let config = config::default_path().map(|path| path.to_string_lossy().into_owned()).unwrap_or_default();
    let configured = config::default_path().and_then(|path| config::read_file(&path).ok()).is_some_and(|file| file != Overrides::default());
    match settings() {
        Ok(settings) => {
            Status { ready: true, configured, who: Some(settings.describe()), engine: Some(settings.engine().id()), problem: None, config }
        }
        Err(problem) => Status { ready: false, configured, who: None, engine: None, problem: Some(problem), config },
    }
}

/// Where the interpretation of report `id` in `lang` is kept. The page names the report; the
/// name must be one the history could have made, so that it cannot point anywhere else.
fn kept(folder: &Path, id: &str, lang: Language) -> Result<PathBuf, String> {
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("no such report".into());
    }
    let lang = match lang {
        Language::Zh => "zh",
        Language::En => "en",
    };
    Ok(folder.join(format!("{id}.{lang}.json")))
}

fn load(folder: &Path, id: &str, lang: Language) -> Option<Interpretation> {
    let bytes = std::fs::read(kept(folder, id, lang).ok()?).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The interpretation kept for report `id` in `lang`, if one was made.
#[tauri::command]
pub fn ai_get(state: State<'_, AppState>, id: String, lang: String) -> Option<Interpretation> {
    load(&state.ai_folder, &id, language(&lang))
}

/// Forgets the interpretations of report `id`, or of every report (`None`).
pub fn forget(folder: &Path, id: Option<&str>) {
    let Ok(files) = std::fs::read_dir(folder) else { return };
    for file in files.flatten() {
        let name = file.file_name().to_string_lossy().into_owned();
        if id.is_none_or(|id| name.strip_prefix(id).is_some_and(|rest| rest.starts_with('.'))) && name.ends_with(".json") {
            let _ = std::fs::remove_file(file.path());
        }
    }
}

/// The files an exported folder gets for the interpretation of `id` in `lang`, if there is one.
pub fn export_files(folder: &Path, id: &str, lang: Lang) -> Vec<(&'static str, Vec<u8>)> {
    let lang = if lang == Lang::Zh { Language::Zh } else { Language::En };
    match load(folder, id, lang) {
        Some(made) => vec![
            (aa_interpret::JSON_NAME, aa_interpret::json(&made)),
            (aa_interpret::MARKDOWN_NAME, aa_interpret::markdown(&made).into_bytes()),
        ],
        None => Vec::new(),
    }
}

/// Clears the flag when the interpretation ends, however it ends.
struct Busy<'a>(&'a AtomicBool);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Has the model the user set up explain report `id` in `lang`, keeps the result and returns
/// it. What is going on meanwhile arrives as `ai-step` events.
#[tauri::command]
pub async fn ai_interpret(app: AppHandle, state: State<'_, AppState>, id: String, lang: String) -> Result<Interpretation, String> {
    let language = language(&lang);
    let target = kept(&state.ai_folder, &id, language)?;
    let report = state.report(&id)?;
    let settings = settings()?;
    if state.interpreting.swap(true, Ordering::SeqCst) {
        return Err("an interpretation is already being written; wait for it to finish".into());
    }
    let _busy = Busy(&state.interpreting);

    // A program that is handed the work reads the report from a file, through this program
    // started as the tool server.
    let work = state.ai_folder.join("work");
    std::fs::create_dir_all(&work).map_err(|e| format!("cannot create {}: {e}", work.display()))?;
    let report_path = work.join(format!("{id}.report.json"));
    std::fs::write(&report_path, export::render(&report, Kind::Json, Lang::En, &[])?)
        .map_err(|e| format!("cannot write {}: {e}", report_path.display()))?;
    let program = std::env::current_exe().map_err(|e| format!("cannot tell where this program is: {e}"))?;
    let mut on_step = |step: &str| {
        let shown: String = step.chars().take(200).collect();
        let _ = app.emit("ai-step", shown);
    };
    let context =
        aa_interpret::Context { report_path: &report_path, program: &program, transport: &Net, runner: &Found, on_step: &mut on_step };
    let result = aa_interpret::interpret(&report, &settings, language, context);
    let _ = std::fs::remove_file(&report_path);
    let made = result?;
    std::fs::write(&target, aa_interpret::json(&made)).map_err(|e| format!("cannot keep the interpretation: {e}"))?;
    Ok(made)
}

/// Runs programs like [`Processes`], finding them first. An app started from the Finder or the
/// Dock is not given the shell's search path, so `claude` or `codex` installed in a user's own
/// folder would not be found by name.
struct Found;

impl Runner for Found {
    fn run(&self, program: &str, arguments: &[String], input: &str, folder: &Path, timeout: Duration) -> Result<Finished, String> {
        Processes.run(&locate(program, std::env::var_os("PATH"), home()), arguments, input, folder, timeout)
    }
}

fn home() -> Option<PathBuf> {
    std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// `program` with its folder, when it is named without one and is found on the search path or
/// in one of the usual places for a user's own programs; `program` as it is otherwise.
fn locate(program: &str, search_path: Option<std::ffi::OsString>, home: Option<PathBuf>) -> String {
    if Path::new(program).components().count() != 1 {
        return program.to_string();
    }
    let mut folders: Vec<PathBuf> = search_path.map(|path| std::env::split_paths(&path).collect()).unwrap_or_default();
    if let Some(home) = home {
        folders.extend([".local/bin", ".cargo/bin", "bin", ".npm-global/bin", ".bun/bin"].map(|folder| home.join(folder)));
    }
    folders.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
    let names: &[&str] = if cfg!(windows) { &["", ".exe", ".cmd"] } else { &[""] };
    folders
        .iter()
        .flat_map(|folder| names.iter().map(move |suffix| folder.join(format!("{program}{suffix}"))))
        .find(|candidate| candidate.is_file())
        .map(|found| found.to_string_lossy().into_owned())
        .unwrap_or_else(|| program.to_string())
}

/// Serves the report at `arguments[0]` to a program that was handed the work: this program
/// started as `mcp <report.json> --lang <zh|en>`, the way `analyze-anything mcp` is.
pub fn serve(arguments: &[std::ffi::OsString]) -> Result<(), String> {
    let path = arguments.first().map(PathBuf::from).ok_or("mcp needs the path of a report.json")?;
    let lang = arguments.iter().position(|argument| argument == "--lang").and_then(|at| arguments.get(at + 1));
    let report = export::load(&path)?;
    let language = language(&lang.map(|lang| lang.to_string_lossy().into_owned()).unwrap_or_default());
    aa_interpret::mcp::serve(&report, language, std::io::stdin().lock(), std::io::stdout().lock()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_is_found_in_the_users_own_folders_when_the_search_path_lacks_it() {
        let home = std::env::temp_dir().join(format!("aa-desktop-locate-{}", std::process::id()));
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).expect("folder");
        let name = if cfg!(windows) { "some-agent.exe" } else { "some-agent" };
        std::fs::write(bin.join(name), b"").expect("file");
        let found = locate("some-agent", Some("/nonexistent-a:/nonexistent-b".into()), Some(home.clone()));
        assert_eq!(Path::new(&found), bin.join(name));
        // A program named with its folder is taken as it is, and one that is nowhere keeps its name.
        assert_eq!(locate("/somewhere/agent", None, Some(home.clone())), "/somewhere/agent");
        assert_eq!(locate("no-such-agent-anywhere", None, Some(home.clone())), "no-such-agent-anywhere");
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn a_kept_interpretation_is_named_by_report_and_language_only() {
        let folder = Path::new("/data/ai");
        assert_eq!(kept(folder, "20261119-101500", Language::Zh).expect("named"), folder.join("20261119-101500.zh.json"));
        assert!(kept(folder, "../elsewhere", Language::En).is_err());
        assert!(kept(folder, "", Language::En).is_err());
    }

    #[test]
    fn forgetting_one_report_leaves_the_others() {
        let folder = std::env::temp_dir().join(format!("aa-desktop-forget-{}", std::process::id()));
        std::fs::create_dir_all(&folder).expect("folder");
        for name in ["a-1.en.json", "a-1.zh.json", "a-10.en.json"] {
            std::fs::write(folder.join(name), b"{}").expect("file");
        }
        forget(&folder, Some("a-1"));
        let left: Vec<String> =
            std::fs::read_dir(&folder).expect("list").flatten().map(|f| f.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left, ["a-10.en.json"]);
        forget(&folder, None);
        assert_eq!(std::fs::read_dir(&folder).expect("list").count(), 0);
        let _ = std::fs::remove_dir_all(folder);
    }
}
