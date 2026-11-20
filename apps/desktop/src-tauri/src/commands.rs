//! The window, and the commands its page may call. Everything here is a thin layer over
//! `aa-app`; the page is given paths and reports only through these commands.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::SystemTime;

use aa_app::export::{self, Kind, Lang};
use aa_app::history::{Entry, History};
use aa_app::run::{self, Program, Run, Update};
use aa_worker::protocol::LimitOverrides;
use serde::Serialize;
use tauri::{AppHandle, DragDropEvent, Emitter, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;

use crate::state::{AppState, lock};
use crate::{WORKER_FLAG, ai, menu, report_page, selftest};

/// Largest piece of a file the page may ask for at once.
const MAX_READ: u64 = 256 * 1024;

type CommandResult<T> = Result<T, String>;

fn language(lang: &str) -> Lang {
    if lang == "zh" { Lang::Zh } else { Lang::En }
}

#[derive(Serialize)]
struct AppInfo {
    version: &'static str,
    /// Output formats this build can write, by their short names.
    formats: Vec<&'static str>,
}

#[tauri::command]
fn app_info() -> AppInfo {
    AppInfo { version: env!("CARGO_PKG_VERSION"), formats: Kind::ALL.into_iter().filter(|k| k.available()).map(Kind::id).collect() }
}

/// The input the app was started with, once.
#[tauri::command]
fn initial_input(state: State<'_, AppState>) -> Option<String> {
    lock(&state.initial).take().map(|path| path.to_string_lossy().into_owned())
}

/// Lets the user choose a file (`folder` false) or a folder to analyze. `None` when they cancel.
#[tauri::command]
async fn pick_input(app: AppHandle, state: State<'_, AppState>, folder: bool) -> CommandResult<Option<String>> {
    let english = state.english.load(Ordering::Relaxed);
    let dialog = app.dialog().file().set_title(match (folder, english) {
        (false, false) => "选择要分析的文件",
        (false, true) => "Choose a file to analyze",
        (true, false) => "选择要分析的文件夹",
        (true, true) => "Choose a folder to analyze",
    });
    let path = match &state.selftest {
        // A self-check answers its own dialogs.
        Some(plan) => match plan.next_input() {
            Some(path) => path,
            None => return Ok(None),
        },
        None => {
            let chosen = if folder { dialog.blocking_pick_folder() } else { dialog.blocking_pick_file() };
            let Some(chosen) = chosen else { return Ok(None) };
            chosen.into_path().map_err(|e| e.to_string())?
        }
    };
    state.allow(&path);
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Starts analyzing `path`, which must be an input the user chose. What happens next arrives as
/// the events `run-progress`, then one of `run-done`, `run-failed` and `run-cancelled`.
#[tauri::command]
fn start_analysis(app: AppHandle, state: State<'_, AppState>, path: String) -> CommandResult<()> {
    let input = PathBuf::from(&path);
    if !state.is_allowed(&input) {
        return Err("this path was not chosen by the user".into());
    }
    // End whatever ran before, outside the lock: its thread may be reporting right now.
    let previous = lock(&state.run).take();
    drop(previous);
    *lock(&state.live) = None;
    let generation = state.generation.fetch_add(1, Ordering::SeqCst) + 1;

    let (handle, source) = (app.clone(), input.clone());
    let started = Run::start(&state.program, &input, LimitOverrides::default(), move |update| {
        let state = handle.state::<AppState>();
        if state.generation.load(Ordering::SeqCst) != generation {
            return;
        }
        // A window that is gone cannot be told anything; nothing to do about a failed emit.
        let _ = match update {
            Update::Progress(step) => handle.emit("run-progress", step),
            Update::Done(report) => match state.history.add(&report, Some(&source), SystemTime::now()) {
                Ok(entry) => {
                    state.remember(&entry.id, Arc::new(*report));
                    *lock(&state.live) = Some(entry.id.clone());
                    handle.emit("run-done", entry)
                }
                Err(error) => handle.emit("run-failed", format!("the report could not be kept: {error}")),
            },
            Update::Failed(message) => handle.emit("run-failed", message),
            Update::Cancelled => handle.emit("run-cancelled", ()),
        };
    })
    .map_err(|e| e.to_string())?;
    *lock(&state.run) = Some(Arc::new(started));
    Ok(())
}

#[tauri::command]
fn cancel_analysis(state: State<'_, AppState>) {
    if let Some(run) = lock(&state.run).as_ref() {
        run.cancel();
    }
}

#[tauri::command]
fn history_list(state: State<'_, AppState>) -> Vec<Entry> {
    state.history.list()
}

#[tauri::command]
fn history_remove(state: State<'_, AppState>, id: String) -> CommandResult<()> {
    close_if_live(&state, Some(&id));
    state.forget(&id);
    ai::forget(&state.ai_folder, Some(&id));
    state.history.remove(&id).map_err(|e| e.to_string())
}

#[tauri::command]
fn history_clear(state: State<'_, AppState>) -> CommandResult<usize> {
    close_if_live(&state, None);
    state.forget_all();
    ai::forget(&state.ai_folder, None);
    state.history.clear().map_err(|e| e.to_string())
}

/// Ends the finished analysis whose report is being removed (`id`), or any (`None`).
fn close_if_live(state: &AppState, id: Option<&str>) {
    let mut live = lock(&state.live);
    if live.is_some() && id.is_none_or(|id| live.as_deref() == Some(id)) {
        *live = None;
        let run = lock(&state.run).take();
        drop(live);
        drop(run);
    }
}

#[derive(Serialize)]
struct Opened {
    entry: Entry,
    /// True while the analysis this report came from is still open, so its bytes can be read.
    live: bool,
    /// True when the input is still where it was, so it can be analyzed again.
    source_present: bool,
}

/// Loads the kept report `id` for display. The page then shows `report://localhost/<id>`.
#[tauri::command]
fn open_report(state: State<'_, AppState>, id: String) -> CommandResult<Opened> {
    let entry = state.history.entry(&id).map_err(|e| e.to_string())?;
    state.report(&id)?;
    let live = lock(&state.live).as_deref() == Some(id.as_str());
    let source_present = entry.source.as_deref().is_some_and(|source| {
        let path = Path::new(source);
        // Analyzing it again is the user's choice, made when they asked to open this report.
        let present = path.exists();
        if present {
            state.allow(path);
        }
        present
    });
    Ok(Opened { entry, live, source_present })
}

#[derive(Serialize)]
struct Bytes {
    hex: String,
    size: u64,
}

/// Reads bytes of the file `path` of the report `id`. Only a report whose analysis is still
/// open has them; a report from the history does not.
#[tauri::command]
async fn read_bytes(state: State<'_, AppState>, id: String, path: String, offset: u64, length: u64) -> CommandResult<Bytes> {
    let run = {
        let live = lock(&state.live);
        if live.as_deref() != Some(id.as_str()) {
            return Err("not-live".into());
        }
        lock(&state.run).clone().ok_or("not-live")?
    };
    // The page names the file; it must be one of this report's.
    if !state.report(&id)?.artifacts.iter().any(|artifact| artifact.path == path) {
        return Err("this report has no such file".into());
    }
    let chunk = run.read(&path, offset, length.min(MAX_READ))?;
    let mut hex = String::with_capacity(chunk.bytes.len() * 2);
    for byte in &chunk.bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(Bytes { hex, size: chunk.size })
}

/// A file name made from the input's name that is safe to suggest in a save dialog.
fn base_name(name: &str) -> String {
    let cleaned: String = name.chars().map(|c| if c.is_control() || matches!(c, '/' | '\\' | ':') { '_' } else { c }).collect();
    let trimmed = cleaned.trim_matches(|c: char| c == '.' || c.is_whitespace());
    if trimmed.is_empty() { "report".into() } else { trimmed.chars().take(80).collect() }
}

/// Asks where to save the report `id` as `kind` and writes it there. Returns the path, or
/// `None` when the user cancelled.
#[tauri::command]
async fn export_report(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    kind: String,
    lang: String,
) -> CommandResult<Option<String>> {
    let kind = Kind::from_id(&kind).filter(|kind| kind.available()).ok_or("this format cannot be written")?;
    let report = state.report(&id)?;
    let stem = base_name(&report.input.name);
    let suggested = match kind {
        Kind::Sbom => format!("{stem}.sbom.cdx.json"),
        other => format!("{stem}.report.{}", other.extension()),
    };
    let english = state.english.load(Ordering::Relaxed);
    let path = match &state.selftest {
        Some(plan) => plan.export_folder()?.join(&suggested),
        None => {
            let chosen = app
                .dialog()
                .file()
                .set_title(if english { "Export the report" } else { "导出报告" })
                .set_file_name(suggested)
                .add_filter(kind.id(), &[kind.extension()])
                .blocking_save_file();
            let Some(chosen) = chosen else { return Ok(None) };
            chosen.into_path().map_err(|e| e.to_string())?
        }
    };
    let bytes = export::render(&report, kind, language(&lang), &[])?;
    std::fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(Some(path.to_string_lossy().into_owned()))
}

/// Asks for a folder and writes the report `id` there in every format, with a manifest, in a
/// new folder of its own. Returns that folder, or `None` when the user cancelled.
#[tauri::command]
async fn export_folder(app: AppHandle, state: State<'_, AppState>, id: String, lang: String) -> CommandResult<Option<String>> {
    let report = state.report(&id)?;
    let english = state.english.load(Ordering::Relaxed);
    let title = if english { "Choose where to put the report folder" } else { "选择存放报告文件夹的位置" };
    let parent = match &state.selftest {
        Some(plan) => plan.export_folder()?,
        None => {
            let Some(chosen) = app.dialog().file().set_title(title).blocking_pick_folder() else { return Ok(None) };
            chosen.into_path().map_err(|e| e.to_string())?
        }
    };
    // A new folder every time: nothing the user already has is overwritten.
    let stem = format!("{} report", base_name(&report.input.name));
    let folder = (1..1000u32)
        .map(|n| parent.join(if n == 1 { stem.clone() } else { format!("{stem} {n}") }))
        .find(|candidate| !candidate.exists())
        .ok_or("no free name for the report folder")?;
    let kinds: Vec<Kind> = Kind::ALL.into_iter().filter(|kind| kind.available()).collect();
    export::write_folder(&report, &folder, &kinds, language(&lang), &[])?;
    // An AI interpretation the user had made of this report, in this language, goes along.
    export::add_files(&folder, &ai::export_files(&state.ai_folder, &id, language(&lang)))?;
    Ok(Some(folder.to_string_lossy().into_owned()))
}

/// Compares the kept reports `before` and `after`.
#[tauri::command]
async fn compare_reports(state: State<'_, AppState>, before: String, after: String) -> CommandResult<aa_export::diff::Diff> {
    let (a, b) = (state.report(&before)?, state.report(&after)?);
    Ok(aa_export::diff::diff(&a, &b))
}

/// Puts the menu bar and the dialogs in Chinese (`zh`) or English (`en`).
#[tauri::command]
fn set_menu_language(app: AppHandle, state: State<'_, AppState>, lang: String) -> CommandResult<()> {
    let english = lang != "zh";
    state.english.store(english, Ordering::Relaxed);
    let built = menu::build(&app, english).map_err(|e| e.to_string())?;
    app.set_menu(built).map(|_| ()).map_err(|e| e.to_string())
}

/// Records paths the user handed to the app and tells the page about the first of them.
fn offer(app: &AppHandle, paths: &[PathBuf]) {
    let state = app.state::<AppState>();
    let Some(first) = paths.iter().find(|path| path.exists()) else { return };
    state.allow(first);
    let _ = app.emit("input-offered", first.to_string_lossy().into_owned());
}

/// Where the app keeps its reports, its scratch files and the AI interpretations.
/// `AA_DESKTOP_DATA_DIR` overrides it, for trying the app without touching the real history.
fn data_folders(app: &tauri::App) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    if let Some(root) = std::env::var_os("AA_DESKTOP_DATA_DIR").map(PathBuf::from) {
        return Ok((root.join("history"), root.join("scratch"), root.join("ai")));
    }
    let data = app.path().app_data_dir()?;
    Ok((data.join("history"), app.path().app_cache_dir()?.join("scratch"), data.join("ai")))
}

/// Opens the window and runs until the app quits.
pub fn run(initial: Option<PathBuf>) {
    let built = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .register_asynchronous_uri_scheme_protocol("report", |context, request, responder| {
            let app = context.app_handle().clone();
            // Rendering a large report takes a moment; it must not hold up the window.
            std::thread::spawn(move || responder.respond(report_page::serve(&app, &request)));
        })
        .setup(move |app| {
            let (history, scratch, ai_folder) = data_folders(app)?;
            std::fs::create_dir_all(&ai_folder)?;
            run::clean_scratch(&scratch);
            let program = Program { path: std::env::current_exe()?, arguments: vec![WORKER_FLAG.to_string()], scratch_root: scratch };
            app.manage(AppState::new(History::open(&history)?, program, ai_folder, initial, selftest::Plan::from_environment()));
            app.set_menu(menu::build(app.handle(), true)?)?;
            Ok(())
        })
        .on_menu_event(|app, event| {
            // The page acts on menu choices; it knows what is on screen.
            let _ = app.emit("menu", event.id().as_ref());
        })
        .on_window_event(|window, event| {
            if let WindowEvent::DragDrop(drag) = event {
                let app = window.app_handle();
                match drag {
                    DragDropEvent::Enter { .. } => drop(app.emit("drag", true)),
                    DragDropEvent::Leave => drop(app.emit("drag", false)),
                    DragDropEvent::Drop { paths, .. } => {
                        let _ = app.emit("drag", false);
                        offer(app, paths);
                    }
                    _ => {}
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            app_info,
            initial_input,
            pick_input,
            start_analysis,
            cancel_analysis,
            history_list,
            history_remove,
            history_clear,
            open_report,
            read_bytes,
            export_report,
            export_folder,
            compare_reports,
            set_menu_language,
            ai::ai_status,
            ai::ai_get,
            ai::ai_interpret,
            selftest::selftest_plan,
            selftest::selftest_menu,
            selftest::selftest_finish,
        ])
        .build(tauri::generate_context!());
    let app = match built {
        Ok(app) => app,
        Err(error) => {
            eprintln!("error: the app could not start: {error}");
            std::process::exit(1);
        }
    };
    app.run(|app, event| match event {
        // Files opened with the app from Finder or `open -a`.
        #[cfg(target_os = "macos")]
        RunEvent::Opened { urls } => {
            let paths: Vec<PathBuf> = urls.iter().filter_map(|url| url.to_file_path().ok()).collect();
            offer(app, &paths);
        }
        // Ending the run ends its worker and removes what it unpacked.
        RunEvent::Exit => {
            let state = app.state::<AppState>();
            let run = lock(&state.run).take();
            drop(run);
        }
        _ => {}
    });
}
