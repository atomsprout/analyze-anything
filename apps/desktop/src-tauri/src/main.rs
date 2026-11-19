//! Analyze Anything, the desktop app: a window around the same engine as the `aa` command.
//!
//! The program has two roles. Started normally it shows the window. Started with `--worker` it
//! is a worker process (see `aa-worker`): it analyzes one input for the window that started it
//! and never opens a window itself. The window never analyzes anything in its own process.

// No console window next to the app on Windows.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod menu;
mod report_page;
mod selftest;
mod state;

/// The argument that makes the program a worker.
const WORKER_FLAG: &str = "--worker";

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    if first.as_deref().is_some_and(|argument| argument == WORKER_FLAG) {
        aa_worker::serve(std::io::stdin().lock(), std::io::stdout());
        return;
    }
    // A file or folder named on the command line is opened at once, like one dropped on the window.
    let initial = first.map(std::path::PathBuf::from).filter(|path| path.exists());
    commands::run(initial);
}
