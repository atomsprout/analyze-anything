// Every command the page may call is named here, so that each has to be allowed in
// capabilities/default.json: a command that is not listed there cannot be called at all.
const COMMANDS: &[&str] = &[
    "app_info",
    "initial_input",
    "pick_input",
    "start_analysis",
    "cancel_analysis",
    "history_list",
    "history_remove",
    "history_clear",
    "open_report",
    "read_bytes",
    "export_report",
    "export_folder",
    "compare_reports",
    "set_menu_language",
    "selftest_plan",
    "selftest_menu",
    "selftest_finish",
];

fn main() {
    let attributes = tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attributes).expect("the app's build description is valid");
}
