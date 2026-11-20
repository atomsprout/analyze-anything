import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type { AiStatus, AppInfo, Backend, Chunk, Diff, Entry, Handlers, Interpretation, Lang, Opened, Step } from "./types";

/** The backend when the page runs inside the app: every call is a command of the Rust side. */
export function tauriBackend(): Backend {
  return {
    appInfo: () => invoke<AppInfo>("app_info"),
    initialInput: () => invoke<string | null>("initial_input"),
    pickInput: (folder) => invoke<string | null>("pick_input", { folder }),
    startAnalysis: (path) => invoke<void>("start_analysis", { path }),
    cancelAnalysis: () => invoke<void>("cancel_analysis"),
    historyList: () => invoke<Entry[]>("history_list"),
    historyRemove: (id) => invoke<void>("history_remove", { id }),
    historyClear: () => invoke<number>("history_clear"),
    openReport: (id) => invoke<Opened>("open_report", { id }),
    readBytes: (id, path, offset, length) => invoke<Chunk>("read_bytes", { id, path, offset, length }),
    exportReport: (id, kind, lang) => invoke<string | null>("export_report", { id, kind, lang }),
    exportFolder: (id, lang) => invoke<string | null>("export_folder", { id, lang }),
    compareReports: (before, after) => invoke<Diff>("compare_reports", { before, after }),
    setMenuLanguage: (lang) => invoke<void>("set_menu_language", { lang }),
    aiStatus: () => invoke<AiStatus>("ai_status"),
    aiGet: (id, lang) => invoke<Interpretation | null>("ai_get", { id, lang }),
    aiInterpret: (id, lang) => invoke<Interpretation>("ai_interpret", { id, lang }),
    // The id is made of digits and dashes by the app itself; it is still encoded, as any part
    // of an address should be.
    reportUrl: (id, lang: Lang) => `report://localhost/${encodeURIComponent(id)}?lang=${lang}&host=1`,
    async on(handlers: Handlers) {
      await listen<Step>("run-progress", (event) => handlers.progress(event.payload));
      await listen<Entry>("run-done", (event) => handlers.done(event.payload));
      await listen<string>("run-failed", (event) => handlers.failed(event.payload));
      await listen<null>("run-cancelled", () => handlers.cancelled());
      await listen<string>("input-offered", (event) => handlers.offered(event.payload));
      await listen<boolean>("drag", (event) => handlers.drag(event.payload));
      await listen<string>("menu", (event) => handlers.menu(event.payload));
      await listen<string>("ai-step", (event) => handlers.aiStep(event.payload));
    },
  };
}

/** True when the page runs inside the app rather than in a plain browser. */
export function insideApp(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

/** The app checking itself; see `selftest.rs`. `plan` answers `null` in ordinary use. */
export const selftest = {
  plan: () => invoke<{ inputs: number; slow: boolean } | null>("selftest_plan"),
  menu: (id: string) => invoke<void>("selftest_menu", { id }),
  finish: (result: unknown) => invoke<void>("selftest_finish", { result }),
};
