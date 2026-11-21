// The app's page: which screen is shown, and what the menu, the keyboard and the rest of the
// app ask of it. Every screen is built from scratch when it is shown; there is no state hidden
// in the page besides what is in this file.

import { applyTheme, confirmer, remember, remembered, toaster, type App } from "./app";
import { insideApp, selftest, tauriBackend } from "./backend";
import { clear, el } from "./dom";
import { word } from "./i18n";
import type { Backend, Lang, Theme, WindowsSourceRoot } from "./types";
import { compareView } from "./views/compare";
import { homeView, type HomeView } from "./views/home";
import { progressView, type ProgressView } from "./views/progress";
import { reportView, type ReportView } from "./views/report";

type Screen =
  | { name: "home"; view: HomeView }
  | { name: "progress"; view: ProgressView }
  | { name: "report"; view: ReportView; id: string }
  | { name: "compare"; before: string; after: string };

async function start(): Promise<void> {
  // Outside the app (a browser, for trying the page and for its tests) a stand-in answers.
  const backend: Backend = insideApp() ? tauriBackend() : (await import("./mock")).mockBackend();
  const root = document.getElementById("app");
  if (!root) return;
  const stage = el("div", { class: "stage-host" });
  const toasts = el("div", { class: "toasts" });
  const dialogs = el("div", { class: "dialogs" });
  root.append(stage, toasts, dialogs);

  const app: App = {
    backend,
    info: await backend.appInfo(),
    // English until the user chooses otherwise in the View menu; the choice is remembered.
    lang: remembered("lang", ["zh", "en"] as const, "en"),
    theme: remembered("theme", ["system", "light", "dark"] as const, "system"),
    t: (key, values) => word(app.lang, key, values),
    toast: toaster(toasts),
    confirm: confirmer(dialogs, () => app.lang),
  };
  let screen: Screen | null = null;

  const show = (next: Screen, element: HTMLElement) => {
    screen = next;
    clear(stage).appendChild(element);
  };

  const goHome = async (preserve = false) => {
    const roots = preserve && screen?.name === "home" ? screen.view.sourceRootDraft() : [];
    const entries = await backend.historyList();
    const view = homeView(
      app,
      entries,
      {
        pick: (folder) => void pick(folder),
        open: (id) => void openReport(id),
        compare: (before, after) => void openCompare(before, after),
      },
      () => void goHome(true),
      roots,
    );
    show({ name: "home", view }, view.element);
  };

  const analyze = async (path: string, savedRoots?: WindowsSourceRoot[]) => {
    let roots: WindowsSourceRoot[];
    try { roots = savedRoots ?? (screen?.name === "home" ? screen.view.sourceRoots() : []); }
    catch { app.toast(app.t("source_root_error"), true); return; }
    const name = path.replace(/[/\\]+$/, "").split(/[/\\]/).pop() || path;
    const view = progressView(app, name, () => void backend.cancelAnalysis());
    show({ name: "progress", view }, view.element);
    try {
      await backend.startAnalysis(path, roots);
    } catch (error) {
      app.toast(app.t("failed", { message: String(error) }), true);
      await goHome();
    }
  };

  const pick = async (folder: boolean) => {
    // Choosing a new input while one is being analyzed would silently drop that analysis.
    if (screen?.name === "progress") return;
    try {
      const path = await backend.pickInput(folder);
      if (path !== null) await analyze(path);
    } catch (error) {
      app.toast(String(error), true);
    }
  };

  const openReport = async (id: string) => {
    try {
      const opened = await backend.openReport(id);
      const view = reportView(app, opened, { home: () => void goHome(), reanalyze: (path) => void analyze(path, opened.windows_source_roots ?? []) });
      show({ name: "report", view, id }, view.element);
    } catch (error) {
      app.toast(String(error), true);
      await goHome();
    }
  };

  const openCompare = async (before: string, after: string) => {
    try {
      const diff = await backend.compareReports(before, after);
      show({ name: "compare", before, after }, compareView(app, diff, { home: () => void goHome(), swap: () => void openCompare(after, before) }));
    } catch (error) {
      app.toast(String(error), true);
    }
  };

  /** Draws the current screen again, after the language changed. */
  const redraw = async () => {
    if (!screen) return;
    if (screen.name === "home") await goHome(true);
    else if (screen.name === "compare") await openCompare(screen.before, screen.after);
    else if (screen.name === "report") await openReport(screen.id);
    // The progress screen keeps its words until it ends; redrawing it would lose its counts.
  };

  const setLang = async (lang: Lang) => {
    if (lang === app.lang) return;
    app.lang = lang;
    remember("lang", lang);
    document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
    await backend.setMenuLanguage(lang).catch(() => undefined);
    await redraw();
  };

  const setTheme = (theme: Theme) => {
    app.theme = theme;
    remember("theme", theme);
    applyTheme(theme);
    if (screen?.name === "report") screen.view.sync();
  };

  await backend.on({
    progress: (step) => {
      if (screen?.name === "progress") screen.view.step(step);
    },
    done: (entry) => void openReport(entry.id),
    failed: (message) => {
      app.toast(app.t("failed", { message }), true);
      void goHome();
    },
    cancelled: () => {
      app.toast(app.t("cancelled"));
      void goHome();
    },
    offered: (path) => {
      if (screen?.name !== "progress") void analyze(path);
    },
    drag: (over) => {
      if (screen?.name === "home") screen.view.setDragging(over);
    },
    menu: (id) => {
      if (id === "open-file") void pick(false);
      else if (id === "open-folder") void pick(true);
      else if (id === "home") {
        if (screen?.name !== "progress") void goHome();
      } else if (id === "lang:zh" || id === "lang:en") void setLang(id === "lang:zh" ? "zh" : "en");
      else if (id === "theme:system" || id === "theme:light" || id === "theme:dark") setTheme(id.slice(6) as Theme);
      else if (id.startsWith("export:") && screen?.name === "report") screen.view.export(id.slice(7));
      else if (id === "ai" && screen?.name === "report") screen.view.toggleAi();
    },
    aiStep: (text) => {
      if (screen?.name === "report") screen.view.aiStep(text);
    },
  });

  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
    if (app.theme === "system" && screen?.name === "report") screen.view.sync();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && screen?.name === "report") screen.view.dismiss();
  });
  // A file dropped on the page itself must not replace the app with that file.
  for (const type of ["dragover", "drop"]) document.addEventListener(type, (event) => event.preventDefault());

  applyTheme(app.theme);
  document.documentElement.lang = app.lang === "zh" ? "zh-CN" : "en";
  await backend.setMenuLanguage(app.lang).catch(() => undefined);
  await goHome();
  const initial = await backend.initialInput();
  if (initial !== null) await analyze(initial);
  // Started to check itself, the app goes through its own screens and reports what it saw.
  if (insideApp() && (await selftest.plan().catch(() => null)) !== null) {
    const { runSelftest } = await import("./selftest");
    await runSelftest(app, () => (screen?.name === "report" ? screen.view : null));
  }
}

void start();
