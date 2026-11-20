import { resolvedTheme, type App } from "../app";
import { clear, el } from "../dom";
import { bytes as sizeText, fromHex, group, parseOffset, visible } from "../format";
import { hexView, type HexView, type Range } from "../hexview";
import type { Opened } from "../types";
import { aiPanel } from "./ai";

export interface ReportActions {
  home(): void;
  reanalyze(path: string): void;
}

export interface ReportView {
  element: HTMLElement;
  /** Tells the report page the language and colours to use. */
  sync(): void;
  export(kind: string): void;
  /** Closes what is open on top of the report; false when nothing was. */
  dismiss(): boolean;
  /** Shows the bytes of one of the report's files, as the report page asks for them. */
  showBytes(path: string, marked: Range | null): Promise<void>;
  /** Opens or closes the AI interpretation beside the report. */
  toggleAi(): void;
  /** What the interpretation being written is doing right now. */
  aiStep(text: string): void;
}

/** What the report page may ask for. Anything else it sends is ignored. */
interface PageMessage {
  kind: "ready" | "evidence" | "file";
  path?: string;
  offset?: number;
  length?: number;
}

function pageMessage(data: unknown): PageMessage | null {
  if (typeof data !== "object" || data === null) return null;
  const message = data as Record<string, unknown>;
  if (message.source !== "analyze-anything-report") return null;
  if (message.kind === "ready") return { kind: "ready" };
  if (message.kind !== "evidence" && message.kind !== "file") return null;
  if (typeof message.path !== "string" || message.path.length > 8192) return null;
  if (message.kind === "file") return { kind: "file", path: message.path };
  const whole = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  if (!whole(message.offset) || !whole(message.length)) return null;
  return { kind: "evidence", path: message.path, offset: message.offset, length: message.length };
}

const FORMAT_NAMES: Record<string, string> = { pdf: "PDF", html: "HTML", md: "Markdown", json: "JSON", sarif: "SARIF" };

export function reportView(app: App, opened: Opened, actions: ReportActions): ReportView {
  const { t, backend } = app;
  const { entry } = opened;

  // The report is its own page in a frame that may run its script and nothing else: it cannot
  // reach the app's commands, open windows, or navigate anything.
  const frame = el("iframe", { class: "report-frame", title: entry.name });
  frame.setAttribute("sandbox", "allow-scripts");
  frame.setAttribute("referrerpolicy", "no-referrer");
  frame.src = backend.reportUrl(entry.id, app.lang);

  const drawer = el("section", { class: "drawer", hidden: true, "aria-label": t("bytes_title") });
  let hex: HexView | null = null;

  const sync = () => {
    frame.contentWindow?.postMessage({ source: "analyze-anything-host", lang: app.lang, theme: resolvedTheme(app.theme) }, "*");
  };

  const closeDrawer = () => {
    drawer.hidden = true;
    clear(drawer);
    hex = null;
  };

  const drawerHead = (path: string, extra: Node | null) =>
    el(
      "header",
      { class: "drawer-head" },
      el("strong", null, t("bytes_title")),
      el("span", { class: "mono path grow", title: path }, visible(path)),
      extra,
      el("button", { type: "button", class: "plain", title: t("close"), "aria-label": t("close"), onclick: closeDrawer }, "✕"),
    );

  /** Shows the bytes of `path`, with `marked` highlighted and in view. */
  const showBytes = async (path: string, marked: Range | null) => {
    drawer.hidden = false;
    clear(drawer);
    if (!opened.live) {
      const source = entry.source;
      drawer.append(
        drawerHead(path, null),
        el(
          "div",
          { class: "drawer-note" },
          el("p", null, t("not_live")),
          source && opened.source_present ? el("button", { type: "button", class: "btn primary", onclick: () => actions.reanalyze(source) }, t("reanalyze")) : null,
          source && !opened.source_present ? el("p", { class: "muted small" }, t("source_gone", { path: source })) : null,
        ),
      );
      return;
    }
    const read = async (offset: number, length: number) => fromHex((await backend.readBytes(entry.id, path, offset, length)).hex);
    let size: number;
    try {
      // The first read also says how large the file is.
      size = (await backend.readBytes(entry.id, path, 0, 16)).size;
    } catch (error) {
      drawer.append(drawerHead(path, null), el("div", { class: "drawer-note" }, el("p", null, t("read_failed", { message: String(error) }))));
      return;
    }
    const range = marked && marked.offset < size ? marked : null;
    const status = el("span", { class: "muted small" }, t("size_of", { size: `${sizeText(size)} (${group(size)} ${t("byte_unit")})` }));
    const input = el("input", { type: "text", class: "offset", placeholder: "0x0", title: t("offset_hint"), "aria-label": t("go_to") });
    const view = hexView(size, read, range, (message) => app.toast(t("read_failed", { message }), true));
    hex = view;
    const go = (event: Event) => {
      event.preventDefault();
      const offset = parseOffset(input.value, size);
      if (offset === null) app.toast(t("bad_offset"), true);
      else view.reveal(offset);
    };
    const form = el("form", { class: "row", onsubmit: go }, el("label", { class: "muted small" }, t("go_to")), input, el("button", { type: "submit", class: "btn small" }, t("go")));
    const evidence = range
      ? el(
          "div",
          { class: "drawer-evidence" },
          el("span", null, t("evidence_range", { offset: group(range.offset), hex: range.offset.toString(16).toUpperCase(), length: group(range.length) })),
          el("button", { type: "button", class: "btn small", onclick: () => view.reveal(range.offset) }, t("back_to_evidence")),
        )
      : null;
    drawer.append(drawerHead(path, status), el("div", { class: "drawer-tools" }, form, evidence), size === 0 ? el("div", { class: "drawer-note" }, el("p", null, t("empty_file"))) : view.element);
    // The view needs its size before it can say which rows are on screen.
    requestAnimationFrame(() => (range ? view.reveal(range.offset) : view.resize()));
  };

  const onMessage = (event: MessageEvent) => {
    if (event.source !== frame.contentWindow) return;
    const message = pageMessage(event.data);
    if (!message) return;
    if (message.kind === "ready") sync();
    else if (message.path !== undefined) void showBytes(message.path, message.kind === "evidence" ? { offset: message.offset ?? 0, length: message.length ?? 0 } : null);
  };
  window.addEventListener("message", onMessage);
  const onResize = () => hex?.resize();
  window.addEventListener("resize", onResize);

  /* ---------- export ---------- */

  const menu = el("div", { class: "menu", role: "menu", hidden: true });
  const exportButton = el("button", { type: "button", class: "btn", "aria-haspopup": "menu", "aria-expanded": "false" }, `${t("export")} ▾`);
  const toggleMenu = (open: boolean) => {
    menu.hidden = !open;
    exportButton.setAttribute("aria-expanded", String(open));
  };
  exportButton.addEventListener("click", () => toggleMenu(menu.hidden !== false));
  const closeMenuOutside = (event: MouseEvent) => {
    if (!menu.hidden && !menu.contains(event.target as Node) && event.target !== exportButton) toggleMenu(false);
  };
  document.addEventListener("click", closeMenuOutside);

  let exporting = false;
  const doExport = async (kind: string) => {
    toggleMenu(false);
    if (exporting) return;
    exporting = true;
    app.toast(t("exporting"));
    try {
      const saved = kind === "folder" ? await backend.exportFolder(entry.id, app.lang) : await backend.exportReport(entry.id, kind, app.lang);
      if (saved !== null) app.toast(t("exported", { path: saved }));
      else app.toast("");
    } catch (error) {
      app.toast(t("export_failed", { message: String(error) }), true);
    } finally {
      exporting = false;
    }
  };
  for (const kind of app.info.formats) {
    const label = kind === "txt" ? t("export_txt") : kind === "sbom" ? t("export_sbom") : (FORMAT_NAMES[kind] ?? kind);
    menu.appendChild(el("button", { type: "button", role: "menuitem", onclick: () => void doExport(kind) }, `${label}…`));
  }
  menu.append(el("hr", null), el("button", { type: "button", role: "menuitem", onclick: () => void doExport("folder") }, t("export_folder")));

  /* ---------- AI interpretation ---------- */

  const aiButton = el("button", { type: "button", class: "btn ai-toggle", "aria-pressed": "false" }, t("ai"));
  // The report page looks the finding up among its own; it is told nothing else.
  const showFinding = (id: string) => frame.contentWindow?.postMessage({ source: "analyze-anything-host", finding: id }, "*");
  const ai = aiPanel(app, entry, showFinding, (open) => aiButton.setAttribute("aria-pressed", String(open)));
  aiButton.addEventListener("click", () => ai.toggle());

  const counts = (["high", "medium", "low"] as const).filter((level) => entry[level] > 0).map((level) => el("span", { class: `sev ${level}` }, `${t(`sev_${level}`)} ${group(entry[level])}`));
  const toolbar = el(
    "header",
    { class: "toolbar" },
    el("button", { type: "button", class: "btn", onclick: actions.home }, `‹ ${t("home")}`),
    el("span", { class: "toolbar-name grow", title: entry.name }, visible(entry.name)),
    el("span", { class: "entry-counts" }, counts),
    aiButton,
    el("div", { class: "menu-anchor" }, exportButton, menu),
  );

  const element = el("main", { class: "report" }, toolbar, el("div", { class: "report-body" }, el("div", { class: "report-main" }, frame, drawer), ai.element));
  // When the view leaves the page its listeners go with it.
  const observer = new MutationObserver(() => {
    if (element.isConnected) return;
    window.removeEventListener("message", onMessage);
    window.removeEventListener("resize", onResize);
    document.removeEventListener("click", closeMenuOutside);
    observer.disconnect();
  });
  requestAnimationFrame(() => element.parentNode && observer.observe(element.parentNode, { childList: true }));

  return {
    element,
    sync,
    export: (kind) => void doExport(kind),
    showBytes,
    toggleAi: () => ai.toggle(),
    aiStep: (text) => ai.step(text),
    dismiss() {
      if (!menu.hidden) {
        toggleMenu(false);
        return true;
      }
      if (!drawer.hidden) {
        closeDrawer();
        return true;
      }
      return ai.close();
    },
  };
}
