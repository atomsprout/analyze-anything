import type { App } from "../app";
import { clear, el } from "../dom";
import { group } from "../format";
import type { Entry } from "../types";

export interface HomeActions {
  pick(folder: boolean): void;
  open(id: string): void;
  compare(before: string, after: string): void;
}

export interface HomeView {
  element: HTMLElement;
  /** Shows that something is being dragged over the window. */
  setDragging(over: boolean): void;
}

function when(entry: Entry, lang: string): string {
  return new Date(entry.analyzed_at * 1000).toLocaleString(lang === "zh" ? "zh-CN" : "en", { dateStyle: "medium", timeStyle: "short" });
}

export function homeView(app: App, entries: Entry[], actions: HomeActions, refresh: () => void): HomeView {
  const { t } = app;
  const dropTitle = el("h2", null, t("drop_here"));
  const drop = el(
    "section",
    { class: "drop" },
    el("div", { class: "drop-mark", "aria-hidden": "true" }, "⤓"),
    dropTitle,
    el("p", { class: "muted" }, t("drop_types")),
    el(
      "div",
      { class: "drop-actions" },
      el("button", { type: "button", class: "btn primary", onclick: () => actions.pick(false) }, t("open_file")),
      el("button", { type: "button", class: "btn", onclick: () => actions.pick(true) }, t("open_folder")),
    ),
    el("p", { class: "muted small" }, t("read_only")),
  );

  // Two reports are picked for a comparison, the older of the two being "before".
  const picked: string[] = [];
  const compare = el("button", { type: "button", class: "btn", disabled: true, title: t("compare_hint") }, t("compare"));
  compare.addEventListener("click", () => {
    const chosen = entries.filter((entry) => picked.includes(entry.id)).sort((a, b) => a.analyzed_at - b.analyzed_at || a.id.localeCompare(b.id));
    const [before, after] = chosen;
    if (before && after) actions.compare(before.id, after.id);
  });

  const list = el("ul", { class: "history" });
  const boxes: HTMLInputElement[] = [];
  const syncPicks = () => {
    compare.disabled = picked.length !== 2;
    for (const box of boxes) box.disabled = picked.length === 2 && !box.checked;
  };

  for (const entry of entries) {
    const box = el("input", { type: "checkbox", "aria-label": t("select_for_compare"), title: t("select_for_compare") });
    box.addEventListener("change", () => {
      if (box.checked) picked.push(entry.id);
      else picked.splice(picked.indexOf(entry.id), 1);
      syncPicks();
    });
    boxes.push(box);
    const counts = (["high", "medium", "low"] as const)
      .filter((level) => entry[level] > 0)
      .map((level) => el("span", { class: `sev ${level}` }, `${t(`sev_${level}`)} ${group(entry[level])}`));
    const remove = async () => {
      if (!(await app.confirm(t("delete_confirm", { name: entry.name }), t("delete")))) return;
      try {
        await app.backend.historyRemove(entry.id);
      } catch (error) {
        app.toast(String(error), true);
      }
      refresh();
    };
    list.appendChild(
      el(
        "li",
        { class: "entry" },
        box,
        el(
          "button",
          { type: "button", class: "entry-main", onclick: () => actions.open(entry.id) },
          el("span", { class: "entry-name" }, entry.name),
          el(
            "span",
            { class: "entry-meta" },
            when(entry, app.lang),
            " · ",
            t("files", { n: group(entry.artifacts) }),
            entry.partial ? el("span", { class: "tag", title: t("partial_title") }, t("partial")) : null,
          ),
        ),
        el("span", { class: "entry-counts" }, counts),
        el("button", { type: "button", class: "plain", title: t("delete"), "aria-label": t("delete"), onclick: () => void remove() }, "✕"),
      ),
    );
  }

  const clearAll = async () => {
    if (!(await app.confirm(t("clear_confirm", { n: entries.length }), t("clear_history")))) return;
    try {
      await app.backend.historyClear();
    } catch (error) {
      app.toast(String(error), true);
    }
    refresh();
  };
  const history = el(
    "section",
    { class: "history-box" },
    el(
      "header",
      { class: "row" },
      el("h3", null, t("history")),
      el("span", { class: "muted small grow" }, t("history_note")),
      entries.length >= 2 ? compare : null,
      entries.length > 0 ? el("button", { type: "button", class: "btn quiet", onclick: () => void clearAll() }, t("clear_history")) : null,
    ),
    entries.length > 0 ? list : el("p", { class: "muted" }, t("history_empty")),
  );

  const element = el(
    "main",
    { class: "home" },
    el("header", { class: "home-head" }, el("h1", null, "Analyze Anything"), el("p", { class: "muted" }, t("tagline"))),
    drop,
    history,
    el("footer", { class: "muted small" }, t("version", { version: app.info.version })),
  );
  return {
    element,
    setDragging(over) {
      drop.classList.toggle("over", over);
      clear(dropTitle).appendChild(document.createTextNode(t(over ? "drop_release" : "drop_here")));
    },
  };
}
