import type { App } from "../app";
import { clear, el } from "../dom";
import { sourceRoots } from "../source-roots";
import type { WindowsSourceRoot } from "../types";

export function sourceRootPanel(app: App, initial: WindowsSourceRoot[] = []) {
  const rows = initial.map((row) => ({ ...row }));
  const list = el("div", { class: "source-root-list" });
  const add = el("button", { type: "button", class: "btn", onclick: () => { rows.push({ inf: "", root: "" }); draw(); } }, app.t("source_root_add"));
  const draw = () => {
    clear(list);
    rows.forEach((row, index) => {
      const inf = el("input", { type: "text", value: row.inf, placeholder: "driver.inf", "aria-label": app.t("source_root_inf"), oninput: () => { row.inf = inf.value; } });
      const root = el("input", { type: "text", value: row.root, placeholder: ".", "aria-label": app.t("source_root_directory"), oninput: () => { row.root = root.value; } });
      inf.maxLength = root.maxLength = 8192;
      inf.spellcheck = root.spellcheck = false;
      list.append(el("div", { class: "source-root-row" }, el("label", null, app.t("source_root_inf"), inf), el("label", null, app.t("source_root_directory"), root),
        el("button", { type: "button", class: "plain", "aria-label": app.t("source_root_remove"), onclick: () => { rows.splice(index, 1); draw(); } }, "✕")));
    });
    add.disabled = rows.length >= 32;
  };
  draw();
  return {
    element: el("details", { class: "source-root-options" }, el("summary", null, app.t("source_root_title")), el("p", { class: "muted small" }, app.t("source_root_hint")), list, add),
    draft: () => rows.map((row) => ({ ...row })),
    values: () => sourceRoots(rows),
  };
}
