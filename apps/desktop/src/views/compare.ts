import type { App } from "../app";
import { clear, el } from "../dom";
import { bytes as sizeText, group, sentence, visible } from "../format";
import type { Changed, Diff, FileChange, FileEntry, Finding, Statement } from "../types";

export interface CompareActions {
  home(): void;
  swap(): void;
}

/** Rows drawn at first and added by each "show more". */
const PAGE = 200;

export function compareView(app: App, diff: Diff, actions: CompareActions): HTMLElement {
  const { t } = app;
  let filter = "";

  const says = (finding: Finding) => {
    const { title, text } = sentence(diff.rules, finding.rule, finding.params, app.lang);
    return { title: visible(title), text: visible(text) };
  };
  const badge = (finding: Finding) => el("span", { class: `sev ${finding.severity}` }, t(`sev_${finding.severity}`));
  const place = (path: string) => (path ? el("span", { class: "mono path" }, visible(path)) : null);
  const short = (hash: string | null) => (hash ? hash.slice(0, 12) : "?");

  const statementRow = (mark: string) => (statement: Statement) => {
    const { title, text } = says(statement.finding);
    return { text: `${title} ${text} ${statement.place}`, node: () => el("li", { class: "diff-row" }, el("span", { class: "mark" }, mark), badge(statement.finding), el("div", { class: "grow" }, el("strong", null, title), " ", text, place(statement.place))) };
  };
  const changedRow = (change: Changed) => {
    const now = says(change.after);
    const was = says(change.before);
    return {
      text: `${now.title} ${now.text} ${was.text} ${change.place}`,
      node: () =>
        el("li", { class: "diff-row" }, el("span", { class: "mark" }, "~"), badge(change.after), el("div", { class: "grow" }, el("strong", null, now.title), " ", now.text, el("div", { class: "was" }, t("was"), was.text), place(change.place))),
    };
  };
  const fileRow = (mark: string) => (file: FileEntry) => ({
    text: file.path,
    node: () => el("li", { class: "diff-row" }, el("span", { class: "mark" }, mark), el("span", { class: "mono path grow" }, visible(file.path)), el("span", { class: "muted small" }, sizeText(file.size))),
  });
  const fileChangeRow = (change: FileChange) => ({
    text: change.path,
    node: () =>
      el(
        "li",
        { class: "diff-row" },
        el("span", { class: "mark" }, "~"),
        el("span", { class: "mono path grow" }, change.path ? visible(change.path) : t("the_input")),
        el("span", { class: "muted small mono" }, `${sizeText(change.before.size)} → ${sizeText(change.after.size)} · ${short(change.before.sha256)} → ${short(change.after.sha256)}`),
      ),
  });

  interface Row {
    text: string;
    node(): HTMLElement;
  }
  const lists: { title: string; rows: Row[] }[] = [
    { title: `${t("findings")} · ${t("added")}`, rows: diff.findings.added.map(statementRow("+")) },
    { title: `${t("findings")} · ${t("removed")}`, rows: diff.findings.removed.map(statementRow("−")) },
    { title: `${t("findings")} · ${t("changed")}`, rows: diff.findings.changed.map(changedRow) },
    { title: `${t("files_tab")} · ${t("added")}`, rows: diff.files.added.map(fileRow("+")) },
    { title: `${t("files_tab")} · ${t("files_removed")}`, rows: diff.files.removed.map(fileRow("−")) },
    { title: `${t("files_tab")} · ${t("changed")}`, rows: diff.files.changed.map(fileChangeRow) },
  ];

  const body = el("div", { class: "diff-lists" });
  const draw = () => {
    clear(body);
    const needle = filter.trim().toLowerCase();
    for (const list of lists) {
      const rows = needle ? list.rows.filter((row) => row.text.toLowerCase().includes(needle)) : list.rows;
      const items = el("ul", { class: "diff-list" });
      let shown = 0;
      const more = el("button", { type: "button", class: "btn small" });
      const add = () => {
        const end = Math.min(rows.length, shown + PAGE);
        for (; shown < end; shown += 1) items.appendChild((rows[shown] as Row).node());
        more.hidden = shown >= rows.length;
        clear(more).appendChild(document.createTextNode(t("show_more", { n: Math.min(PAGE, rows.length - shown) })));
      };
      more.addEventListener("click", add);
      add();
      const section = el("details", { class: "diff-section" }, el("summary", null, list.title, el("span", { class: "count" }, group(rows.length))), rows.length ? items : el("p", { class: "muted" }, t("none_in_list")), more);
      section.open = rows.length > 0;
      body.appendChild(section);
    }
  };
  draw();

  let timer = 0;
  const search = el("input", { type: "search", class: "grow", placeholder: t("filter"), "aria-label": t("filter") });
  search.addEventListener("input", () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      filter = search.value;
      draw();
    }, 120);
  });

  const tile = (label: string, count: number, kind: string) => el("div", { class: `tile ${kind}` }, el("span", { class: "tile-count" }, group(count)), el("span", { class: "tile-label" }, label));
  const empty = [diff.findings.added, diff.findings.removed, diff.findings.changed, diff.files.added, diff.files.removed, diff.files.changed].every((list) => list.length === 0);

  return el(
    "main",
    { class: "compare" },
    el("header", { class: "toolbar" }, el("button", { type: "button", class: "btn", onclick: actions.home }, `‹ ${t("home")}`), el("span", { class: "toolbar-name grow" }, t("comparison")), el("button", { type: "button", class: "btn", onclick: actions.swap }, `⇄ ${t("swap")}`)),
    el(
      "div",
      { class: "compare-body" },
      el(
        "section",
        { class: "sides" },
        el("div", { class: "side" }, el("span", { class: "muted small" }, t("before")), el("strong", null, visible(diff.a.name)), el("span", { class: "muted small" }, `${group(diff.a.findings)} ${t("findings")} · ${t("files", { n: group(diff.a.files) })}`)),
        el("div", { class: "arrow", "aria-hidden": "true" }, "→"),
        el("div", { class: "side" }, el("span", { class: "muted small" }, t("after")), el("strong", null, visible(diff.b.name)), el("span", { class: "muted small" }, `${group(diff.b.findings)} ${t("findings")} · ${t("files", { n: group(diff.b.files) })}`)),
      ),
      el(
        "section",
        { class: "tiles" },
        el("div", { class: "tile-group" }, el("h3", null, t("findings")), tile(t("added"), diff.findings.added.length, "plus"), tile(t("removed"), diff.findings.removed.length, "minus"), tile(t("changed"), diff.findings.changed.length, "delta"), tile(t("unchanged"), diff.findings.unchanged, "same")),
        el("div", { class: "tile-group" }, el("h3", null, t("files_tab")), tile(t("added"), diff.files.added.length, "plus"), tile(t("files_removed"), diff.files.removed.length, "minus"), tile(t("changed"), diff.files.changed.length, "delta"), tile(t("unchanged"), diff.files.unchanged, "same")),
      ),
      el("p", { class: "muted small" }, t("compare_how")),
      empty ? el("p", { class: "notice" }, t("no_differences")) : [el("div", { class: "row" }, search), body],
    ),
  );
}
