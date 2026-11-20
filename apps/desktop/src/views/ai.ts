// The optional AI interpretation of the report on screen: a panel beside the report.
//
// Nothing is asked of any model until the user presses the button, and the panel says first who
// would be asked and what is handed over. What comes back is shown as the model's text, marked
// as such; each statement carries the findings it rests on, and clicking one shows that finding
// in the report itself.

import type { App } from "../app";
import { clear, el } from "../dom";
import type { AiStatement, AiStatus, Entry, Interpretation, Lang } from "../types";

export interface AiPanel {
  element: HTMLElement;
  /** Opens the panel, or closes it when it is open. */
  toggle(): void;
  /** Closes the panel; false when it was not open. */
  close(): boolean;
  /** What the interpretation being written is doing right now. */
  step(text: string): void;
}

/** Interpretations being written, by report and language, so that a panel opened again while
 *  one is under way waits for that one instead of asking twice. */
const running = new Map<string, Promise<Interpretation>>();

const SETUP = ["analyze-anything ai claude", "analyze-anything ai codex", "analyze-anything ai ollama --model qwen3", "analyze-anything ai api --provider anthropic --api-key-stdin"];

export function aiPanel(app: App, entry: Entry, showFinding: (id: string) => void, onToggle: (open: boolean) => void): AiPanel {
  const { t, backend } = app;
  const lang: Lang = app.lang;
  const key = `${entry.id}:${lang}`;
  const body = el("div", { class: "ai-body" });
  const close = () => {
    if (element.hidden) return false;
    element.hidden = true;
    onToggle(false);
    return true;
  };
  const element = el(
    "aside",
    { class: "ai-panel", hidden: true, "aria-label": t("ai") },
    el("header", { class: "ai-head" }, el("strong", { class: "grow" }, t("ai")), el("button", { type: "button", class: "plain", title: t("close"), "aria-label": t("close"), onclick: close }, "✕")),
    body,
  );
  let loaded = false;
  let stepLine: HTMLElement | null = null;

  const statements = (title: string, list: AiStatement[]) =>
    list.length === 0
      ? null
      : el(
          "section",
          { class: "ai-section" },
          el("h3", null, title),
          el(
            "ul",
            { class: "ai-list" },
            list.map((statement) =>
              el(
                "li",
                { class: "ai-statement" },
                el("span", null, statement.text),
                el(
                  "span",
                  { class: "ai-cites" },
                  statement.findings.map((id) => el("button", { type: "button", class: "cite mono", title: t("ai_show_finding"), onclick: () => showFinding(id) }, id.slice(0, 10))),
                ),
              ),
            ),
          ),
        );

  const showResult = (made: Interpretation, status: AiStatus | null) => {
    clear(body).append(
      el("p", { class: "ai-banner" }, t("ai_generated", { model: made.model })),
      ...[statements(t("ai_summary"), made.summary), statements(t("ai_notable"), made.notable), statements(t("ai_next"), made.next_steps)].filter((node): node is HTMLElement => node !== null),
    );
    if (made.statements_dropped > 0) body.append(el("p", { class: "muted small" }, t("ai_dropped", { n: made.statements_dropped })));
    if (status?.ready) body.append(el("div", { class: "ai-actions" }, el("button", { type: "button", class: "btn", onclick: () => void interpret(status) }, t("ai_again"))));
  };

  const showSetup = (status: AiStatus) => {
    clear(body).append(
      el("p", null, t("ai_intro")),
      el("p", { class: status.configured ? "ai-problem" : "muted" }, status.configured ? t("ai_problem", { problem: status.problem ?? "" }) : t("ai_off")),
      el("p", null, t("ai_setup")),
      el("pre", { class: "ai-commands mono" }, SETUP.join("\n")),
      el("p", { class: "muted small" }, t("ai_setup_note", { path: status.config })),
      el("div", { class: "ai-actions" }, el("button", { type: "button", class: "btn", onclick: () => void load() }, t("ai_recheck"))),
    );
  };

  const showOffer = (status: AiStatus, failure: string | null) => {
    clear(body).append(el("p", null, t("ai_intro")), el("p", { class: "ai-sends" }, t("ai_sends", { who: status.who ?? "" })));
    if (failure !== null) body.append(el("p", { class: "ai-problem", role: "alert" }, t("ai_failed", { message: failure })));
    body.append(el("div", { class: "ai-actions" }, el("button", { type: "button", class: "btn primary", onclick: () => void interpret(status) }, t("ai_start"))));
  };

  const wait = async (work: Promise<Interpretation>, status: AiStatus) => {
    stepLine = el("p", { class: "muted small ai-step" });
    clear(body).append(el("p", { class: "ai-running", role: "status" }, el("span", { class: "spinner", "aria-hidden": "true" }), t("ai_running")), el("p", { class: "ai-sends" }, t("ai_sends", { who: status.who ?? "" })), stepLine);
    try {
      showResult(await work, status);
    } catch (error) {
      showOffer(status, error instanceof Error ? error.message : String(error));
    } finally {
      stepLine = null;
    }
  };

  const interpret = (status: AiStatus) => {
    const work = backend.aiInterpret(entry.id, lang);
    running.set(key, work);
    const done = () => {
      if (running.get(key) === work) running.delete(key);
    };
    work.then(done, done);
    return wait(work, status);
  };

  const load = async () => {
    clear(body).append(el("p", { class: "muted" }, "…"));
    try {
      const status = await backend.aiStatus();
      const under = running.get(key);
      if (under) return await wait(under, status);
      const made = await backend.aiGet(entry.id, lang);
      if (made) showResult(made, status);
      else if (status.ready) showOffer(status, null);
      else showSetup(status);
    } catch (error) {
      clear(body).append(el("p", { class: "ai-problem", role: "alert" }, String(error)));
    }
  };

  return {
    element,
    toggle() {
      if (close()) return;
      element.hidden = false;
      onToggle(true);
      if (!loaded) {
        loaded = true;
        void load();
      }
    },
    close,
    step(text) {
      if (stepLine) stepLine.textContent = text;
    },
  };
}
