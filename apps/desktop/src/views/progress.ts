import type { App } from "../app";
import { clear, el } from "../dom";
import { advance, group, initialProgress, visible, type Progress } from "../format";
import type { Step } from "../types";

export interface ProgressView {
  element: HTMLElement;
  step(step: Step): void;
}

export function progressView(app: App, name: string, cancel: () => void): ProgressView {
  const { t } = app;
  let state: Progress = initialProgress();
  const stage = el("p", { class: "stage" }, t("stage_reading"));
  const bar = el("div", { class: "bar-fill" });
  const track = el("div", { class: "bar", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100", "aria-valuenow": "0" }, bar);
  const counts = el("p", { class: "muted" });
  const current = el("p", { class: "current mono" });
  const notes = el("p", { class: "muted small" });
  const button = el("button", { type: "button", class: "btn" }, t("cancel"));
  button.addEventListener("click", () => {
    button.disabled = true;
    clear(button).appendChild(document.createTextNode(t("cancelling")));
    cancel();
  });

  let scheduled = false;
  const draw = () => {
    scheduled = false;
    clear(stage).appendChild(document.createTextNode(t(`stage_${state.stage}`)));
    const percent = Math.round(state.fraction * 100);
    bar.style.width = `${percent}%`;
    track.setAttribute("aria-valuenow", String(percent));
    clear(counts).appendChild(document.createTextNode(state.total > 0 ? t("of", { done: group(state.done), total: group(state.total) }) : ""));
    clear(current).appendChild(document.createTextNode(visible(state.current)));
    const parts = [state.unpacked > 0 ? t("unpacked", { n: group(state.unpacked) }) : "", state.warnings > 0 ? t("warnings", { n: group(state.warnings) }) : ""];
    clear(notes).appendChild(document.createTextNode(parts.filter(Boolean).join(" · ")));
  };

  const element = el(
    "main",
    { class: "progress" },
    el("div", { class: "progress-box" }, el("p", { class: "muted" }, t("analyzing")), el("h2", null, visible(name)), stage, track, counts, current, notes, el("div", { class: "row end" }, button)),
  );
  return {
    element,
    step(step) {
      state = advance(state, step);
      // Steps can come faster than the screen is drawn; draw once per frame.
      if (!scheduled) {
        scheduled = true;
        requestAnimationFrame(draw);
      }
    },
  };
}
