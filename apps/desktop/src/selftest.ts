// The app checking itself in its real window. Loaded only when the app was started for that
// (see selftest.rs). It uses the screens the way a user would, by clicking what is on them,
// and writes down what it saw. Nothing here is reachable in ordinary use.

import type { App } from "./app";
import { selftest } from "./backend";
import { fromHex } from "./format";
import type { ReportView } from "./views/report";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

async function waitFor<T>(what: string, probe: () => T | null | undefined | false, timeout = 15_000): Promise<T> {
  const deadline = Date.now() + timeout;
  for (;;) {
    const value = probe();
    if (value) return value;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(50);
  }
}

const one = <T extends Element = HTMLElement>(selector: string) => document.querySelector<T>(selector);
const all = <T extends Element = HTMLElement>(selector: string) => Array.from(document.querySelectorAll<T>(selector));
const text = (selector: string) => one(selector)?.textContent ?? "";

function click(what: string, element: Element | null | undefined): void {
  if (!(element instanceof HTMLElement)) throw new Error(`nothing to click: ${what}`);
  if (element instanceof HTMLButtonElement && element.disabled) throw new Error(`disabled: ${what}`);
  element.click();
}

export async function runSelftest(app: App, report: () => ReportView | null): Promise<void> {
  const checks: Check[] = [];
  const notes: Record<string, unknown> = {};
  const check = (name: string, ok: boolean, detail: unknown = "") => {
    checks.push({ name, ok, detail: typeof detail === "string" ? detail : JSON.stringify(detail) });
  };
  /** Runs one part; a failure in it is recorded and the next part still runs. */
  const part = async (name: string, body: () => Promise<void>) => {
    try {
      await body();
    } catch (error) {
      check(`${name}: completed`, false, error instanceof Error ? error.message : String(error));
    }
  };

  // The language is remembered by the web view, which the real app shares; put it back at the end.
  const languageBefore = app.lang;
  let framesReady = 0;
  window.addEventListener("message", (event) => {
    const data = event.data as { source?: string; kind?: string } | null;
    if (data && data.source === "analyze-anything-report" && data.kind === "ready" && event.source === one<HTMLIFrameElement>("iframe")?.contentWindow) framesReady += 1;
  });

  const goHome = async () => {
    if (!one(".home")) click("the Home button", one(".toolbar .btn"));
    await waitFor("the home screen", () => one(".home"));
  };
  const entries = () => all(".history .entry");
  /** Chooses "Open File…", which the plan answers, and waits for the report. */
  const analyzeNext = async () => {
    const before = framesReady;
    click("Open File", one(".drop-actions .btn.primary"));
    await waitFor("the progress screen", () => one(".progress"));
    let moved = false;
    await waitFor(
      "the report",
      () => {
        moved = moved || Number.parseFloat(one(".bar-fill")?.style.width || "0") > 0;
        return one(".report");
      },
      180_000,
    );
    await waitFor("the report page to load in its frame", () => framesReady > before, 60_000);
    return moved;
  };

  await part("start", async () => {
    await waitFor("the home screen", () => one(".home"));
    check("home: shown with an empty history", entries().length === 0, `${entries().length} entries`);
    // The page's own policy: a script written into the page must not run, nor may text be evaluated.
    const injected = document.createElement("script");
    injected.textContent = "window.__selftestInline = 1";
    document.head.appendChild(injected);
    let evaluated = false;
    try {
      // eslint-disable-next-line no-eval
      evaluated = (0, eval)("1") === 1;
    } catch {
      evaluated = false;
    }
    check("policy: an injected script does not run", !("__selftestInline" in window));
    check("policy: text cannot be evaluated as code", !evaluated);
    let fetched = "blocked";
    try {
      await fetch("https://example.invalid/", { mode: "no-cors" });
      fetched = "allowed";
    } catch {
      fetched = "blocked";
    }
    check("policy: the page cannot reach the network", fetched === "blocked");
  });

  let firstId = "";
  let firstName = "";
  await part("analysis", async () => {
    const moved = await analyzeNext();
    check("analysis: the progress bar moved", moved);
    check("analysis: the report is shown in its frame", framesReady >= 1);
    firstName = text(".toolbar-name");
    const list = await app.backend.historyList();
    firstId = list[0]?.id ?? "";
    check("analysis: the report was kept", list.length === 1 && list[0]?.name === firstName, list.map((e) => e.name));
    notes.first = list[0];
  });

  await part("bytes", async () => {
    const view = report();
    if (!view) throw new Error("no report on screen");
    const range = { offset: 20, length: 40 };
    await view.showBytes(firstName, range);
    await waitFor("the hex rows", () => all(".hexrow").length > 3 && all(".hexbytes").every((row) => !(row.textContent ?? "").includes("·"))).catch((error: unknown) => {
      const box = (selector: string) => {
        const rect = one(selector)?.getBoundingClientRect();
        return rect ? `${Math.round(rect.width)}x${Math.round(rect.height)}` : "absent";
      };
      const state = { rows: all(".hexrow").length, first: text(".hexrow").slice(0, 80), drawer: box(".drawer"), scroll: box(".hexscroll"), frame: box(".report-frame"), toast: text(".toast"), drawerText: text(".drawer").slice(0, 200) };
      throw new Error(`${String(error)}: ${JSON.stringify(state)}`);
    });
    const expected = fromHex((await app.backend.readBytes(firstId, firstName, 0, 64)).hex);
    const shown = all(".hexrow")
      .slice(0, 4)
      .map((row) => row.querySelector(".hexbytes")?.textContent ?? "")
      .join(" ")
      .trim()
      .split(/\s+/)
      .map((pair) => Number.parseInt(pair, 16));
    check("bytes: the first rows show the file's bytes", shown.length === 64 && shown.every((byte, i) => byte === expected[i]), shown.slice(0, 8));
    check("bytes: the evidence range is marked", all(".hexbytes mark").length === range.length, `${all(".hexbytes mark").length} marked`);
    check("bytes: the first offset is zero", text(".hexoffset") === "00000000", text(".hexoffset"));

    const input = one<HTMLInputElement>(".offset");
    if (!input) throw new Error("no offset field");
    input.value = "0x100";
    one<HTMLFormElement>(".drawer-tools form")?.requestSubmit();
    await waitFor("the view to move", () => text(".hexoffset") === "000000E0", 5000).catch(() => undefined);
    // Two rows of context are kept above the offset asked for.
    check("bytes: going to an offset moves the view", text(".hexoffset") === "000000E0", text(".hexoffset"));
    input.value = "not a number";
    one<HTMLFormElement>(".drawer-tools form")?.requestSubmit();
    await waitFor("the complaint", () => one(".toast.error"), 3000).catch(() => undefined);
    check("bytes: a bad offset is refused with a message", one(".toast.error") !== null);
    click("dismiss the message", one(".toast .plain"));

    let refused = "";
    try {
      await app.backend.readBytes(firstId, `${firstName}/../../etc/passwd`, 0, 16);
    } catch (error) {
      refused = String(error);
    }
    check("bytes: a file the report does not have is refused", refused !== "", refused);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    check("bytes: Escape closes the panel", one(".drawer")?.hidden === true);
  });

  await part("export", async () => {
    const saved: Record<string, string> = {};
    notes.export_lang = app.lang;
    const exportOne = async (label: string, pick: () => void) => {
      click("Export", one(".menu-anchor > .btn"));
      await waitFor("the export menu", () => one(".menu")?.hidden === false, 3000);
      pick();
      const toast = await waitFor(`the export of ${label}`, () => {
        const shown = one(".toast span")?.textContent ?? "";
        return one(".toast.error") ? shown : shown.includes("/") ? shown : null;
      }, 120_000);
      saved[label] = toast;
      check(`export: ${label}`, !one(".toast.error"), toast);
      click("dismiss the message", one(".toast .plain"));
    };
    const items = all(".menu button");
    check("export: the menu lists every format and the folder", items.length === app.info.formats.length + 1, `${items.length} items`);
    for (let i = 0; i < app.info.formats.length; i += 1) await exportOne(app.info.formats[i] ?? "", () => click("a format", all(".menu button")[i]));
    await exportOne("folder", () => click("the folder item", all(".menu button").at(-1)));
    notes.exports = saved;
  });

  await part("language and colours", async () => {
    const before = framesReady;
    const other = app.lang === "zh" ? "en" : "zh";
    const homeWord = { zh: "主页", en: "Home" };
    await selftest.menu(`lang:${other}`);
    await waitFor("the other language", () => text(".toolbar .btn").includes(homeWord[other]));
    await waitFor("the report page to load again", () => framesReady > before, 60_000);
    check("language: the menu switches the screen and reloads the report", document.documentElement.lang.startsWith(other));
    await selftest.menu("lang:en");
    await waitFor("English", () => text(".toolbar .btn").includes("Home"));
    await selftest.menu("theme:dark");
    await waitFor("dark colours", () => document.documentElement.getAttribute("data-theme") === "dark", 3000);
    await selftest.menu("theme:light");
    await waitFor("light colours", () => document.documentElement.getAttribute("data-theme") === "light", 3000);
    const light = getComputedStyle(document.body).backgroundColor;
    await selftest.menu("theme:system");
    await waitFor("system colours", () => !document.documentElement.hasAttribute("data-theme"), 3000);
    check("colours: the menu switches between dark, light and the system's", light === "rgb(246, 247, 249)", light);
  });

  let secondId = "";
  await part("history", async () => {
    await goHome();
    check("history: the report is listed", entries().length === 1, `${entries().length} entries`);
    click("the entry", one(".entry-main"));
    await waitFor("the report again", () => one(".report"));
    check("history: a listed report opens", text(".toolbar-name") === firstName, text(".toolbar-name"));
    await goHome();
    await analyzeNext();
    const list = await app.backend.historyList();
    secondId = list[0]?.id ?? "";
    notes.second = list[0];
    await goHome();
    check("history: the second analysis is listed first", entries().length === 2 && text(".entry-name") === list[0]?.name, text(".entry-name"));

    // The first report's analysis is closed now: its bytes are gone, and the app says so.
    click("the older entry", all(".entry-main")[1]);
    await waitFor("the older report", () => one(".report"));
    const view = report();
    if (!view) throw new Error("no report on screen");
    await view.showBytes(firstName, null);
    await waitFor("the explanation", () => one(".drawer-note"), 5000);
    check("history: an old report explains why its bytes cannot be shown", one(".hexrow") === null && one(".drawer-note .btn.primary") !== null, text(".drawer-note"));
  });

  await part("compare", async () => {
    await goHome();
    const boxes = all<HTMLInputElement>(".entry input[type=checkbox]");
    check("compare: the button waits for two reports", one<HTMLButtonElement>(".history-box header .btn")?.disabled === true);
    for (const box of boxes.slice(0, 2)) click("a checkbox", box);
    click("Compare", one(".history-box header .btn"));
    await waitFor("the comparison", () => one(".compare"));
    const expected = await app.backend.compareReports(firstId, secondId);
    const counts = all(".tile-count").map((node) => Number((node.textContent ?? "").replace(/,/g, "")));
    const wanted = [expected.findings.added.length, expected.findings.removed.length, expected.findings.changed.length, expected.findings.unchanged, expected.files.added.length, expected.files.removed.length, expected.files.changed.length, expected.files.unchanged];
    check("compare: the counts are those of the comparison, older report first", JSON.stringify(counts) === JSON.stringify(wanted), { counts, wanted });
    check("compare: both names are shown", text(".sides").includes(expected.a.name) && text(".sides").includes(expected.b.name));
    const rows = all(".diff-row").length;
    check("compare: differences are listed", rows > 0 || wanted.slice(0, 3).concat(wanted.slice(4, 7)).every((n) => n === 0), `${rows} rows`);
    click("Swap", all(".toolbar .btn")[1]);
    await waitFor("the swapped comparison", () => (all(".side strong")[0]?.textContent ?? "") === expected.b.name, 10_000);
    check("compare: swapping puts the newer report first", true);
    notes.compare = wanted;
  });

  await part("deleting", async () => {
    await goHome();
    click("delete", one(".entry > .plain"));
    await waitFor("the question", () => one(".dialog"));
    click("Cancel", one(".dialog .btn"));
    await sleep(200);
    check("delete: cancelling keeps the report", entries().length === 2);
    click("delete", one(".entry > .plain"));
    await waitFor("the question", () => one(".dialog"));
    click("Delete", one(".dialog .btn.danger"));
    await waitFor("one entry", () => entries().length === 1);
    check("delete: confirming removes the report", (await app.backend.historyList()).length === 1);
    click("Clear history", one(".history-box header .btn.quiet"));
    await waitFor("the question", () => one(".dialog"));
    click("Clear", one(".dialog .btn.danger"));
    await waitFor("an empty history", () => entries().length === 0 && one(".history-box p"));
    check("delete: clearing empties the history", (await app.backend.historyList()).length === 0);
  });

  await part("cancelling", async () => {
    const plan = await selftest.plan();
    if (!plan?.slow) return;
    await goHome();
    click("Open File", one(".drop-actions .btn.primary"));
    await waitFor("the progress screen", () => one(".progress"));
    await sleep(400);
    const started = Date.now();
    click("Cancel", one(".progress .btn"));
    await waitFor("the home screen", () => one(".home"), 20_000);
    const took = Date.now() - started;
    check("cancel: the app returns to the home screen", true, `${took} ms`);
    check("cancel: nothing was kept", (await app.backend.historyList()).length === 0);
    notes.cancel_ms = took;
  });

  await selftest.menu(`lang:${languageBefore}`).catch(() => undefined);
  await sleep(300);
  await selftest.finish({ passed: checks.filter((c) => c.ok).length, failed: checks.filter((c) => !c.ok).length, checks, notes });
}
