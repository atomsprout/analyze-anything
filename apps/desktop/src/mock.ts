// A stand-in for the rest of the app, used when the page is opened in a plain browser: by
// `npm run dev` and by the page's tests. It is never loaded inside the app.
//
// It keeps a small history, plays an analysis as a sequence of steps, serves a sample report
// from tests/fixtures, and makes up bytes for the hex view. `window.__mock` lets a test drive
// what the real app would: dropping a file, choosing a menu item, the dialogs' answers.

import type { Backend, Chunk, Diff, Entry, Handlers, Interpretation, Lang, Step, WindowsSourceRoot } from "./types";

export interface MockControl {
  /** What the next "open" or "save" dialog answers; `null` is the user cancelling. */
  dialogAnswer: string | null;
  /** Milliseconds between the steps of a played analysis. */
  stepDelay: number;
  /** Makes the next analysis fail with this message. */
  failWith: string | null;
  /** Whether AI interpretation is set up. */
  aiReady: boolean;
  /** Makes the next interpretation fail with this message. */
  aiFailWith: string | null;
  /** The finding the sample interpretation cites, when a test wants a real one of the report. */
  aiCite: string | null;
  /** Every call made, in order, as `name(arguments)`. */
  calls: string[];
  offer(path: string): void;
  drag(over: boolean): void;
  menu(id: string): void;
}

const SIZE = 3 * 1024 * 1024 + 5;

function entry(id: string, name: string, at: number, counts: [number, number, number, number]): Entry {
  return { id, name, kind: "file", sha256: "ab".repeat(32), analyzed_at: at, tool_version: "0.1.0", source: `/Users/me/Downloads/${name}`, artifacts: 452, high: counts[0], medium: counts[1], low: counts[2], info: counts[3], partial: false };
}

const SAMPLE_DIFF: Diff = {
  a: { name: "Example-1.0.ipa", sha256: null, tool_version: "0.1.0", findings: 457, files: 452 },
  b: { name: "Example-1.1.ipa", sha256: null, tool_version: "0.1.0", findings: 460, files: 455 },
  findings: {
    unchanged: 442,
    added: [{ place: "Payload/Example.app/Info.plist", finding: { id: "1", section: "network", rule: "apple.ats-arbitrary-loads", params: { bundle: "Example.app" }, confidence: "verified", severity: "medium" } }],
    removed: [{ place: "Payload/Example.app/Example", finding: { id: "2", section: "hardening", rule: "binary.no-canary", params: { label: "" }, confidence: "derived", severity: "low" } }],
    changed: [
      {
        place: "Payload/Example.app/Info.plist",
        before: { id: "3", section: "overview", rule: "overview.version", params: { version: "1.0 (build 10)" }, confidence: "verified", severity: "info" },
        after: { id: "4", section: "overview", rule: "overview.version", params: { version: "1.1 (build 14)" }, confidence: "verified", severity: "info" },
      },
    ],
  },
  files: {
    unchanged: 436,
    added: [{ path: "Payload/Example.app/new.dat", size: 2048, sha256: "cd".repeat(32) }],
    removed: [{ path: "Payload/Example.app/old.dat", size: 512, sha256: "ef".repeat(32) }],
    changed: [{ path: "", before: { size: 19100177, sha256: "11".repeat(32) }, after: { size: 20794972, sha256: "22".repeat(32) } }],
  },
  rules: {
    "apple.ats-arbitrary-loads": { title_zh: "关闭了传输安全（ATS）", title_en: "App Transport Security is off", text_zh: "{bundle}：NSAllowsArbitraryLoads 为真。", text_en: "{bundle}: NSAllowsArbitraryLoads is true." },
    "binary.no-canary": { title_zh: "没有栈保护", title_en: "No stack canary", text_zh: "{label}没有引用栈保护函数。", text_en: "{label}The stack protector is not referenced." },
    "overview.version": { title_zh: "版本", title_en: "Version", text_zh: "版本：{version}。", text_en: "Version: {version}." },
  },
};

export function mockBackend(): Backend {
  let entries: Entry[] = [entry("20261119-101500", "Example-1.1.ipa", 1795083300, [1, 2, 4, 453]), entry("20261118-090000", "Example-1.0.ipa", 1794992400, [0, 0, 6, 451])];
  let handlers: Handlers | null = null;
  let live: string | null = null;
  let timers: number[] = [];
  const interpretations = new Map<string, Interpretation>();
  const sourceRoots = new Map<string, WindowsSourceRoot[]>();
  const control: MockControl = {
    dialogAnswer: "/Users/me/Downloads/Sample.dmg",
    stepDelay: 30,
    failWith: null,
    aiReady: true,
    aiFailWith: null,
    aiCite: null,
    calls: [],
    offer: (path) => handlers?.offered(path),
    drag: (over) => handlers?.drag(over),
    menu: (id) => handlers?.menu(id),
  };
  (window as unknown as { __mock: MockControl }).__mock = control;
  const called = (name: string, ...args: unknown[]) => control.calls.push(`${name}(${args.map((a) => JSON.stringify(a)).join(",")})`);

  return {
    async appInfo() {
      return { version: "0.1.0", formats: ["json", "html", "pdf", "md", "txt", "sarif", "sbom"], platform: "browser" };
    },
    async initialInput() {
      return null;
    },
    async pickInput(folder) {
      called("pickInput", folder);
      return control.dialogAnswer;
    },
    async startAnalysis(path, roots = []) {
      if (roots.length) called("startAnalysis", path, roots);
      else called("startAnalysis", path);
      const name = path.split("/").pop() ?? path;
      const steps: Step[] = [{ event: "listed", files: 1 }, { event: "reading", index: 1, total: 1, path: name }, { event: "unpacked", path: name, children: 40 }, { event: "analyzing", artifacts: 41 }];
      for (let i = 1; i <= 41; i += 4) steps.push({ event: "analyzed", index: i, total: 41, path: `${name}/Contents/file-${i}.bin` });
      steps.push({ event: "warning", code: "symlink_skipped", path: `${name}/link` });
      for (let i = 1; i <= 6; i += 1) steps.push({ event: "relating", index: i, total: 6, analyzer: ["content", "binary", "apple", "windows", "android", "correlate"][i - 1] ?? "" });
      steps.push({ event: "finished" });
      steps.forEach((step, index) => timers.push(window.setTimeout(() => handlers?.progress(step), control.stepDelay * (index + 1))));
      timers.push(
        window.setTimeout(
          () => {
            if (control.failWith !== null) {
              handlers?.failed(control.failWith);
              control.failWith = null;
              return;
            }
            const made = entry(`20261119-12${String(entries.length).padStart(4, "0")}`, name, 1795090000 + entries.length, [0, 1, 2, 300]);
            made.source = path;
            sourceRoots.set(made.id, roots.map((row) => ({ ...row })));
            entries = [made, ...entries];
            live = made.id;
            handlers?.done(made);
          },
          control.stepDelay * (steps.length + 2),
        ),
      );
    },
    async cancelAnalysis() {
      called("cancelAnalysis");
      timers.forEach((timer) => window.clearTimeout(timer));
      timers = [];
      window.setTimeout(() => handlers?.cancelled(), 20);
    },
    async historyList() {
      return entries.slice();
    },
    async historyRemove(id) {
      called("historyRemove", id);
      entries = entries.filter((e) => e.id !== id);
    },
    async historyClear() {
      called("historyClear");
      const count = entries.length;
      entries = [];
      return count;
    },
    async openReport(id) {
      called("openReport", id);
      const found = entries.find((e) => e.id === id);
      if (!found) throw new Error(`no report is kept under the name ${id}`);
      return { entry: found, live: live === id, source_present: found.source !== null, windows_source_roots: sourceRoots.get(id) ?? [] };
    },
    async readBytes(id, path, offset, length): Promise<Chunk> {
      called("readBytes", id, path, offset, length);
      if (live !== id) throw new Error("not-live");
      const count = Math.max(0, Math.min(length, SIZE - offset));
      let hex = "";
      // Each byte is its own offset folded to 8 bits, so a test can tell where it is.
      for (let i = 0; i < count; i += 1) hex += ((offset + i) & 0xff).toString(16).padStart(2, "0");
      return { hex, size: SIZE };
    },
    async exportReport(id, kind, lang) {
      called("exportReport", id, kind, lang);
      return control.dialogAnswer === null ? null : `/Users/me/Desktop/out.${kind}`;
    },
    async exportFolder(id, lang) {
      called("exportFolder", id, lang);
      return control.dialogAnswer === null ? null : "/Users/me/Desktop/Sample report";
    },
    async compareReports(before, after) {
      called("compareReports", before, after);
      return SAMPLE_DIFF;
    },
    async setMenuLanguage(lang) {
      called("setMenuLanguage", lang);
    },
    async aiStatus() {
      const config = "/Users/me/.analyze-anything/config.toml";
      return control.aiReady
        ? { ready: true, configured: true, who: "sample-model at https://example.test/v1", engine: "api", problem: null, config }
        : { ready: false, configured: false, who: null, engine: null, problem: "AI interpretation is not set up.", config };
    },
    async aiGet(id, lang) {
      return interpretations.get(`${id}:${lang}`) ?? null;
    },
    async aiInterpret(id, lang) {
      called("aiInterpret", id, lang);
      await new Promise((resolve) => window.setTimeout(resolve, control.stepDelay));
      handlers?.aiStep("looking up list_findings");
      await new Promise((resolve) => window.setTimeout(resolve, control.stepDelay * 3));
      if (control.aiFailWith !== null) {
        const message = control.aiFailWith;
        control.aiFailWith = null;
        throw new Error(message);
      }
      const first = control.aiCite ?? "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      const made: Interpretation = {
        engine: "api",
        model: "sample-model",
        language: lang,
        findings_total: 12,
        lookups: 2,
        statements_dropped: 1,
        summary: [{ text: lang === "zh" ? "这是一个磁盘映像。" : "This is a disk image.", findings: [first] }],
        notable: [{ text: lang === "zh" ? "它没有签名。" : "It is not signed. Its fingerprint is 43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab43238d512c1e5eb2d6569f4a3afbf552.", findings: ["fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", first] }],
        next_steps: [],
      };
      interpretations.set(`${id}:${lang}`, made);
      return made;
    },
    reportUrl: (_id: string, lang: Lang) => `/sample-report?lang=${lang}&host=1`,
    async on(given) {
      handlers = given;
    },
  };
}
