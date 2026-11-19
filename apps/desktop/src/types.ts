// The shapes of what the app's two halves say to each other. They mirror the Rust types:
// `aa_app::history::Entry`, `aa_engine::Event`, `aa_export::diff::Diff`.

export type Lang = "zh" | "en";
export type Theme = "system" | "light" | "dark";
export type Severity = "high" | "medium" | "low" | "info";

export interface Entry {
  id: string;
  name: string;
  kind: "file" | "directory";
  sha256: string | null;
  analyzed_at: number;
  tool_version: string;
  source: string | null;
  artifacts: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  partial: boolean;
}

export type Step =
  | { event: "listed"; files: number }
  | { event: "reading"; index: number; total: number; path: string }
  | { event: "unpacked"; path: string; children: number }
  | { event: "analyzing"; artifacts: number }
  | { event: "analyzed"; index: number; total: number; path: string }
  | { event: "relating"; index: number; total: number; analyzer: string }
  | { event: "warning"; code: string; path: string | null }
  | { event: "finished" };

export interface Opened {
  entry: Entry;
  live: boolean;
  source_present: boolean;
}

export interface Chunk {
  hex: string;
  size: number;
}

export interface AppInfo {
  version: string;
  formats: string[];
}

export interface RuleText {
  title_zh: string;
  title_en: string;
  text_zh: string;
  text_en: string;
}

export interface Finding {
  id: string;
  section: string;
  rule: string;
  params: Record<string, unknown>;
  confidence: string;
  severity: Severity;
}

export interface Statement {
  place: string;
  finding: Finding;
}

export interface Changed {
  place: string;
  before: Finding;
  after: Finding;
}

export interface FileState {
  size: number;
  sha256: string | null;
}

export interface FileEntry extends FileState {
  path: string;
}

export interface FileChange {
  path: string;
  before: FileState;
  after: FileState;
}

export interface Side {
  name: string;
  sha256: string | null;
  tool_version: string;
  findings: number;
  files: number;
}

export interface Diff {
  a: Side;
  b: Side;
  findings: { unchanged: number; added: Statement[]; removed: Statement[]; changed: Changed[] };
  files: { unchanged: number; added: FileEntry[]; removed: FileEntry[]; changed: FileChange[] };
  rules: Record<string, RuleText>;
}

/** What the page can ask of the rest of the app. The real one talks to Rust; tests use a stand-in. */
export interface Backend {
  appInfo(): Promise<AppInfo>;
  initialInput(): Promise<string | null>;
  pickInput(folder: boolean): Promise<string | null>;
  startAnalysis(path: string): Promise<void>;
  cancelAnalysis(): Promise<void>;
  historyList(): Promise<Entry[]>;
  historyRemove(id: string): Promise<void>;
  historyClear(): Promise<number>;
  openReport(id: string): Promise<Opened>;
  readBytes(id: string, path: string, offset: number, length: number): Promise<Chunk>;
  exportReport(id: string, kind: string, lang: Lang): Promise<string | null>;
  exportFolder(id: string, lang: Lang): Promise<string | null>;
  compareReports(before: string, after: string): Promise<Diff>;
  setMenuLanguage(lang: Lang): Promise<void>;
  /** Where the frame showing report `id` loads it from. */
  reportUrl(id: string, lang: Lang): string;
  on(handlers: Handlers): Promise<void>;
}

export interface Handlers {
  progress(step: Step): void;
  done(entry: Entry): void;
  failed(message: string): void;
  cancelled(): void;
  /** The user dropped a file on the window or opened one with the app. */
  offered(path: string): void;
  /** Something is being dragged over the window, or no longer. */
  drag(over: boolean): void;
  menu(id: string): void;
}
