// Small pure functions: text for sizes, times and rule sentences, and the arithmetic of the hex view.

import type { Lang, RuleText } from "./types";

/** A byte count for reading: `1.5 MB`. Sizes below 1024 are exact. */
export function bytes(count: number): string {
  if (count < 1024) return `${count} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = count / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 100 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

/** A whole number with thousands separators. */
export function group(count: number): string {
  return String(count).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/**
 * Fills the `{name}` placeholders of a rule's text from a finding's params, the way the Rust
 * side does (`aa_core::fill`): strings as they are, other values as JSON, and a placeholder
 * without a param left in place so that a mistake shows.
 */
export function fill(template: string, params: Record<string, unknown>): string {
  return template.replace(/\{([^{}]*)\}/g, (whole, name: string) => {
    if (!Object.prototype.hasOwnProperty.call(params, name)) return whole;
    const value = params[name];
    return typeof value === "string" ? value : JSON.stringify(value);
  });
}

/** The sentence a finding makes, as `title: text`, or the rule's id when its text is missing. */
export function sentence(rules: Record<string, RuleText>, rule: string, params: Record<string, unknown>, lang: Lang): { title: string; text: string } {
  const words = Object.prototype.hasOwnProperty.call(rules, rule) ? rules[rule] : undefined;
  if (!words) return { title: rule, text: "" };
  return lang === "zh" ? { title: words.title_zh, text: fill(words.text_zh, params) } : { title: words.title_en, text: fill(words.text_en, params) };
}

/** Characters that would hide or reorder text are shown as their code point. */
export function visible(text: string): string {
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/g, (c) => {
    return `<U+${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, "0")}>`;
  });
}

/* ---------- the hex view ---------- */

export const BYTES_PER_ROW = 16;
export const ROW_HEIGHT = 20;
/** Browsers stop laying out elements taller than a few million pixels; the view stays below. */
export const MAX_SCROLL_HEIGHT = 6_000_000;
/** Bytes fetched at once. A multiple of the row length, so a chunk starts on a row. */
export const CHUNK = 64 * 1024;

export function rowCount(size: number): number {
  return Math.ceil(size / BYTES_PER_ROW);
}

/** Height of the scrolling area for a file of `size` bytes. */
export function scrollHeight(size: number): number {
  return Math.min(rowCount(size) * ROW_HEIGHT, MAX_SCROLL_HEIGHT);
}

/**
 * The first row to draw when the view is scrolled to `scrollTop`. For a file small enough that
 * every row has its own pixels this is plain division; for a larger one the scroll position is
 * read as a fraction of the way through the file.
 */
export function firstRow(scrollTop: number, viewport: number, size: number): number {
  const rows = rowCount(size);
  const visibleRows = Math.max(1, Math.floor(viewport / ROW_HEIGHT));
  const lastStart = Math.max(0, rows - visibleRows);
  const natural = rows * ROW_HEIGHT;
  if (natural <= MAX_SCROLL_HEIGHT) return Math.min(lastStart, Math.max(0, Math.floor(scrollTop / ROW_HEIGHT)));
  const travel = Math.max(1, MAX_SCROLL_HEIGHT - viewport);
  const fraction = Math.min(1, Math.max(0, scrollTop / travel));
  return Math.round(fraction * lastStart);
}

/** The scroll position that puts `row` at the top; the inverse of `firstRow`. */
export function scrollTopFor(row: number, viewport: number, size: number): number {
  const rows = rowCount(size);
  const visibleRows = Math.max(1, Math.floor(viewport / ROW_HEIGHT));
  const lastStart = Math.max(0, rows - visibleRows);
  const target = Math.min(lastStart, Math.max(0, row));
  const natural = rows * ROW_HEIGHT;
  if (natural <= MAX_SCROLL_HEIGHT) return target * ROW_HEIGHT;
  const travel = Math.max(1, MAX_SCROLL_HEIGHT - viewport);
  return lastStart === 0 ? 0 : (target / lastStart) * travel;
}

/** An offset as the hex view shows it: eight digits, more for files beyond 4 GB. */
export function offsetText(offset: number): string {
  return offset.toString(16).toUpperCase().padStart(8, "0");
}

/** The character shown for a byte in the text column. */
export function printable(byte: number): string {
  return byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : "·";
}

/** Decodes the hexadecimal text the app sends bytes as. */
export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/**
 * Reads an offset typed by the user: decimal, or hexadecimal with `0x` in front or `h` behind.
 * `null` when it is not a number or lies outside the file.
 */
export function parseOffset(text: string, size: number): number | null {
  const trimmed = text.trim().toLowerCase().replace(/[,_\s]/g, "");
  let value: number;
  if (/^0x[0-9a-f]+$/.test(trimmed)) value = Number.parseInt(trimmed.slice(2), 16);
  else if (/^[0-9a-f]+h$/.test(trimmed)) value = Number.parseInt(trimmed.slice(0, -1), 16);
  else if (/^[0-9]+$/.test(trimmed)) value = Number.parseInt(trimmed, 10);
  else return null;
  return Number.isSafeInteger(value) && value >= 0 && value < Math.max(size, 1) ? value : null;
}

/* ---------- progress ---------- */

import type { Step } from "./types";

export interface Progress {
  stage: "reading" | "analyzing" | "relating" | "finishing";
  /** 0 to 1 over the whole run. */
  fraction: number;
  done: number;
  total: number;
  /** The file or analyzer being worked on. */
  current: string;
  warnings: number;
  unpacked: number;
}

export function initialProgress(): Progress {
  return { stage: "reading", fraction: 0, done: 0, total: 0, current: "", warnings: 0, unpacked: 0 };
}

/**
 * Where a run stands after one more step. The bar gives reading a quarter, the per-file
 * analysis most of the rest and the tree passes the end; it never moves backwards.
 */
export function advance(before: Progress, step: Step): Progress {
  const next = { ...before };
  const share = (from: number, width: number, index: number, total: number) => from + width * (total > 0 ? Math.min(1, index / total) : 0);
  switch (step.event) {
    case "listed":
      next.total = step.files;
      break;
    case "reading":
      next.stage = "reading";
      next.done = step.index;
      next.total = step.total;
      next.current = step.path;
      next.fraction = share(0, 0.25, step.index, step.total);
      break;
    case "unpacked":
      next.unpacked += 1;
      next.current = step.path;
      break;
    case "analyzing":
      next.stage = "analyzing";
      next.done = 0;
      next.total = step.artifacts;
      next.fraction = 0.25;
      break;
    case "analyzed":
      next.stage = "analyzing";
      next.done = step.index;
      next.total = step.total;
      next.current = step.path;
      next.fraction = share(0.25, 0.6, step.index, step.total);
      break;
    case "relating":
      next.stage = "relating";
      next.done = step.index;
      next.total = step.total;
      next.current = step.analyzer;
      next.fraction = share(0.85, 0.14, step.index, step.total);
      break;
    case "warning":
      next.warnings += 1;
      break;
    case "finished":
      next.stage = "finishing";
      next.fraction = 1;
      break;
  }
  next.fraction = Math.max(before.fraction, next.fraction);
  return next;
}
