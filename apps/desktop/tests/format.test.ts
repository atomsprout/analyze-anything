import { describe, expect, it } from "vitest";
import {
  BYTES_PER_ROW,
  MAX_SCROLL_HEIGHT,
  ROW_HEIGHT,
  advance,
  bytes,
  fill,
  firstRow,
  fromHex,
  group,
  initialProgress,
  offsetText,
  parseOffset,
  printable,
  rowCount,
  scrollHeight,
  scrollTopFor,
  sentence,
  visible,
} from "../src/format";
import { ALL_WORDS, word } from "../src/i18n";
import type { Step } from "../src/types";

describe("text", () => {
  it("writes sizes for reading", () => {
    expect([0, 1023, 1024, 1536, 150 * 1024, 5 * 1024 ** 3].map(bytes)).toEqual(["0 B", "1023 B", "1.0 KB", "1.5 KB", "150 KB", "5.0 GB"]);
    expect(group(1234567)).toBe("1,234,567");
    expect(group(999)).toBe("999");
  });

  it("fills a rule's text the way the report does", () => {
    expect(fill("{a} and {b}, {a} again", { a: "x", b: 2 })).toBe("x and 2, x again");
    expect(fill("{list} {flag}", { list: ["p", "q"], flag: true })).toBe('["p","q"] true');
    // A placeholder without a param stays, so a mistake in a rule shows.
    expect(fill("{missing} {}", { other: 1 })).toBe("{missing} {}");
    // A param's value is never read as a template, and object properties are not params.
    expect(fill("{a}", { a: "{b}", b: "no" })).toBe("{b}");
    expect(fill("{constructor} {toString}", {})).toBe("{constructor} {toString}");
  });

  it("makes a sentence in either language and falls back to the rule id", () => {
    const rules = { r: { title_zh: "标题", title_en: "Title", text_zh: "有 {n} 个", text_en: "{n} of them" } };
    expect(sentence(rules, "r", { n: 3 }, "zh")).toEqual({ title: "标题", text: "有 3 个" });
    expect(sentence(rules, "r", { n: 3 }, "en")).toEqual({ title: "Title", text: "3 of them" });
    expect(sentence(rules, "unknown", {}, "en")).toEqual({ title: "unknown", text: "" });
    expect(sentence(rules, "constructor", {}, "en")).toEqual({ title: "constructor", text: "" });
  });

  it("shows characters that hide or reorder text", () => {
    expect(visible("a\u202eb\u200bc\u0000")).toBe("a<U+202E>b<U+200B>c<U+0000>");
    expect(visible("plain 中文\n")).toBe("plain 中文\n");
  });

  it("has every word in both languages, with the same placeholders", () => {
    for (const key of ALL_WORDS) {
      const [zh, en] = [word("zh", key), word("en", key)];
      expect(zh.length, key).toBeGreaterThan(0);
      expect(en.length, key).toBeGreaterThan(0);
      const names = (text: string) => (text.match(/\{\w+\}/g) ?? []).sort();
      expect(names(zh), key).toEqual(names(en));
    }
    expect(word("en", "files", { n: 3 })).toBe("3 files");
    expect(word("en", "of", { done: 1 })).toBe("1 of {total}");
  });
});

describe("hex view arithmetic", () => {
  it("counts rows and decodes bytes", () => {
    expect([0, 1, 16, 17].map(rowCount)).toEqual([0, 1, 1, 2]);
    expect(Array.from(fromHex("00ff7f"))).toEqual([0, 255, 127]);
    expect(offsetText(255)).toBe("000000FF");
    expect(offsetText(2 ** 33)).toBe("200000000");
    expect([0x1f, 0x20, 0x41, 0x7e, 0x7f, 0xff].map(printable).join("")).toBe("· A~··");
  });

  it("maps scrolling to rows one to one for a small file", () => {
    const size = 1000 * BYTES_PER_ROW;
    expect(scrollHeight(size)).toBe(1000 * ROW_HEIGHT);
    expect(firstRow(0, 400, size)).toBe(0);
    expect(firstRow(205, 400, size)).toBe(10);
    // The last screenful: 20 rows fit, so the view never starts past row 980.
    expect(firstRow(1e9, 400, size)).toBe(980);
    expect(scrollTopFor(500, 400, size)).toBe(500 * ROW_HEIGHT);
    expect(scrollTopFor(5000, 400, size)).toBe(980 * ROW_HEIGHT);
  });

  it("reaches every part of a file too large for one pixel per row", () => {
    const size = 8 * 1024 ** 3;
    const rows = rowCount(size);
    expect(scrollHeight(size)).toBe(MAX_SCROLL_HEIGHT);
    const viewport = 600;
    expect(firstRow(0, viewport, size)).toBe(0);
    expect(firstRow(MAX_SCROLL_HEIGHT - viewport, viewport, size)).toBe(rows - 30);
    // Going to a row and reading the position back lands within a scroll pixel's worth of rows.
    const perPixel = rows / (MAX_SCROLL_HEIGHT - viewport);
    for (const row of [0, 12345, Math.floor(rows / 2), rows - 31]) {
      const back = firstRow(scrollTopFor(row, viewport, size), viewport, size);
      expect(Math.abs(back - row)).toBeLessThanOrEqual(Math.ceil(perPixel));
    }
  });

  it("reads offsets as people type them and refuses the rest", () => {
    expect(parseOffset("4096", 10000)).toBe(4096);
    expect(parseOffset(" 0x1F ", 10000)).toBe(31);
    expect(parseOffset("1fh", 10000)).toBe(31);
    expect(parseOffset("1,024", 10000)).toBe(1024);
    for (const bad of ["", "abc", "-1", "1.5", "0x", "10000", "99999999999999999999"]) expect(parseOffset(bad, 10000), bad).toBeNull();
    expect(parseOffset("0", 0)).toBe(0);
  });
});

describe("progress", () => {
  it("moves through the stages without ever going back", () => {
    const steps: Step[] = [
      { event: "listed", files: 2 },
      { event: "reading", index: 1, total: 2, path: "a" },
      { event: "unpacked", path: "a", children: 5 },
      { event: "reading", index: 2, total: 2, path: "b" },
      { event: "warning", code: "symlink_skipped", path: "b/l" },
      { event: "analyzing", artifacts: 7 },
      { event: "analyzed", index: 7, total: 7, path: "a/x" },
      { event: "analyzed", index: 3, total: 7, path: "a/y" },
      { event: "relating", index: 1, total: 2, analyzer: "apple" },
      { event: "finished" },
    ];
    let state = initialProgress();
    const seen: number[] = [];
    for (const step of steps) {
      state = advance(state, step);
      seen.push(state.fraction);
    }
    expect(seen).toEqual([...seen].sort((a, b) => a - b));
    expect(state).toMatchObject({ stage: "finishing", fraction: 1, warnings: 1, unpacked: 1 });
    expect(advance(initialProgress(), { event: "reading", index: 1, total: 0, path: "" }).fraction).toBe(0);
  });
});
