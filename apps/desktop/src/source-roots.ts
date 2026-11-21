import type { WindowsSourceRoot } from "./types";

/** Matches the engine's ordinary ASCII logical-path profile; native validation remains authoritative. */
export function sourceRoots(rows: WindowsSourceRoot[]): WindowsSourceRoot[] {
  const active = rows.filter((row) => row.inf !== "" || row.root !== "");
  const component = (part: string) => part.length > 0 && part.length <= 255 && !/[\x00-\x1f\x80-\uffff:<>"|?*~%\\]/.test(part)
    && !/[ .]$/.test(part) && !/^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9]|LPT[1-9])$/i.test(part.split(".")[0] ?? "");
  const path = (value: string) => value.length > 0 && value.length <= 8192 && value.split("/").length <= 512 && value.split("/").every(component);
  if (active.length > 32 || active.some((row) => !path(row.inf) || !row.inf.toLowerCase().endsWith(".inf") || (row.root !== "." && !path(row.root)))) throw new Error("invalid-source-roots");
  const unique = new Map<string, string>();
  for (const row of active) {
    const inf = row.inf.toLowerCase(), root = row.root.toLowerCase();
    if (unique.has(inf) && unique.get(inf) !== root) throw new Error("conflicting-source-roots");
    unique.set(inf, root);
  }
  return [...unique].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([inf, root]) => ({ inf, root }));
}
