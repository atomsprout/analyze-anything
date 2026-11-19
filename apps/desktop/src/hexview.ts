// The bytes of one file as offset, hexadecimal and text columns. Only the rows on screen exist
// as elements, and only the pieces of the file they need are fetched, so a file of any size
// opens at once.

import { clear, el } from "./dom";
import { BYTES_PER_ROW, CHUNK, ROW_HEIGHT, firstRow, offsetText, printable, rowCount, scrollHeight, scrollTopFor } from "./format";

export interface Range {
  offset: number;
  length: number;
}

export interface HexView {
  element: HTMLElement;
  /** Scrolls so that the row holding `offset` is near the top. */
  reveal(offset: number): void;
  /** Call when the element's size changed. */
  resize(): void;
}

/** Pieces of the file kept in memory; the oldest goes first when there are more. */
const KEPT_CHUNKS = 48;

/**
 * Shows a file of `size` bytes. `read` fetches a piece of it; `marked` is the range to
 * highlight, the evidence a finding rests on. `failed` is told when a piece cannot be read.
 */
export function hexView(size: number, read: (offset: number, length: number) => Promise<Uint8Array>, marked: Range | null, failed: (message: string) => void): HexView {
  const rows = el("div", { class: "hexrows" });
  const spacer = el("div", { class: "hexspacer" }, rows);
  const scroller = el("div", { class: "hexscroll", tabindex: "0", onscroll: () => schedule() }, spacer);
  spacer.style.height = `${scrollHeight(size)}px`;

  const chunks = new Map<number, Uint8Array>();
  const loading = new Set<number>();
  let scheduled = false;

  function schedule(): void {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      draw();
    });
  }

  function chunkFor(offset: number): Uint8Array | null {
    const start = Math.floor(offset / CHUNK) * CHUNK;
    const known = chunks.get(start);
    if (known) {
      // Used again: move it to the young end.
      chunks.delete(start);
      chunks.set(start, known);
      return known;
    }
    if (!loading.has(start)) {
      loading.add(start);
      read(start, Math.min(CHUNK, size - start))
        .then((data) => {
          chunks.set(start, data);
          while (chunks.size > KEPT_CHUNKS) {
            const oldest = chunks.keys().next().value;
            if (oldest === undefined) break;
            chunks.delete(oldest);
          }
          schedule();
        })
        .catch((error: unknown) => failed(error instanceof Error ? error.message : String(error)))
        .finally(() => loading.delete(start));
    }
    return null;
  }

  function isMarked(offset: number): boolean {
    return marked !== null && offset >= marked.offset && offset < marked.offset + marked.length;
  }

  function rowNode(row: number): HTMLElement {
    const start = row * BYTES_PER_ROW;
    const data = chunkFor(start);
    const hex = el("span", { class: "hexbytes" });
    const text = el("span", { class: "hextext" });
    for (let i = 0; i < BYTES_PER_ROW; i += 1) {
      const offset = start + i;
      const gap = i === 8 ? "  " : i === 0 ? "" : " ";
      if (offset >= size) {
        hex.appendChild(document.createTextNode(`${gap}  `));
        continue;
      }
      const base = Math.floor(offset / CHUNK) * CHUNK;
      const byte = data ? data[offset - base] : undefined;
      const shown = byte === undefined ? "··" : byte.toString(16).toUpperCase().padStart(2, "0");
      const char = byte === undefined ? " " : printable(byte);
      if (gap) hex.appendChild(document.createTextNode(gap));
      if (isMarked(offset)) {
        hex.appendChild(el("mark", null, shown));
        text.appendChild(el("mark", null, char));
      } else {
        hex.appendChild(document.createTextNode(shown));
        text.appendChild(document.createTextNode(char));
      }
    }
    return el("div", { class: "hexrow" }, el("span", { class: "hexoffset" }, offsetText(start)), hex, text);
  }

  function draw(): void {
    const viewport = scroller.clientHeight;
    const first = firstRow(scroller.scrollTop, viewport, size);
    const count = Math.min(rowCount(size) - first, Math.ceil(viewport / ROW_HEIGHT) + 1);
    clear(rows);
    // The rows sit where the scroll position is, whatever row numbers they show.
    rows.style.transform = `translateY(${Math.min(scroller.scrollTop, Math.max(0, scrollHeight(size) - viewport))}px)`;
    for (let i = 0; i < count; i += 1) rows.appendChild(rowNode(first + i));
  }

  return {
    element: scroller,
    reveal(offset: number) {
      const row = Math.max(0, Math.floor(offset / BYTES_PER_ROW) - 2);
      scroller.scrollTop = scrollTopFor(row, scroller.clientHeight, size);
      schedule();
    },
    resize: schedule,
  };
}
