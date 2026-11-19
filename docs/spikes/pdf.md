# Technical validation #1: Chinese PDF output with embedded Typst

> Status: **passed**, landed as `Format::Pdf` (2026-11-18). The fallback `fulgur` was not enabled.
> Corresponds to the validation item in [PLAN.md](../PLAN.md) §5.3 and §6.1: "Chinese PDF from embedded Typst: with a table of contents, long tables spanning pages, no missing Chinese glyphs".

## Findings

| Pass criterion | Result |
|---|---|
| Has a table of contents | Passed. Generated automatically by Typst `outline`, with correct page numbers (checked on the 8-page, 55-page and 158-page samples) |
| Long tables spanning pages | Passed. The 300-row file inventory spans 7–8 pages, with the header repeated on each page |
| No missing Chinese glyphs | Passed. Noto Sans SC is embedded; `pdffonts` shows both fonts as embedded subsets, and `pdftotext` extracts the Chinese text and complete hashes |
| Same report ⇒ identical bytes | Passed. No creation time, a fixed document identifier; two renders in the same process and two renders in different processes are all byte-for-byte identical |
| Untrusted text is not treated as markup | Passed. Report text does not enter the Typst source (see below) |

## Approach

- Dependencies: `typst = "0.14.2"`, `typst-pdf = "0.14.2"` (Apache-2.0). 0.14.2 is the latest version compatible with the
  workspace's `rust-version = 1.90`; 0.15 needs a higher Rust version, and the `World` and `PdfOptions` interfaces must be re-checked when upgrading.
- The code is in `crates/aa-report/src/pdf/`: `mod.rs` implements `World`, and `report.typ` is the fixed layout template.
- **`World` provides only two files and two fonts**: the template itself (source) and `report.json` (data, generated in memory by the renderer).
  Every other path and every package (`@preview/...`) returns `AccessDenied`; there is no disk, no network, no system fonts and no clock
  (`today()` returns `None`).
- **Report text is never spliced into the Typst source**. The template reads the data with `json("report.json")`; all values are used only as strings, do not go through `eval`,
  and are not parsed as markup. So `#eval(...)`, `*bold*`, `$x$` and `#import "@preview/..."` in a file name are all typeset as they are —
  the unit tests take the text back out of the typeset result and check it item by item.
- Characters that hide text or change its direction (such as U+202E and zero-width characters) are replaced with a visible form like `[U+202E]` before being passed to the template;
  HTML and PDF use the same function (`sanitize.rs`).
- The fonts are in `crates/aa-report/fonts/`, embedded in the binary, with the license files in the same directory:
  - `NotoSansSC-Regular.otf` (8.3 MB, OFL 1.1, taken from `Sans/SubsetOTF/SC` in notofonts/noto-cjk) — body text, Chinese, Latin;
  - `JetBrainsMono-Regular.ttf` (0.27 MB, OFL 1.1) — paths, hashes, evidence.

  Only the single Regular weight is included: the "bold" of headings is replaced by a thin stroke in the same color, saving an 8 MB Bold. The fonts add 8.6 MB to the repository.
- Determinism: `PdfOptions { ident: Smart::Custom(<fixed string>), timestamp: None }`, and `set document(date: none)` in the template;
  the PDF has no `/CreationDate` or `/ModDate`.
- `pdf` is a cargo feature of `aa-report`, on by default, and `aa-cli` passes it through; `cargo build -p aa-cli --no-default-features`
  produces a slim build without PDF, in which `--format pdf` returns a clear error.

## What is in the PDF

Title block (input name, tool version, input SHA-256) → summary (counts by severity, coverage numbers) → how to read → table of contents (with page numbers) →
all findings of the 12 chapters (the severity and confidence labels each carry a shape mark, so they can be told apart in black-and-white print; body, evidence lines, corresponding standards, the first 16 characters of the finding ID) →
file inventory table → coverage and limitations. The page header is the input name, and the page footer is the tool version and "page X of Y". There is one set each for Chinese and English.

The PDF is a file for people to read and archive; **the complete data is in report.html and report.json**. Overlong parts are truncated, and this is stated in place:

| Content | Limit | Note shown when truncated |
|---|---|---|
| Findings of the same rule | Merged into one; neutral facts list 10, the rest list 30 | "N more of this kind are not listed here; report.html and report.json hold them all" |
| Entries per chapter (after merging) | 200 | "This chapter has N findings; the first 200 … are shown here. report.html and report.json hold them all" |
| Evidence per finding | 5 lines, 160 characters for the value on each line | "N more pieces of evidence not shown here" |
| File inventory | 300 rows (same as Markdown) | "The table shows the first 300 of N files; report.json lists them all" |
| Files involved in each kind of limitation | 30 (same as Markdown) | "… +N" |
| Title / body of a single finding | 200 / 1500 characters | Ends with "…" |

The summary also has one fixed sentence: "This PDF is for reading and filing: long lists are cut and say so; report.html and report.json hold the complete data."

## Measurements

Machine: 4-core x86-64 Linux, release build.

| Report | Pages | PDF size | Total time of `analyze-anything render --format pdf` (including reading the JSON) | Peak memory |
|---|---|---|---|---|
| 22 files, 43 findings (every chapter present, including malicious strings) | 8 | 0.26 MB | 0.15 s | about 50 MB |
| 3,000 files, 400 findings | 55 | 1.6 MB | 0.84 s | — |
| 50,000 files, 5,000 findings (more than 1,100 typeset after truncation per the table above) | 158 | 4.1 MB | 2.0 s | about 500 MB (including the 26 MB report.json itself) |

For comparison: the HTML for the same three reports takes 0.01 s, 0.04 s and 0.48 s respectively. Peak memory was measured on a build without LTO.

The debug build is much slower (about 23 seconds for 55 pages), so the large report in the tests typesets only 96 findings.

Binary size (after `strip`):

| Build (workspace release profile: thin LTO, `codegen-units = 1`, strip) | Size of `analyze-anything` |
|---|---|
| `cargo build --release -p aa-cli` (with PDF) | 49.3 MB |
| `cargo build --release -p aa-cli --no-default-features` (without PDF) | 10.0 MB |
| Difference | **+39.3 MB**, of which fonts are 8.6 MB |

The complete dependency tree is about 400 crates, all with licenses in the allowed range (MIT / Apache-2.0 / BSD / Zlib / Unicode-3.0 and so on, no GPL/LGPL).
The first full release compile takes about 6 minutes longer.

The plan estimated 15–25 MB; the actual size is larger: besides the 8.6 MB of fonts, Typst also carries the whole standard library other than the math fonts — syntax highlighting definitions,
bibliography styles, ICU segmentation data, image decoding, the WASM plugin runtime — and 0.14 has no switch to remove these. Distributions that care about size use
`--no-default-features`.

## Pitfalls encountered

1. **Long strings do not wrap.** Hashes and paths have no spaces, and Typst lets them run off the page. Inserting zero-width spaces between characters makes them wrap, but the zero-width spaces enter
   the PDF's text layer: the hash extracted by `pdftotext` has U+200B mixed in, and searching for the whole hash in a reader finds nothing. The current approach: the renderer cuts a long string into
   small segments (preferably after separators such as `/ . - _`, and every 8 characters where there is no separator), and the template joins them with `h(0.001pt)`. In Typst's line-breaking
   algorithm, inline spacing is equivalent to a space: a line can break there, yet no character is produced. The spacing must be non-zero — a spacing of exactly 0 is dropped by Typst.
   When it does not wrap, the hash is continuous, searchable and copyable; the one that happens to be split across two lines at a line break cannot be found as a whole string, as in every PDF.
2. **Missing glyphs for the hint characters.** At first `⟦U+202E⟧` and the Unicode control pictures (the U+2400 block) were used to show hidden characters; Noto Sans SC does not have these glyphs,
   and they were typeset as boxes. Changed to pure ASCII `[U+202E]`.
3. **Findings spanning pages.** When a finding block was allowed to span pages, the "finding ID" line could fall alone onto the next page. Now no finding spans pages, and the character limits in the table above ensure
   that a finding is never longer than one page.
4. **A poppler warning.** For the tagged PDF generated by Typst, `pdfinfo` reports `Suspects object is wrong type (boolean)`.
   This is a problem in poppler's parsing of `/MarkInfo`, and it does not affect display, text extraction or font embedding.

## Known shortcomings

- **Missing glyphs for characters outside the two fonts.** Emoji, Arabic, Korean and so on in file names are not in the embedded fonts and are typeset as boxes. HTML uses system fonts and
  is not affected. The `--font` override option in the plan has not been built yet.
- **Bold is simulated with a stroke**, and at small sizes it is not as clear as a real Bold; switching to a real weight only takes adding another font of about 8 MB and changing two lines of the template.
- **No interaction other than bookmarks.** Table of contents entries and chapter headings can be jumped to in the PDF outline; evidence cannot be expanded as in HTML.
- The PDF is tagged (Tagged PDF, the Typst default), but has not been validated against PDF/A or PDF/UA.
- The first render in a process has to parse the 8 MB font in addition; later renders reuse it (on a build without LTO, the 8-page sample takes 0.38 seconds the first time and 0.19 seconds each time after).

## Why we did not switch to fulgur

Typst met all the pass criteria on the first try, render time is on the order of seconds, the output is reproducible, and report text is completely isolated from the layout code. The HTML → PDF route would additionally have to
solve pagination, headers and footers, and table of contents page numbers, which are exactly what Typst already provides.
