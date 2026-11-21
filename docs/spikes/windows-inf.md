# INF declaration reader

Initial W5 increment, 2026-11-20. W5 remains open: this adds a syntax reader, not a
driver-package verifier or a Windows installation decision.

## Boundary and representation

The `windows.inf` fact records ordered section occurrences and entries, retaining
section decorations, original-case names, keys, list fields and 1-based physical
start/end lines. Duplicate sections and duplicate keys remain in source order;
the reader does not pretend that source occurrence order is installation order.
Quoted commas/semicolons, doubled quotes inside quoted strings, omitted comma fields,
comments and explicit line continuations are read. Backslashes are not quote escapes.
Entries after a malformed section header do not inherit the previous section's context.

Recognition requires `.inf` and a readable Version section. This can include non-driver
INF documents. Version signatures, directive placement, scalar types, required fields
and installation applicability are not validated. Fields in arbitrary sections remain
syntax, not evidence that a service, registry change or file copy would take place.
The summary finding has source-field evidence and verified syntax confidence. A separate
overview identifies the document; every readable INF also carries the bilingual
`windows.inf-semantics-unresolved` limitation.

Text is ASCII without a BOM, or BOM-marked UTF-8/UTF-16 LE/BE. Non-ASCII unmarked text
is refused rather than guessed using the host ANSI code page. Supporting decoding of
marked text is not a claim that Windows accepts every encoding as an installable INF.
Legacy INF without a Version section remains unsupported.

`neutral_fields` is an optional separate projection using unique, literal definitions
from undecorated Strings sections. Raw fields are always retained. Any localized Strings
section, non-ASCII section/string-key name, incomplete parse, duplicate definition,
nested substitution, missing token or unresolved directory ID prevents the relevant
projection (or all projections where the namespace is uncertain). Sensitive-name string
definitions are not propagated into other fields. `%%` becomes a literal percent in
this projection, without a second expansion. Neither the host language nor environment,
registry, Driver Store or target architecture is consulted. This is a documented limited
projection, not the complete SetupAPI string algorithm. Original string definitions and
line positions remain in the fact for inspection.

The parser never follows Include/Needs, opens payloads, installs INF data or loads a
driver. `installed: false` says what this reader did, not whether the host has installed
the package. `platform_selected: false` and `catalog_verified: false` explicitly prevent
the syntax result from being read as applicability or integrity verification.

## Budgets and unread content

- Input: 2 MiB; logical line: 64 KiB.
- Sections: 1,024 occurrences; entries: 8,192; fields: 128 per entry.
- Field: 4,096 decoded UTF-8 bytes; section name: 255 characters and 1,024 UTF-8 bytes.
- Neutral projections: 4 MiB total. Exhaustion discards all projections, preserving raw
  entries and reporting a limitation, so short repeated tokens cannot amplify output
  without a bound.
- Issue details: first 64, with an independent total count. Structural errors and exhausted
  budgets get `windows.inf-partial`; undecodable, oversized or unrecognized structure gets
  `windows.inf-unreadable`.

Recognizable credentials are redacted from section names, keys, literal fields,
projections and evidence before output. Sensitive registry value names in literal or
projected list rows hide the row's fields. Pattern matching cannot identify every secret.

## Reference and samples

`upstream-nullFilter.inf` is an unchanged source fixture from Microsoft's
[Windows-driver-samples](https://github.com/microsoft/Windows-driver-samples/blob/d49bb7d72f3651952b2b6e4ad28d14fe2247eb69/filesys/miniFilter/nullFilter/nullFilter.inf),
commit `d49bb7d72f3651952b2b6e4ad28d14fe2247eb69`, under MS-PL, with its full license
and copyright notices retained in tests/data and NOTICE.
SHA-256: `04351440bf6ee49fd39f2d36d76ced97af06941d3faadc1865862c0bff35891d`.
The source still contains `$ARCH$` build placeholders and is not a built driver package.
No SYS, catalog or certificate is included.

`tools/native-compare/windows-inf-check.py` captured the checked-in reference through
SetupOpenInfFileW, SetupEnumInfSectionsW, SetupGetLineByIndexW and SetupGetStringFieldW on
the available Windows x64 host. It passes a full path to avoid implicit host-INF search,
never appends other INFs, queues installation actions or modifies the registry. Native
section enumeration places Strings first, so comparisons use section names, not order.
The CLI comparison matches 91 projected fields; directory-ID references remain explicitly
unprojected. Repeated report JSON is identical, English/Chinese Markdown and HTML include the finding, and the input
bytes are unchanged. The local result is `out/windows-baseline/inf/checks.json`.
The development snapshot includes SetupAPI's own directory-ID expansion. Those native
host-context values are excluded from portable projection comparisons and are never
copied into the analyzer's report.

Constructed tests cover quoting, comments, continuation spans, repeated sections,
decorations, empty fields, Unicode encoding, missing/malformed sections, ambiguous and
localized strings, directory IDs, credential propagation and each resource budget.
The portable pipeline compares the pinned reference snapshot; the native helper must
be run on Windows and is never part of report generation.
The whole-engine robustness suite also discovers these fixtures automatically and
mutates their bytes while preserving `.inf`, so the extension-gated reader is exercised.

The project-authored `native-inf-syntax.inf` and checked-in native snapshot add 25
projected-field comparisons for doubled/tripled outer quotation marks in Strings,
quoted commas and semicolons, literal percent escapes, preserved spaces, omitted fields
and a continuation after a quoted backslash. These are controlled syntax examples,
not another independently distributed driver package. Both fixture files with checked
digests are excluded from Git newline conversion.

Final local Windows checks passed: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo build -p aa-cli --no-default-features`, and `cargo test --workspace`.
The final full test log is `out/windows-baseline/workspace-inf-final.log`.
The seven INF unit/reference tests passed, including continuation start/end lines and
both checked fixture digests. Native CLI comparisons passed again for 91 + 25 projected
fields, repeated JSON, unchanged input and English/Chinese/HTML output.
Windows desktop page tests/build, portable fixture generation and 22 browser tests also
passed; [DESKTOP.md](../DESKTOP.md) states the distinction from native-window validation.
Cross-platform CI passed for this INF increment at commit
`b35f16d55971275191a3ca2f5bd2cf7706bc92cf`:
[run 44840156007](https://github.com/atomsprout/analyze-anything/actions/runs/44840156007).
Linux, macOS and Windows core checks, the macOS desktop checks and licenses all passed.
The previously recorded `413e05e` CI success covers the earlier entry-point/reference implementation.

## Still needed for W5

Typed device/model, service and registry declarations; decorated-section applicability
and reference relationships; source/destination payload mapping; supplied-catalog links;
catalog parsing, signature integrity and the correct member subject hashing; missing and
modified member comparisons with explicit-catalog SignTool. Broader real built packages,
code-page variants and parser corner cases remain separate coverage work. Windows trust,
revocation, WHQL acceptance and installation eligibility remain outside the conclusion.

References: Microsoft's [general INF syntax](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/general-syntax-rules-for-inf-files),
[Strings](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-strings-section),
[Version](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-version-section)
and [SetupOpenInfFileW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupopeninffilew).
