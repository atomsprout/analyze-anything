# Usage

[中文](USAGE.zh-CN.md)

`analyze-anything` analyzes a file or folder statically and writes a report with evidence. The input is read; it is never run, installed or loaded.

Homebrew also installs the command under the short name `aaaa`.

## Analyze

```
analyze-anything <file or folder> [-o folder] [--format json,html,pdf,md,txt] [--lang en|zh]
```

Without `-o` the report goes into `<name of the input>.report` in the current folder. It holds `report.json`, `report.html`, `report.pdf`, `report.md`, `report.txt` and `manifest.json`.

`analyze-anything analyze <file or folder>` is the same thing spelled out. To analyze something whose name is also a command, such as a file called `diff`, write its path: `analyze-anything ./diff`.

Reports are in English unless you pass `--lang zh` for Chinese. `report.html` holds both languages and can switch between them; JSON, SARIF and CycloneDX are data and have no language. The desktop app is in English by default too; change it in the View menu, and the choice is remembered.

MSIX/APPX inputs with a supported `AppxBlockMap.xml` also receive content-size and
block/file-hash comparisons. These checks use supplied uncompressed files within the
same container or extracted package directory. With original archive bytes, a separate
bounded ZIP32/ZIP64 layer checks record correspondence and declared local-header sizes.
Supported stored/independently decodable DEFLATE blocks are also bound to captured
content, with measured physical extents and digest/CRC comparisons. Unsupported
compression profiles remain explicit limitations. Supported P7X signatures receive
separate CMS mathematics and SHA-256 package-region/footprint comparisons. A uniquely
verified embedded signer can also be compared literally with the unique manifest
Publisher, using a qualified Windows subject-spelling profile. Signed coverage of the
manifest is recorded separately. Certificate policy and Windows trust remain unchecked; digest agreement
does not authenticate a package. Unsupported or ambiguous names, missing files and exhausted budgets remain
limitations. See [the MSIX check scope](spikes/windows-msix-integrity.md).

Manifest declarations use known namespace/hierarchy paths. Duplicate identities do not
select a first value; dependencies and target-device families are preserved as literal
constraints. Unknown extensions and limited fields remain explicit issues. This is
not full schema validation or installed-package/host compatibility resolution; see
[the manifest scope](spikes/windows-msix-manifest.md).
See [publisher correspondence](spikes/windows-msix-publisher.md) for supported subject
encodings, aliases and the native comparisons.

MSIX/APPX bundles also receive bounded bundle-manifest projections and comparisons with
stored inner packages: original data offsets/sizes, identities, architectures and
application/resource types. UTF-8 OPC file-name escaping is handled as a logical archive
identifier. Qualified outer bundle CMS/digest coverage is separate from inner-package
correspondence and does not imply a separate inner signature is required. No package is
selected for this host. See [bundle scope](spikes/windows-msix-bundles.md) for unsupported
resource, optional/flat bundle and trust-policy semantics.

| Format | File | For |
|---|---|---|
| `json` | `report.json` | The single source of truth: the whole file tree, every finding and its evidence, the limitations, the text of the rules. Every other format is rendered from it |
| `html` | `report.html` | One self-contained file that opens offline; filter, search, browse the file tree, switch language |
| `pdf` | `report.pdf` | Reading and archiving; cut short when there is too much, and says where |
| `md` / `txt` | `report.md` / `report.txt` | Reading as plain text |
| `sarif` | `report.sarif` | SARIF 2.1.0, for CI and code-scanning platforms |
| `sbom` | `sbom.cdx.json` | A CycloneDX 1.5 bill of materials |

Limits keep a hostile or huge input from exhausting the machine. When one is reached, the report records a limitation:

```
--max-files <N>            most files in the tree, unpacked ones included; default 200000
--max-depth <N>            how many containers deep to unpack; default 6
--max-unpacked-bytes <N>   most bytes to unpack in total; default 8 GiB
--max-entry-bytes <N>      largest single entry to unpack; default 2 GiB
--analyzer-timeout <s>     seconds one analyzer may spend on one file; default 300
--unpack-timeout <s>       seconds unpacking one container may take; default 900
--run-timeout <s>          optional whole-analysis deadline, followed by up to 5 seconds to obtain a partial report
```

`analyze` runs the static analysis in a supervised child process. Ctrl+C or `--run-timeout`
requests cancellation; the worker has up to five seconds to return a valid partial report.
If it cannot, it is terminated and the command fails without writing a new report. Export and
optional AI interpretation run after analysis and are outside this deadline. Individual analyzer
timeouts still abandon threads inside the worker; they do not immediately terminate one parser.

`--fail-on low|medium|high` ends with exit code 3 when a finding of that severity or higher exists, for CI.

`--rules <file>` adds YARA rules of your own (repeatable). A rule's `meta: severity = "high"` (or `medium`, `low`, `info`) sets the severity of its findings; without it they are low.

`--windows-source-root <INF> <ROOT>` explicitly binds an INF to a distribution root in
the supplied input tree (repeatable). Use logical paths, not machine paths; `.` is the
outer input root. For example:

```
analyze-anything ./driver-package -o out --windows-source-root driver.inf .
analyze-anything ./bundle.zip -o out --windows-source-root bundle.zip/pkg/driver.inf bundle.zip/pkg
```

Without this setting, source-media roots remain unresolved. Supported loose-file media
paths can associate supplied files and captured digests; this does not choose a Windows
architecture, verify catalog membership or establish installation eligibility. CAB/tag
media, unsupported aliases and incomplete listings remain limitations. The initial
profile accepts ASCII logical paths, at most 32 assignments and 8 KiB per path. The
engine and worker enforce the same validation. In the desktop home page, expand
**Driver source mapping (optional)** and add the logical INF/root pairs before choosing
or dropping the input. The settings apply to that input; returning home clears them.
Analyzing a kept report again retains its validated mappings. See
[the source mapping scope](spikes/windows-inf-source-mapping.md).

`--font <font file>` adds a fallback font to the PDF (repeatable) for text the built-in fonts cannot show, such as Korean, Arabic or emoji. The PDF then depends on those font files too.

`--deep` also asks Ghidra or Hopper, whichever you have, which functions use the APIs and addresses that were found; see [DEEP.md](DEEP.md). It is off by default and much slower.

`--ai` also has the AI you set up explain the report; see [AI.md](AI.md). It is off by default.

## Other commands

```
analyze-anything render out/report.json -o out2 --format pdf --lang zh   # other formats from an existing report, without analyzing again
analyze-anything explain out/report.json <start of a finding id>         # one finding with all its evidence
analyze-anything verify out/                                             # do the output files match manifest.json?
analyze-anything inspect <file or folder>                                # only unpack and list the file tree, as JSON on standard output
analyze-anything selftest                                                # check this build with built-in samples
analyze-anything diff old/report.json new/report.json                    # compare two reports
analyze-anything interpret out/                                          # optional: an AI reading of a report, see AI.md
analyze-anything ai                                                      # show or choose who does the AI reading
analyze-anything mcp out/report.json                                     # serve a report's read-only tools to an AI agent
```

`diff` is meant for two versions of one app. Findings are paired by rule and by where in the input their file is: the same statement is unchanged, a different one is changed, one that is on one side only is added or removed. Files are compared by path inside the input and by SHA-256. `--json` prints the full result, `--lang zh` writes Chinese, and `--fail-on-difference` ends with exit code 3 when the reports differ.

`manifest.json` records the size and SHA-256 of every output file. `verify` points out files that were changed, are missing, or were added. The manifest is not signed: it catches accidental changes, and deliberate ones too if you keep the manifest's own SHA-256 somewhere else.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Done |
| 1 | Could not run (the input cannot be read, for instance), or `verify` found a difference |
| 2 | Ran, but the analysis is partial; the report's coverage and limitations say why |
| 3 | A finding reached the `--fail-on` severity, or `diff --fail-on-difference` found a difference |

## Reading a report

- **Confidence.** *Verified* was read directly from a structure the format defines, or checked cryptographically. *Derived* was computed from verified facts by a fixed rule. *Heuristic* is a pattern match and may be a false positive.
- **Severity.** *Info* is a neutral fact, not a problem. Low, medium and high are fixed for each rule and order your reading; they are not a verdict on whether the input is safe.
- **Coverage and limitations** lists what could not be analyzed and why: unreadable, encrypted, over a limit, failed to unpack. "Nothing found" and "not checked" are different things, and the second always appears in this chapter.
- **Signatures.** The report says which checks were made. Whether a root certificate is trusted, whether a certificate was revoked, and Apple's notarization status need the network or the system's trust store; this tool does not check them, and the report says so.

## Supported inputs

| | Formats |
|---|---|
| General | Any file or folder; zip, tar, 7z, gzip, bzip2, xz, zstd, nested |
| Native binaries | PE (exe, dll, sys), ELF, Mach-O (universal binaries included) |
| Apple | `.app` and other bundles, IPA, DMG (HFS+, APFS), pkg; code signatures, entitlements, provisioning profiles, privacy manifests |
| Windows | Authenticode, version information and manifests, .NET assemblies, NSIS / Inno Setup / MSI / CAB installers, self-extractors, Electron (asar), MSIX, installed program folders |
| Android | APK, AAB, XAPK / APKS / APKM; manifest, resources, signatures v1–v3.1, DEX, SDK and packer detection |

What is unsupported or only recognized is in [LIMITATIONS.md](LIMITATIONS.md).

## Build

```
cargo build --release                                   # with PDF and the optional AI command
cargo build --release --no-default-features             # without either: much smaller, and no network code at all
cargo build --release --no-default-features --features pdf   # PDF, no network code
```

Needs Rust 1.90 or newer. The program is `target/release/analyze-anything`.

## Fuzzing

Needs the nightly toolchain and `cargo-fuzz`:

```
cargo +nightly fuzz run analyze fuzz/corpus/analyze crates/*/tests/data
```
