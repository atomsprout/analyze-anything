# Analyze Anything — Final Plan

> Version: v1.0 final (2026-11-18). Phase one has been implemented (see "Implementation status" below). The research behind this plan is in [RESEARCH.md](RESEARCH.md).
> Positioning in one sentence: **take any artifact on a computer (file / folder / archive / installer / app package) as input, and output a reliable, traceable, multi-dimensional analysis report (PDF / HTML / Markdown / TXT).** Written in Rust, purely static analysis, works offline.

---

## Implementation status (2026-11-19)

All code for phase one (CLI, M0–M6) has been implemented. The table below gives the actual result of each milestone; the parts that were not verified are listed in [LIMITATIONS.md](LIMITATIONS.md).

| Milestone | Status | Actual result |
|---|---|---|
| M0 Foundation and technical validation | Done | All four technical validations reached a conclusion, recorded in `docs/spikes/` |
| M1 Generic layer and rendering | Done | 7 archive formats, generic content analysis, JSON / Markdown / TXT / HTML / PDF |
| M2 Native binaries | Done | Compared against `readelf`, `llvm-readobj`, `llvm-otool`: 2457 ELF, 151 PE and 34 Mach-O files with no mismatch |
| M3 Apple | Done | 9 real DMGs match 7-Zip file by file; 587 signed binaries match `rcodesign` |
| M4 Windows | Done | NSIS / Inno / MSI / CAB match 7-Zip, `innoextract`, `msiextract`, `cabextract` file by file; signatures match `osslsigncode` |
| M5 Android | Done | 13 real APKs match `aapt`, `apksigner`, `dexdump`; accept / reject results for 21 signature samples match `apksigner` |
| M6 Correlation and polish | Done, no version tag | Overview, structure statistics, component inventory, SARIF, CycloneDX, `analyze-anything verify`, fuzzing; the release process was trial-run successfully on 5 target platforms (build, release-mode tests, artifact self-check, packaging), but no version tag was created and no formal release was made |

**Deviations from the original plan**

- **Conclusions of the technical validations**: embedding Typst for PDF works; the existing DMG libraries were not sufficient, so a reader was written in-house; NSIS uses an existing library with two gaps filled; APK signature verification was written in-house.
- **Most parsers are written in-house**: binaries, DEX, AXML, Authenticode and Apple signature blobs do not use the existing libraries listed in §3 / RESEARCH. The reason is that byte offsets are needed as evidence, and the existing libraries crash or give wrong results on malformed input. Existing libraries are used only in tests, as a reference.
- **Risk levels instead of a single score**: the report gives an attention level (high / medium / low / none, taken from the highest severity among the findings) and the count at each level, and states that this is not a safety verdict. No weighted single score was built, because there is no reliable basis for the weights.
- **Crate layout**: there are actually 12 (`aa-core`, `aa-engine`, `aa-unpack`, `aa-content`, `aa-binary`, `aa-apple`, `aa-windows`, `aa-android`, `aa-correlate`, `aa-export`, `aa-report`, `aa-cli`). There is no separate `aa-vfs`, `aa-detect` or `aa-rules`.
- **All planned features are implemented**: including `analyze-anything inspect`, `analyze-anything selftest`, `--rules` (YARA), `--font`, TLSH similarity hash, and timeouts for analyzers and unpacking. The timeout is implemented by giving up waiting rather than terminating the thread; details are in LIMITATIONS.
- **Executable size**: about 49 MB with PDF, larger than the §5.3 estimate (Typst plus fonts is about 39 MB); about 10 MB without PDF.
- **Form of the differential tests**: the comparisons were run with scripts on real samples during development. Only the comparison results for small samples were written as automated tests; CI does not call external tools.
- **CI passes on Linux, macOS and Windows** (format, lint, all tests, license and security advisory checks). There is also a manually triggered comparison workflow that checks results on macOS and Windows with `codesign`, `hdiutil`, `pkgbuild`, `Get-AuthenticodeSignature`, `makecab`; all 230 items match. Details are in LIMITATIONS.

---

## 0. Summary of the final plan

**Decisions made**

| Item | Decision |
|---|---|
| Language | Rust; dependencies only from crates.io; no GPL libraries |
| Product form | **CLI first (phase one, up to v1.0), then the desktop app (phase two)** |
| Format order | Apple → Windows → Android |
| Desktop app framework | Tauri |
| Reference projects | Craft Anything, RESX, REA and others serve only as code and design references; no fork, no dependency |
| Output | `report.json` is the single source of truth, rendered to PDF / HTML / Markdown / TXT |
| Reliability | Every finding carries evidence and a confidence; fact extraction does not use an LLM; a fixed "coverage and limitations" section |

**Items set to defaults that can be changed at any time**: the command name is `analyze-anything`; reports can switch between Chinese and English, Chinese by default; the AI interpretation layer is not part of v1.0.

**Three phases**

| Phase | Goal | Estimate |
|---|---|---|
| Phase one: CLI | M0–M6, release CLI v1.0 | 14–18 weeks |
| Phase two: desktop app | A graphical interface on the same engine | After CLI v1.0, estimated separately |
| Phase three: ecosystem | Agent interface, AI interpretation layer, version comparison, more formats | In parallel with phase two or after it |

---

## 1. Product definition

### 1.1 Input (limited to "artifacts on a computer")

| Category | Formats | Priority |
|---|---|---|
| iOS | `.ipa`, unpacked `Payload/*.app` | P0 |
| Android | `.apk`, `.aab`, `.xapk` / `.apks` | P0 |
| macOS | `.app` directory, `.dmg`, `.pkg`, single Mach-O, `.framework` / `.dylib` | P0 |
| Windows | `.exe` / `.dll` (PE), **NSIS installers**, Inno Setup, `.msi`, `.msix`, **installed program directories** | P0 (NSIS/PE/directory) P1 (the rest) |
| Linux | ELF, `.deb`, `.rpm`, AppImage | P2 |
| Generic | Any folder, zip / tar.* / 7z / (rar), unknown files (fall back to generic analysis) | P0 |

An unknown format **never exits with an error**: it falls back to "generic file analysis" (type guessing, hashes, entropy, strings, embedded data scan).

### 1.2 Output

- `report.json` — **the single source of truth** (an intermediate representation, IR, with a JSON Schema)
- `report.md` / `report.txt` / `report.html` (single self-contained file, opens offline, with search and a table of contents) / `report.pdf`
- Optional: `sbom.cdx.json` (CycloneDX), `--extract-dir` to keep the unpacked artifacts

All four human-readable formats **are rendered from the same IR**, which keeps their content consistent.

### 1.3 CLI form

```
analyze-anything analyze <PATH> [-o out/] [--format pdf,html,md,txt,json] [--lang zh|en]
                  [--profile quick|standard|deep] [--rules extra.yar] [--offline]
analyze-anything inspect <PATH> --json          # identification + structure tree only, for agents/scripts
analyze-anything render report.json --format pdf # re-render from an existing IR, without re-analyzing
analyze-anything explain <FINDING_ID>           # print the full evidence of one finding
analyze-anything verify out/                    # check the manifest hashes of the output directory, confirm the report was not changed
analyze-anything selftest                       # self-check with built-in samples
```

CLI conventions: results go to files, progress and diagnostics go to stderr; every subcommand supports `--json`; exit codes distinguish "success / some analyzers failed / input unreadable"; `--fail-on <severity>` is for CI use.

### 1.4 Non-goals (explicitly out of scope)

- No executing, installing or dynamic debugging of the analyzed object (purely static)
- No decompiling to pseudocode (that is the domain of Ghidra/IDA/REA; an optional plugin may connect to them later)
- No FairPlay decryption, no unpacking of packers, no bypassing of any protection; when encryption or packing is encountered, report truthfully that "this part is not visible"
- No network lookups (offline by default; lookups such as VirusTotal are optional and must be turned on explicitly)

---

## 2. How "reliable" is achieved (core design principles)

This is the top priority of the whole project, guaranteed by mechanisms rather than slogans:

1. **An evidence-first data model**. Every finding (Finding) in the report must carry:
   - `evidence[]`: source file (full path in the unpacked tree), byte offset / structure field name, raw value, SHA-256 of that file
   - `method`: which analyzer and which rule (including the rule version) produced it
   - `id`: SHA-256 of the finding's canonical JSON (borrowed from Craft Anything) — the same observation always gets the same ID, any tampering is detectable, and `analyze-anything explain <ID>` and the diff of two reports become simple
   - `confidence`: three levels (corresponding to Craft Anything's Observed / Derived / Inferred, for future interoperability) —
     - **Verified**: read directly from a structure defined by a specification, or cryptographically verified (e.g. "signature verification passed", "CFBundleIdentifier = … in Info.plist")
     - **Derived**: deterministically deduced from verified facts (e.g. "links libswiftCore → contains Swift code")
     - **Heuristic**: pattern match / rule hit (e.g. "possible AWS key", "possible UPX packing"), clearly marked in the report, with a false-positive note
2. **Nothing is written without evidence**. The rendering layer may only reference Findings in the IR; templates may not contain assertive text that is not backed by a Finding ID.
3. **Declare blind spots truthfully**. Unresolved questions are recorded as first-class `Unknown` items ("what was not figured out + what means could figure it out"); each analyzer outputs `Coverage` (checked / total). Every report has a fixed "analysis coverage and limitations" section: which files failed to parse, which are encrypted (FairPlay / encrypted DMG), which were skipped because a limit was exceeded, which analyzers were not enabled. **"Not found" and "not checked" are strictly distinguished**.
4. **Deterministic and reproducible**. Missing values are always null in the IR, never replaced with 0 or an empty string; when a limit is hit, the truncation is recorded explicitly (borrowed from RESX). Same input + same version + same rule library ⇒ byte-identical `report.json` (stable ordering, no timestamps in the body, ordered merging of parallel results). The report header records: tool version, rule library version, input SHA-256, command-line arguments.
5. **The core flow does not use an LLM**. Fact extraction is done 100% by deterministic code. An LLM is only a later, **optional** "interpretation layer" (see §7); it may only read the IR, must cite a Finding ID for every sentence, and gets its own chapter in the report marked "AI-generated".
6. **Cross-validation (differential testing)**. In CI, our results are compared with authoritative tools: `codesign -dvvv` / `apksigner verify` / `aapt2 dump` / `sigcheck` / `otool` / `readelf` / MobSF. Any mismatch is treated as a bug.
7. **Robustness against malicious input**. Input is untrusted data: unpack limits (total size, file count, nesting depth, compression ratio → zip bomb protection), path traversal protection, symlinks are not followed, parser panic isolation (`catch_unwind` + a timeout per analyzer), `cargo-fuzz` on all parsers. A single analyzer failure only degrades into one "limitation" record and does not affect the whole report.

---

## 3. Architecture

### 3.1 Pipeline (6 stages)

```
 Input path
   │
   ▼
① Identify   Identify the type (magic numbers + structure probing; the extension is only a hint)
   │
   ▼
② Unpack     Unpack recursively → build the artifact tree (Artifact Tree)
   │           IPA → Payload/X.app → Mach-O(fat) → arm64 slice
   │           NSIS.exe → install script + embedded files → app.asar → JS …
   ▼
③ Analyze    Run the matching analyzers on every node of the tree in parallel → Facts + Findings
   │
   ▼
④ Correlate  Cross-node correlation: declared permissions vs actual API use, SDK merging,
   │           duplicate files, which files the same certificate signed, URL→domain aggregation
   ▼
⑤ Assess     Scoring and summary: risk levels, key info cards, coverage statistics
   │
   ▼
⑥ Render     report.json → md / txt / html / pdf
```

### 3.2 Workspace layout

```
analyze-anything/
├── crates/
│   ├── aa-core        # Data model: Artifact / Fact / Finding / Evidence / Confidence, IR schema
│   ├── aa-vfs         # Artifact tree + read-only virtual file system (memory / temp directory / mmap), limits and safety policy
│   ├── aa-detect      # Type identification
│   ├── aa-unpack      # Unpackers: zip tar 7z dmg xar/pkg nsis inno msi cab asar ar/deb rpm …
│   ├── aa-binary      # Generic binaries: PE / Mach-O / ELF, hardening checks, symbols, imports/exports, compiler/language identification
│   ├── aa-apple       # .app / .ipa: Info.plist, signature, entitlements, provisioning, PrivacyInfo
│   ├── aa-android     # APK/AAB: Manifest, resources, DEX, signature v1–v4, native libs
│   ├── aa-windows     # Authenticode, version resources, manifest, .NET, installer semantics, installed directories
│   ├── aa-content     # Generic content: strings, URLs/domains/IPs, secrets, entropy, embedded files, scripts/configs
│   ├── aa-rules       # Rule engine and rule library (YARA, secret regexes, SDK/Tracker fingerprints, packer signatures)
│   ├── aa-correlate   # Cross-artifact correlation and assessment
│   ├── aa-report      # Renderers: json / md / txt / html / pdf (typst), i18n
│   ├── aa-engine      # Facade: chains the layers above into one entry point; both the CLI and the desktop app depend only on it
│   └── aa-cli         # Binary `analyze-anything` (thin shell: parse arguments, show progress, write files)
├── apps/              # Phase two: the desktop app goes here and reuses aa-engine
├── rules/             # Versioned rule data (YAML/YAR), embedded at compile time, can also be overridden at run time
├── testdata/          # Self-built minimal samples + expected output (golden)
└── docs/
```

### 3.3 Key abstractions

```rust
trait Unpacker { fn probe(&self, a: &Artifact) -> Match; fn unpack(&self, a: &Artifact, ctx: &mut Ctx) -> Result<Vec<Artifact>>; }
trait Analyzer { fn id(&self) -> &'static str; fn applies(&self, a: &Artifact) -> bool;
                 fn analyze(&self, a: &Artifact, ctx: &Ctx) -> AnalyzerOutput /* facts, findings, limitations */; }
trait Renderer { fn render(&self, report: &Report, opts: &RenderOpts) -> Result<Vec<u8>>; }
```

Adding a format = implementing an `Unpacker` and/or an `Analyzer` and registering it, without touching the core.

### 3.4 Provisions for the desktop app (constraints to hold from phase one)

The CLI comes first, but from M0 on the code is written as "the engine is a library, the CLI is a thin shell", so the desktop app needs no rework:

1. **All analysis logic is in libraries**. `aa-cli` contains no analysis code; library crates do not print directly, do not read the command line, and do not call `process::exit`.
2. **One entry point** `aa_engine::analyze(input, options, &mut dyn ProgressSink) -> Result<Report>`.
3. **Progress is structured events** (stage start/end, current file, done/total, warnings). The CLI renders them as a progress bar, the desktop app renders them as UI.
4. **Cancellable**: long tasks check a cancel flag periodically; after cancellation they return the completed part and record it as a "limitation".
5. **`report.json` is self-contained**: the desktop app, like `analyze-anything render`, can display and re-export from it alone, without the original file.
6. **The artifact tree can be read on demand**: provide an interface to "get bytes / get a hex fragment by node ID", used when the desktop app opens a piece of evidence.
7. **Configuration is data**: limits, profiles and rule paths are all in the `Options` struct, with no dependence on environment variables or global state.

---

## 4. Report dimensions (what "all-round interpretation" means concretely)

The report always has the sections below. When a section does not apply, it shows "not applicable" instead of being omitted, which keeps the structure stable.

| # | Section | Content | Example |
|---|---|---|---|
| 0 | **Summary** | Understand it in one page: what this is, who published it, how big it is, what it was built with, key risk points, coverage | "iOS app com.x.y 3.2.1, Team ABCDE12345, Swift + Flutter, contains 14 third-party SDKs" |
| 1 | **Identity** | Name, package name/Bundle ID, version, build number, minimum OS, architectures, hashes (MD5/SHA-1/SHA-256/TLSH), icon | |
| 2 | **Origin and signature** | Certificate chain, signer, validity period, timestamp, whether the signature covers everything, notarization/Notarization ticket, provisioning type (development/AdHoc/enterprise/store), APK signature scheme v1–v4, Authenticode | |
| 3 | **Structure inventory** | Artifact tree, size distribution (Treemap), file type statistics, Top N largest files, duplicate files, nested packages | |
| 4 | **Tech stack and composition** | Languages (Swift/ObjC/Kotlin/Java/C++/Rust/Go/.NET), frameworks (Flutter / React Native / Electron / Unity / Qt / Xamarin / Tauri…), compiler and SDK versions, third-party library/SDK inventory (with versions), SBOM | |
| 5 | **Permissions and capabilities** | Android permissions and exported components, iOS entitlements and usage descriptions, URL Scheme / deep link, Windows manifest (UAC level), installer behavior (registry writes, autostart, services, drivers) | |
| 6 | **Security hardening** | PIE/ASLR, NX/DEP, Stack Canary, RELRO, CFG, ARC, whether stripped, debug flags, ATS / cleartext, backup switch, packer/obfuscation identification | |
| 7 | **Network and endpoints** | URLs, domains, IPs, certificate pinning configuration, classification of cloud service endpoints | |
| 8 | **Sensitive information** | Hard-coded keys/tokens/private keys (heuristic, shown redacted), embedded certificates, credentials in configuration files | |
| 9 | **Privacy** | Tracker/advertising/analytics SDKs, PrivacyInfo.xcprivacy, permissions related to Data Safety, inferred collection capabilities | |
| 10 | **Code insights** | Imported/exported symbols, ObjC/Swift class names, DEX class package structure, .NET types, interesting strings, Electron main process entry and IPC | |
| 11 | **Anomalies and suspicious points** | High-entropy sections, modified after signing, extension does not match content, hidden files, YARA hits | |
| 12 | **Analysis coverage and limitations** | See §2 item 3 | |
| Appendix | Full evidence table, file inventory (with hashes), rule versions, glossary | |

---

## 5. Key technical decisions

### 5.1 Artifact tree + recursive unpacking
All inputs are unified into one tree; node = `Artifact { id, path_in_tree, kind, size, sha256, parent, source: OnDisk|InMemory|Lazy }`. Small files stay in memory; large files go to a temp directory and are mmapped. Folder input and archive input take the same path, so "an installed Windows program directory" and "a .app directory" are supported naturally.

### 5.2 Rule data separated from code
SDK fingerprints, Tracker lists, secret regexes, packer signatures and permission risk levels are all versioned data files under `rules/`, embedded at compile time, and can be extended with `--rules`. The rule library has its own version number, which is written into the report.

### 5.3 PDF approach: embedded Typst
Comparison results:

| Approach | Conclusion |
|---|---|
| headless Chrome printing HTML | Good output but brings in an external dependency, which violates "single file, offline" ✗ |
| `fulgur` (Blitz + krilla, pure Rust HTML→PDF) | Promising, but fairly new; long-table pagination / CJK need validation; kept as a fallback |
| `printpdf` / `krilla` with hand-written layout | A lot of work; tables/pagination/table of contents all have to be built by hand ✗ |
| **`typst` embedded as a library** | **Chosen**: a mature typesetting engine, automatic table of contents/headers and footers/tables across pages/code blocks, good CJK support, pure Rust, reproducible output ✓ |

How: IR → Typst source (templates embedded) → `typst-pdf` output. A set of open-source fonts is embedded (including Chinese, e.g. a Noto Sans SC subset) to keep output consistent across machines; `--font` overrides it. Measured binary growth is about 39 MB (of which fonts are 8.6 MB); it can be turned off with the `pdf` feature.

### 5.4 HTML
Single file, self-contained (CSS/JS/icons inlined, no external links), containing the full IR data. Supports: section navigation, full-text search, artifact tree browsing, filtering by confidence/severity, clicking a finding to expand its evidence. Adapts to light and dark mode.

### 5.5 i18n
Findings are stored in the IR as `message_id + parameters`; at render time the text is picked by `--lang zh|en`. The first release ships Chinese + English.

### 5.6 Performance targets
Parallel analysis with `rayon`; a 500 MB IPA at the `standard` profile in ≤ 60 seconds with peak memory ≤ 1 GB (laptop). The `quick` profile skips the full strings/YARA scan.

---

## 6. Roadmap

### 6.1 Phase one: CLI (M0–M6 → v1.0)

Every milestone is accepted on "a demonstrable end-to-end result + golden tests", and releases a usable preview version.

| Milestone | Content | Acceptance | Version |
|---|---|---|---|
| **M0 Foundation and technical validation** (about 1 week) | Workspace skeleton, `aa-core` data model and IR schema, `aa-engine` entry point and progress events, CI (fmt/clippy/test/deny); **4 spikes**: ① embedded typst producing a Chinese PDF ② DMG (HFS+/APFS) reading ③ NSIS extraction ④ apk-info signature capability | `analyze-anything analyze <any file>` outputs JSON + MD with hashes/type/entropy; a spike conclusions document that decides, per format, between an existing crate and in-house code | — |
| **M1 Generic layer + four renderers** (about 2 weeks) | Artifact tree, recursive zip/tar/7z unpacking with limits, generic content analysis (strings, URLs, secrets, entropy), rule engine, md/txt/html/pdf renderers | A complete four-format report for any folder/archive | v0.1 |
| **M2 Native binaries** (about 2 weeks) | PE / Mach-O / ELF: headers, sections, imports/exports, hardening, symbols, language/compiler/framework identification, dependent libraries | Differential match with `otool`/`readelf`/`dumpbin` | v0.2 |
| **M3 The Apple family** (about 2–3 weeks) | `.app` / `.ipa` / `.dmg` / `.pkg`: Info.plist, code signature verification, entitlements, provisioning profile, PrivacyInfo, frameworks, FairPlay encryption detection; findings mapped to OWASP MASVS / CWE numbers | Differential match with `codesign -dvvv --entitlements` | v0.3 |
| **M4 Windows** (about 3–4 weeks) | Authenticode, version resources, manifest, .NET, NSIS / Inno / MSI installer semantics (what is installed, which registry keys are written, whether it autostarts), installed directories, Electron (asar); PE structure validity checks and initial packer screening, behavior profile summarizing imported APIs by category (network / crypto / inter-process communication / persistence); kernel driver (.sys) identification and basic information | Differential match with `sigcheck` / 7-Zip listings | v0.4 |
| **M5 Android** (about 2–3 weeks) | APK / AAB / XAPK: Manifest, resources, signature v1–v4 verification, DEX structure, native libs, SDK/Tracker fingerprints, packer identification; findings mapped to OWASP MASVS / CWE numbers | Differential match with `apksigner` / `aapt2`; compared against MobSF report items | v0.5 |
| **M6 Correlation, assessment and polish** (about 2–3 weeks) | Cross-artifact correlation, risk scoring, SBOM export, SARIF output, output manifest hashes and `analyze-anything verify`, visual polish of the report, fuzz, performance, release (prebuilt binaries for each platform) | All golden / differential / fuzz tests pass; prebuilt packages for three platforms | **v1.0** |

14–18 weeks in total. M3 / M4 / M5 are independent of each other; the order is Apple → Windows → Android.

**The four technical validations in M0** decide whether each format uses an existing library or in-house code. The conclusions go into `docs/SPIKES.md`:

| Validation | Pass criteria | Fallback if it fails |
|---|---|---|
| Embedded Typst producing a Chinese PDF | Has a table of contents, long tables across pages, no missing Chinese glyphs | Switch to `fulgur` (HTML → PDF) |
| DMG reading | Can list and read files inside HFS+ and APFS images with the common compression methods | In-house UDIF layer; for unsupported variants analyze only the outer layer and record a "limitation" |
| NSIS extraction | Can recover the install script and extract the embedded files | Fall back to generic analysis of PE + appended data |
| APK signature verification | v1–v3 verification results match `apksigner` | In-house signing block parsing and verification |

### 6.2 Phase two: desktop app (after CLI v1.0)

- **Positioning**: a graphical interface on the same engine, with no new analysis capability. Drop a file in → watch progress → browse the report → export PDF / HTML / Markdown / TXT.
- **What it has beyond the CLI**: artifact tree browsing, clicking a finding to jump to its evidence (with a hex view), filtering by confidence and severity, a list of past reports, comparison of two reports.
- **Framework: Tauri** (confirmed 2026-11-18). The UI directly reuses the HTML report from phase one, and the installer is small; it depends on the system WebView. The Rust side depends only on `aa-engine`.
- **Precondition**: all seven constraints in §3.4 are held throughout phase one.
- A separate desktop app plan with estimates will be written before work starts.

### 6.3 Phase three: ecosystem (v1.x)

- Interfaces for AI agents to call: MCP server and SKILL.md
- Optional AI interpretation layer (§7)
- Comparison report between two versions
- More inputs: Linux packages (deb / rpm / AppImage), HarmonyOS HAP, packaged programs such as PyInstaller
- `deep` profile: function-level analysis, optionally connecting to Ghidra or Kuna

---

## 7. Optional AI interpretation layer (v1.x, off by default)

- The only input is `report.json`; it does not touch the original files
- It outputs "plain-language interpretation / points worth attention / suggested next actions"; every sentence must cite a Finding ID; the renderer checks that the citation exists, otherwise it drops the sentence
- It gets its own chapter in the report, explicitly marked "AI-generated, based on the verified facts above"
- This gains "readability" without contaminating "reliability"

---

## 8. Testing and quality

- **Golden tests**: self-built minimal valid samples in `testdata/` (hello-world-level IPA/APK/NSIS/DMG… that we compile/package ourselves, can be checked in, no copyright issues) + expected `report.json`, `cargo insta` snapshots
- **Differential tests**: call authoritative tools in CI and compare (see §2 item 6)
- **Malformed samples**: truncated, corrupted, zip bomb, path traversal, extremely deep nesting — must degrade gracefully
- **Fuzz**: `cargo-fuzz` covers all in-house parsers
- **Determinism tests**: run the same input twice; `report.json` is byte-identical
- **Supply chain**: `cargo-deny` (licenses + security advisories), locked dependencies

---

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| The main binary of an IPA downloaded from the App Store is FairPlay-encrypted and the code segment is unreadable | Detect `LC_ENCRYPTION_INFO.cryptid` and mark it truthfully; metadata, resources, signature and frameworks can still be analyzed in full |
| Many DMG variants (APFS, encrypted, segmented, LZFSE/ULMO) | M0 spike; for unsupported variants clearly report "cannot be read" and still analyze the outer layer; write an in-house UDIF layer if necessary |
| Many NSIS / Inno versions, including modified builds | Rely on dedicated parsing crates; on failure fall back to generic analysis of PE + overlay |
| Some crates are not actively maintained (dex, apple-dmg, etc.) | The format specifications are public and stable; vendor or write a lightweight in-house parser if necessary; all third-party parsers are wrapped in panic isolation |
| False positives in heuristic findings (secrets, Trackers) | Confidence levels + redaction + evidence that can be opened and checked; rules come with test cases |
| Binary size (typst + fonts + yara-x) | Feature switches; the rule engine starts with `boreal` and moves to `yara-x` only if truly needed |
| Compliance: the legal boundary of reverse analysis | Purely static, read-only, no decryption, no bypassing; the README states it is only for objects you are entitled to analyze |
