# Where it stands and where it is going

Version 0.1.0 is the first release. This page says what it can do today, what "anything" means, and what comes next. The itemized list of open work is [TODO.md](TODO.md); what the program cannot do, or has not been checked to do, is in [LIMITATIONS.md](LIMITATIONS.md).

## What it does today

**One command, any input.** `analyze-anything <file or folder>` writes a report. Nothing is run, installed or sent anywhere, and the same input gives the same report byte for byte.

**A report you can check.** Every finding names the file it came from, the place in it, and the value that was read there, with a confidence (verified, derived, heuristic). What could not be read is listed under coverage and limitations, so "nothing found" is never confused with "not looked at". There is no verdict and no score.

**What it understands in depth**

| | |
|---|---|
| Apple | `.app` and other bundles, IPA, DMG (HFS+ and APFS), pkg. Code signatures down to each page hash, certificate chains, sealed resources, entitlements, provisioning profiles, privacy manifests, FairPlay encryption |
| Android | APK, AAB, XAPK / APKS / APKM. Manifest and resources, signature schemes v1 to v3.1, DEX, permissions, network security configuration, SDKs and packers |
| Windows | PE, Authenticode, .NET, MSI (with its own signature), NSIS, Inno Setup, CAB, self-extractors, Electron (asar), MSIX, installed program folders |
| Any file | Mach-O, ELF and PE hardening; zip, tar, gzip, bzip2, xz, zstd and 7z, nested to any depth; URLs and hosts, likely credentials, entropy, duplicate files |

**Seven outputs from one report.** HTML (interactive, self-contained), PDF, Markdown, plain text, JSON, SARIF and a CycloneDX bill of materials. `diff` compares two versions, `explain` shows one finding with all its evidence, `verify` tells whether a report folder was changed, and `--fail-on` makes a build fail.

**Three ways in.** The command line; a desktop app for macOS (drop a file, read the report, click evidence to see the bytes, keep a history, compare two versions); and a read-only MCP server through which an AI agent looks things up in a report.

**An optional AI reading.** Off unless set up. A model explains a finished report in plain words: through an API key, Claude Code, Codex, a model in Ollama, or a program of your own. It sees the report, never the files, and a statement that cites no finding of the report is dropped.

**How far it has been checked.** 400 and more automated tests on Linux, macOS and Windows. Signature results agree with `codesign` on 332 points across real apps, and with Windows' own tools on 132. The desktop app checks itself in its real window (67 checks). Used by hand on one Apple silicon Mac only; released for Apple silicon Macs only. [LIMITATIONS.md](LIMITATIONS.md) has the exact list.

## What "anything" means

It is a promise about the floor, and a direction for the ceiling.

**The floor holds today.** Any file or folder gets a report: what kind of thing it is, its digests, what is packed inside it layer by layer, the strings worth noticing, and, where it holds programs, how they were built. An unknown format is never an error; the report says what was recognized and what was not.

**The ceiling is raised one format at a time.** Understanding a format in depth (its signatures, its manifest, its permissions) takes an analyzer that knows it. There are three families now. Each new one is a crate that implements two small traits ([ANALYZERS.md](ANALYZERS.md)); nothing else in the program has to change, and every output format, the comparison, the desktop app and the AI reading get it at once.

So the work toward "anything" has four directions, and the order below is the order of priority.

### 1. The same thing on every system

What exists should work where people are before it grows.

- Released builds of the command line for Linux, Windows and Intel Macs. They build and pass their tests in CI; nobody has used them by hand.
- A first real run on a Windows machine, with the signature findings compared against `signtool`.
- The desktop app for Windows and Linux.
- The signed release built in CI instead of on a developer's Mac; automatic updates for the desktop app.

### 2. More kinds of input

Chosen by how often people meet them and how much a reader gains from depth.

- **Linux software**: deb, rpm, AppImage, Flatpak and snap. Maintainer scripts, dependencies, signatures.
- **Container images**: OCI and Docker archives, layer by layer, with what each layer added.
- **Packages of language ecosystems**: Python wheels and PyInstaller bundles, npm tarballs, Java jars and wars, NuGet packages. This is where a bill of materials earns its keep.
- **More app platforms**: HarmonyOS HAP, browser extensions (crx, xpi), VS Code extensions.
- **Documents that carry code**: Office files with macros, PDFs with scripts and attachments.
- **Firmware and disk images**: more file systems (ext4, squashfs, FAT), so that an image is a container like any other.

Formats that already exist but were only tried on constructed data (packed APKs, XAPK, encrypted DMGs, Inno Setup 6.4) get real samples first.

### 3. Deeper where it matters

- **Known vulnerabilities**: match the components of the bill of materials against an advisory database kept on disk, so the analysis stays offline and repeatable.
- **A `deep` level**: function-level facts (which code reaches which API), optionally through Ghidra, always with the evidence a reader can follow.
- **Rules as data**: let a team add its own checks without writing Rust.
- **Policies**: a file that says what a release must or must not have, turned into an exit code for CI.

### 4. Easier to use and to build on

- A GitHub Action and ready-made CI recipes for "report on every build, fail on a new high finding, comment the diff".
- The AI reading as a chapter of the HTML and PDF reports, marked as a model's; follow-up questions about a report (`analyze-anything ask`); setting it up from inside the desktop app.
- For agents: a skill, and a tool server that can also ask for an analysis, not only read a finished one.
- A stable `report.json` schema with versioning rules, so that other tools can rely on it.

## What will not change

These are what make a report worth trusting, and no feature is worth losing them.

- **Static only.** The input is read. It is never run, installed, loaded or decrypted.
- **Offline analysis.** The analysis connects to nothing. Only the optional AI reading sends anything, only when asked, and only findings.
- **Deterministic.** The same input and version give the same report.
- **Evidence for every finding**, and an honest list of what was not read.
- **No verdict.** The report shows what is there. Deciding what it means for you stays with you.

## How to help

Reports of wrong or missing findings are the most useful thing, with the one finding from `report.json` that shows it (not the file, unless you may share it). A format you need is worth an issue even without code. To add one, start with [ANALYZERS.md](ANALYZERS.md) and [AGENTS.md](../AGENTS.md).
