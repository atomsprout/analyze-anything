# Analyze Anything — Research notes

> 2026-11-18. This is the basis for [PLAN.md](PLAN.md); the plan itself is in PLAN.md.

## 1. Reference projects

| Project | What it is | Worth borrowing | How it differs from us |
|---|---|---|---|
| **REA** (Reverse Engineer Anything, `morluto/rea`, MIT, Node.js) | An MCP server + CLI for AI agents. It wraps Ghidra / IDA / Hopper / JADX / Apktool / Binwalk and others as tools, so an agent can decompile, trace and test hypotheses interactively | ① Every finding carries **evidence + limitations + unknowns**; ② results are schema-validated on the server side; ③ its "target list" of coverage (ELF/PE/Mach-O, .NET, APK, Flutter, Electron, PyInstaller, IL2CPP, Godot, WASM…) can serve as our format roadmap | REA is **interactive, agent-driven and depends on heavy external tools**, with no fixed "report" artifact; we are **deterministic, run once to completion, have zero external dependencies, and deliver a report** |
| **Craft Anything** (`storytold/craft-anything`, MIT OR Apache-2.0, **pure Rust**, about 280,000 lines, early alpha) | "Understand any software and rebuild your own": a Research → Build → Check loop. About 314 inspection tools, exposed both as CLI subcommands and as MCP tools, plus an egui desktop app and a WASM build. The default is clean-room mode (looks only at external behavior); only `--deep` reads code and files | **Closest to our stack, and the primary reference**: ① the evidence model in `crates/evidence` — confidence `Observed / Derived / Inferred`, the authority source `Authority`, `Limitation`, `Coverage`, a first-class `Unknown` ("absence is not proof"), and evidence ID = SHA-256 of canonical JSON; ② `crates/formats` contains many in-house parsers (Mach-O, PE, ELF, DEX, AXML, ARSC, APK signatures, Authenticode, codesign, plist, nib, asset catalog, asar, .NET, PyInstaller, IL2CPP, Unity/Unreal/Godot…), with the underlying libraries split out into `storytold/craft-libs` (craft-pe / craft-macho / craft-elf / craft-dex / craft-zip / craft-plist…); ③ workspace-wide `unsafe_code = "forbid"`, `cargo-deny`, and the engineering discipline of `docs/pitfalls.md` | The goal is to **rebuild software**, driven by an agent; the report is only a side tool (`core_report_write`). It **does not cover** installers such as DMG / NSIS / Inno / MSI, has no provisioning profile, tracker/SDK fingerprints, hardening assessment or PDF output, and has no fixed pipeline that "produces a complete report with one command" |
| **RESX** (`ryftenius/resx`, MIT, pure Rust, about 70,000 lines, v2.3.0) | A static reverse-engineering toolbox focused on Windows x64 PE: `peinfo` / `pechk` health checks, recovery of hidden dynamic APIs (hashing, PEB walking), call graphs, behavior classification (`network` / `crypto` / `ipc` / `payload`), IOCTL code tables and device security checks for kernel drivers, sample diff / indexing / search, YARA. It only reads file bytes and never loads or executes anything | ① Very few dependencies (only 8, such as `iced-x86`); the PE, PDB and YARA parsers are all written in-house, which shows that writing the Windows part ourselves is feasible; ② JSON output discipline: a versioned envelope, **"missing evidence is output as null, never replaced with 0"**, and truncation is reported explicitly when a hit limit is reached; ③ layering: format parsing → shared facts per image (computed lazily and cached) → analysis → rendering, with no analysis in the command layer; ④ its concrete approach to PE validity checks, first-pass packer screening, behavior classification and driver analysis, as a reference for M4 Windows | It handles only deep reverse engineering of a single PE, with terminal output aimed at reverse engineers; it does not handle installers or other platforms, and has no finished report. Its function-level depth (call graphs, CFG reconstruction, parameter recovery) is beyond our v1.0 scope and is listed as a later candidate for the `deep` tier |
| **CLI-Anything** (`HKUDS/CLI-Anything`, Apache-2.0) | Wraps any software as an agent-callable CLI using a 7-stage pipeline | ① The idea of a pipeline with fixed stages; ② "Agent-native": every command supports `--json` and ships with a SKILL.md | A different goal (generating a CLI rather than analyzing artifacts). We borrow its agent-friendly interface design |
| **MobSF** (Python) | Static/dynamic security analysis of mobile apps, with PDF/JSON reports | Its report chapters are the de facto standard: permissions, exported components, signatures, binary hardening (PIE/Canary/NX/RELRO), hard-coded keys, URLs/domains, trackers (the Exodus database), APKiD packer identification | Covers mobile only, heavy to deploy (Docker + JDK), no desktop formats |
| **reknife / rbat / binsec** (Rust) | Binary health-check tools built on goblin + yara-x + iced-x86 | Proof that a pure Rust stack is feasible | They look only at a single executable, do not handle "packages", and have no complete report |
| **binwalk v3** (Rust) / unblob | Recursively identify and extract embedded data | Recursive unpacking, entropy analysis | Aimed at firmware; does not interpret semantics |
| **Detect-It-Easy / APKiD / capa / FLOSS** | Compiler/packer identification, capability identification, recovery of obfuscated strings | Rule sets and identification approaches | Each covers one part; no unified report |

## 2. Additions from a second round of searching (2026-11-18, based only on repository descriptions and READMEs; source code not read)

| Project | Language / size | What it is | Reference value for us |
|---|---|---|---|
| **reverify** (`2akouwu/reverify`) | ★1.3k | "The model proposes findings, deterministic tools verify them one by one" | Matches the idea of the AI interpretation layer in PLAN.md; when building the v1.x interpretation layer, study its verification mechanism closely |
| **knife / reknife** (`bl4ckr0ss3/knife`) | Rust, ★412 | A terminal-first reverse-engineering toolbox for PE / ELF / Mach-O, with CLI + TUI + MCP; YARA goes through yara-x | The Rust peer closest to the M2 scope; reference for its subcommand layout and how it exposes MCP |
| **binskim** (`microsoft/binskim`) | C#, ★869 | Microsoft's security compliance checker for PE / ELF binaries; rules are numbered, output is SARIF | The **rule list and decision criteria** for hardening checks; consider adding SARIF output for easier CI integration |
| **checksec.rs** (`etke/checksec.rs`) | Rust, ★122 | checksec for the three platforms ELF / PE / Mach-O | A direct comparison for the decision logic of hardening items (can also serve as a differential testing baseline) |
| **capa** (`mandiant/capa`) | Python, ★6.3k | Uses rules to identify the "capabilities" of an executable (such as "takes screenshots" or "injects into processes"), mapped to ATT&CK | How rules for a behavior profile are organized; the rule set is Apache-2.0, so format compatibility can be evaluated |
| **APEX** (`mlab-sh/apex`) | Rust, ★2, GPL-3.0 | 15 analyzers for APK / AAB / XAPK / IPA + weighted scoring; findings map to CWE / OWASP MASVS / ATT&CK; the evidence bundle carries a SHA-256 manifest and an RFC 3161 timestamp | ① How findings are mapped to MASVS / CWE; ② the report manifest hash + a `verify` command. **GPL: look at the ideas only, not the code** |
| **ReArk** (`lkimuk/ReArk`) | C++, ★977 | Reverse engineering and AI-assisted analysis of HarmonyOS NEXT (HAP/APP/ABC), Android and iOS packages | A reminder: **HarmonyOS HAP** is an input format worth listing for v1.x |
| **MachOExplorer** (`everettjf/machoexplorer`) | Rust, ★647 | A Mach-O structure browser | Reference for how M3 presents Mach-O fields |
| **disrobe** (`1-3-7/disrobe`) | Rust, ★174 | Python decompilation, unpacking and deobfuscation of PyInstaller and others | Reference for unpacking PyInstaller / Python-packaged programs (v1.x) |
| **Kuna** (`Noelo-Lab/kuna`) | Rust, ★907 | An agent-oriented decompiler, ported from Ghidra | If the `deep` tier ever produces pseudocode, this is a pure Rust candidate to integrate with |
| **binsider** (`orhun/binsider`) | Rust, ★4.5k | Interactive terminal analysis of ELF | ELF only; reference for TUI interaction |
| **cwe_checker** (`fkie-cad/cwe_checker`) | Rust, ★1.4k | Finds CWE vulnerability patterns in binaries (depends on Ghidra) | Beyond the v1.0 scope; recorded for later reference |
| APKHunt / APKDeepLens / apkAnalyzer | Python | Various static APK scanners, with HTML / PDF / SARIF output | A comparison for the M5 check list |
| ida-pro-mcp / GhidraMCP / Open ReverseLab / Eleven | — | MCP bridges that connect IDA / Ghidra / x64dbg / Frida to agents | The same class as REA: interactive reverse engineering, no report; complementary to us |

**Conclusion of this round**: we still found no peer that does "any desktop/mobile artifact → one complete report with evidence"; the closest ones, MobSF (mobile only, Python) and APEX (mobile only, and only 3 analyzers run on IPA), cover neither Windows installers, macOS applications nor DMG. Three items were added to the plan as a result: mapping findings to **OWASP MASVS / CWE** identifiers (M3–M5), **SARIF** output (M6), and a report manifest hash with `analyze-anything verify` (M6); HarmonyOS HAP and PyInstaller are listed for v1.x.

**The gap (our opportunity)**: no tool today satisfies all of these at once —
① a fixed pipeline that delivers a **report** (rather than agent interaction or a software rebuild); ② coverage of IPA / APK / Windows installers / installed program directories / .app / DMG together; ③ **cross-file correlation** after recursive unpacking; ④ a single pure Rust binary, offline, with four outputs: PDF/HTML/MD/TXT.

## 3. Availability in the Rust ecosystem (versions as measured on crates.io on 2026-11-18)

| Capability | Preferred crate | License | Notes |
|---|---|---|---|
| ELF / PE / Mach-O parsing | `goblin` 0.10.7 (supplemented by `object` 0.41) | MIT | Mature, supports fat binaries |
| Apple code signing / entitlements | `apple-codesign` 0.29 | MPL-2.0 | Heavy dependencies, so it goes behind a feature; or parse the SuperBlob ourselves |
| plist / provisioning profile | `plist` 1.10 + `cms` + `x509-parser` 0.18 | MIT / Apache | A mobileprovision is a plist wrapped in CMS |
| DMG | `apple-dmg` 0.5 / `dmgwiz` 1.1 + `hfsplus` 0.4 + `apfs` 0.4 | MIT | **Risk**: coverage of APFS and encrypted DMG needs a spike to verify |
| pkg (xar / bom) | `apple-xar` 0.20, `apple-bom` 0.3 | MPL / MIT | |
| APK overall (AXML / ARSC / signing block) | `apk-info` 1.1.1 | Apache-2.0 | Claims to be malware-robust; v3/v4 signature verification has to be added ourselves |
| DEX | `dex` 0.5 / `rusty-dex` 0.2 | MIT / Apache | Both are rather old; we may need to write a lightweight parser ourselves (the format is stable and the specification is public) |
| NSIS installers | `nsis` 0.6.1 | Apache-2.0 | Aimed at malware analysis; can parse the script + extract files |
| Inno Setup | `innospect` 0.2 / `inno` 0.7.6 | Apache / MIT | |
| MSI / CAB / CFB | `msi` 0.11, `cab` 0.6, `cfb` 0.16, `lzxd` | MIT | |
| General archives | `zip` 9.7, `tar`, `sevenz-rust2` 0.25, `flate2`/`xz2`/`zstd`/`bzip2` | MIT / Apache | RAR only has C bindings (`unrar`); made an optional feature |
| Authenticode | `authenticode` 0.6 + `cms` + `x509-parser` | MIT / Apache | Chain validation has to be assembled ourselves |
| .NET metadata | `dotscope` 0.9.1 | Apache-2.0 | Pure Rust ECMA-335 |
| Electron asar | `asar` 0.3 | MIT / Apache | |
| Disassembly | `iced-x86` 1.22, `disarm64` 0.2 / `yaxpeax-arm` | MIT | Lightweight uses only (entry points, signatures); no decompilation |
| Debug info / symbols | `gimli` 0.34, `pdb` 0.8, `symbolic-demangle` | MIT / Apache | |
| Rule engine | `yara-x` 1.23 (or the lighter `boreal` 1.4) | BSD-3 / MIT | yara-x brings wasmtime and is large; boreal is lighter |
| File type identification | `infer` 0.22 + our own magic number table | MIT | |
| Similarity hashing | `tlsh2` 1.1 | Apache / BSD | Avoids the GPL `ssdeep` |
| SBOM | `cyclonedx-bom` 0.9 | Apache-2.0 | |
| Templates / Markdown | `minijinja` 3.1 / `askama` 0.16, `comrak` 1.0 | Apache / MIT / BSD | |
| **PDF** | **`typst` 0.15 + `typst-pdf` (embedded as a library)** | Apache-2.0 | See PLAN.md §5.3 |

**License red line**: no GPL crates (such as `exe`, `ssdeep`); MPL-2.0 (apple-codesign / apple-xar) is acceptable case by case but must be declared in NOTICE.

> Limitation: the environment used for this research could not reach docs.rs. The "existence / version / license" of each crate in the table above was therefore verified through crates.io, but **API depth (for example whether apfs can read compressed volumes, or whether apk-info verifies v3 signatures) has not been verified**; it is listed among the M0 technical validation tasks.

---

## Sources

- REA: <https://github.com/morluto/rea>; InfoQ coverage <https://www.infoq.com/news/2026/10/reverse-engineer-anything/>
- Craft Anything: <https://github.com/storytold/craft-anything> (source cloned and read: `crates/evidence`, `crates/formats`, `docs/tools.md`)
- RESX: <https://github.com/ryftenius/resx> (source cloned and read: `docs/architecture.md`, `docs/json-schemas.md`, `resx/src`)
- CLI-Anything: <https://github.com/HKUDS/CLI-Anything>; paper <https://arxiv.org/html/2606.03854v1>
- MobSF: <https://github.com/MobSF/Mobile-Security-Framework-MobSF>
- Rust crate versions and licenses: crates.io (verified with `cargo info` on 2026-11-18)
