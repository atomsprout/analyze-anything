# Roadmap

The current release is [v0.2.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.1), with unsigned CLI archives for Windows x64, Linux x64/ARM64 and Apple silicon macOS, plus Windows x64 desktop portable and offline NSIS packages. Its [source CI](https://github.com/atomsprout/analyze-anything/actions/runs/45893998208) and [release gates](https://github.com/atomsprout/analyze-anything/actions/runs/45893998676) passed, including extracted-package analysis/query/agent workflows. The published Windows portable app passed 67 real-window checks. The latest signed and notarized macOS/Homebrew release remains [v0.1.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.1.1); the earlier disconnected Windows guest qualification was not repeated with the 0.2.1 installer.

The previous **0.2–0.5 labels were implementation acceptance groups**, delivered together through [PR #6](https://github.com/atomsprout/analyze-anything/pull/6), with the worker-root correction in [PR #7](https://github.com/atomsprout/analyze-anything/pull/7). They are completed history, not four future releases. [PLAN-VERSIONS.md](PLAN-VERSIONS.md) retains that acceptance record; [TODO.md](TODO.md) tracks open work and [LIMITATIONS.md](LIMITATIONS.md) records its tested boundaries.

## Product direction

The purpose of a report is to explain an unfamiliar supplied artifact: what it is, what it
contains, what capabilities and actions it declares, how its parts relate, and what could
not be established. Existing opening questions, relationship indexes and offline queries
already support this. The next work should complete useful explanations and evidence
workflows around them, with a small acceptance set for each delivery.

## Related-project review (2026-11-27)

This is a review of official project documentation, not an execution, accuracy or
performance benchmark. The projects address different audiences; Malcat is a commercial
product. Their useful design lessons are selected against this project's fixed guarantees.

| Reference | Documented focus | Consequence for this roadmap |
|---|---|---|
| [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) | File identification using signatures and heuristics | Make identity and toolchain hints explainable, retain uncertainty and test false positives; expand profiles when real reports justify them. |
| [capa](https://github.com/mandiant/capa) | Capability rules with detailed match locations; offline result exploration | Explain a capability through scoped combinations of evidence and code locations. Static references must not become claims of execution. |
| [Malcat](https://malcat.fr/features.html) | Structured file inspection and native, .NET, Python and installer-code readers | Read more of code already captured, starting with one bounded .NET IL profile; keep navigation from an observation to its source. |
| [Syft](https://github.com/anchore/syft) and [ScanCode](https://github.com/aboutcode-org/scancode-toolkit) | Component inventories/SBOMs, package metadata and licence/origin evidence | Deepen the existing inventory and CycloneDX output: distinguish dependency declarations, captured components and their exact metadata sources. |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile static/dynamic analysis, including hybrid application code | Connect platform declarations to embedded contents. Hybrid code is a later candidate; running applications remains outside ordinary analysis. |
| [Binwalk](https://github.com/ReFirmLabs/binwalk) | Embedded data identification and extraction, primarily for firmware | Preserve container provenance and unread regions. Broad carving and firmware/filesystem expansion need their own bounded profiles and real cases. |

The resulting direction is an offline, reviewable explanation of one supplied software
artifact: identity, composition, declared operations, static capability evidence and unknowns.
Existing summaries, evidence/hex views, component inventories, CycloneDX, queries and MCP
are foundations to deepen. Comparing two software versions is not a delivery priority.

## Delivery order after 0.2.1

| Order | User outcome | Bounded scope | Acceptance |
|---|---|---|---|
| Completed foundation | Read a useful report and reliably finish or stop an analysis | Five representative real-input scenarios, source corrections and packaged CLI/agent automation, shipped through PR #8 in 0.2.1 | [Recorded report review](spikes/report-workflow.md); platform-specific CI/release gates retain their own revision and runtime scope |
| 1. MSI action-context increment — implemented; release qualification pending | Follow a declared operation to its condition, source and supplied target | MSI action sequences, phase/order, literal conditions and supported Binary-table payload links; reuse existing entry-point relationships and evidence navigation | Preserve original table/row evidence, ambiguous or missing targets and unread semantics; validate real redistributable samples against read-only native inspection. Reports and queries must expose the same facts without asserting execution. |
| 2. Explain static code references | See which method contains a capability-related reference and why it matters | Start with one .NET IL profile using existing CLR metadata; bounded method-body decoding, supported call/string/token references and a small set of explainable same-method evidence combinations | Real licensed samples and independent static-reader references; method/token and proven byte locations, malformed/unsupported cases and budgets; no runtime loading and no inferred execution or complete reachability |
| 3. Clarify software composition | Distinguish a declared dependency from a component actually present | Extend one existing Electron/npm profile with selected packaged manifest/lockfile relationships, reusing component IDs and CycloneDX | Source file/field, declared range versus captured version, missing/ambiguous targets and declared licence provenance remain distinct; no registry lookup or host dependency resolution |
| Optional follow-up: retain raw evidence | Revisit selected byte evidence after the original input is unavailable | User-selected bounded fragments for saved reports/history, with hashes, explicit omissions and export controls | Define storage caps and secret/redaction handling first; reopened fragments verify against their manifest; do not delay semantic readers for a full portable-evidence archive |

Assign release numbers after each scope is fixed. Evidence navigation and explicit unknowns
are acceptance requirements for every increment. Moving .NET IL ahead of raw-byte retention
prioritizes explaining currently opaque captured contents; retention improves later review
but does not explain those contents itself. Python bytecode/PYZ and hybrid JavaScript remain
separate candidates after the first code profile is qualified.

Signing/notarization, broader OS baselines and installed-package qualification continue as
separate delivery work, with claims limited to the actual artifacts and environments tested.

### First work package: real reports and packaged workflows

The scoped review and Windows process checks are complete; see
[the inputs, reading answers, corrections and reproducible gates](spikes/report-workflow.md).
The acceptance definition below is retained for subsequent deliveries. The MSI action-context increment is implemented; its native references and remaining W9
boundaries are recorded in [the Windows plan](PLAN-WINDOWS.md#w9-installation-declarations-and-payload-relationships).

Use five scenarios spanning an installer with supplied payloads, an installed application
folder, an Android or Apple application, a Linux package and a modern executable bundle.
Choose inputs from licensed fixtures or explicitly sourced real samples. Record the input
hashes and expected observations; native references check the same sample where available.

Read each report through using the same questions:

1. What kind of software or package is this, and what establishes its identity?
2. Which entry points and components were established?
3. Which permissions, operations and network references are declared or observed in bytes?
4. Where is the evidence, and what is its confidence or resolution status?
5. Which contents or semantics remain unread or unresolved?

Fix missing context, difficult evidence navigation and understated unknowns found in those
cases. Existing summaries and queries should be reused. Turn the actual release-package
analysis, query and agent smoke into a repeatable gate, including private fresh/aged scratch
roots, cancellation/EOF cleanup and explicit partial results. Update installation and
qualification wording to distinguish published packages from earlier candidate checks.

Exit with a recorded report review and automated packaged-workflow checks. Use those
results to choose the next increment. The first planned feature increment is MSI action
context; Burn, patch/transform semantics and broad script control-flow analysis have
separate feasibility gates in [PLAN-WINDOWS.md](PLAN-WINDOWS.md#w9-installation-declarations-and-payload-relationships).

### Follow-up boundaries

Installation conditions depending on host state or user choices remain literal or
unresolved. Targets are associated only within explicitly supplied inputs. A command
declaration, a matched file and evidence of an API reference retain distinct meanings.

Saved reports already retain findings and their textual evidence, and offline queries
already work without the original input. The evidence-retention work adds selected raw
bytes/hex for history and portable review. It must define size caps, secret/redaction
handling and user selection before storing fragments; AI tools remain report-only.

Code inspection must use bounded byte readers or the existing explicitly requested deep
level. Managed assemblies and Python objects are never loaded into their runtimes. A code
reference does not establish a runtime call or a complete control-flow explanation.

## Available in the implementation

`analyze-anything <file or folder>` builds an evidence-linked report. Ordinary analysis runs offline and produces the same report for the same input, version and options. It inventories unfamiliar inputs through file detection, digests, nested contents and observable strings. Format-specific readers add findings about areas such as signatures, configuration and dependencies.

| Input | Selected coverage |
|---|---|
| Apple | App bundles, IPA, DMG with HFS+ or APFS, and pkg. Code signatures, sealed resources, entitlements, provisioning profiles and privacy manifests. |
| Android | APK, AAB, and selected XAPK, APKS and APKM profiles. Signing schemes from v1 through v3.1, manifest and resources, DEX, permissions and network configuration. |
| Windows | PE, Authenticode, .NET, MSI, NSIS, Inno Setup, CAB, Electron, and selected MSIX profiles. Version 0.2.1 includes Windows entry-point and script readers, INF and catalog relationships, and NuGet, VSIX and WinGet package metadata. |
| Executable bundles and Linux packages | Bounded .NET single-file and PyInstaller CArchive contents; deb control/data archives and RPM v4 headers/CPIO payloads, with dependency, script and link declarations. |
| Other files and archives | Mach-O, ELF and PE hardening, nested ZIP, TAR, 7z and supported compressed streams, URLs and hosts, likely credentials, entropy and duplicate files. |

Reports are available as HTML, PDF, Markdown, text, JSON, SARIF and CycloneDX. The CLI can explain a finding, query its evidence and verify exported files. The desktop app adds a report and evidence viewer and history. A read-only MCP server serves finished reports; the separate rooted server accepts explicit analysis requests. Optional deep analysis uses [Ghidra or Hopper](DEEP.md). Optional [AI interpretation](AI.md) works from a finished report.

## Windows x64 desktop acceptance

The portable and NSIS-installed builds passed real-window WebView2 checks with byte-for-byte CLI export comparisons. Local checks covered Unicode and long paths, a locked input, cancellation and cleanup, native dialogs, keyboard navigation and driver source mapping. A disconnected Windows 10 x64 guest qualified offline WebView2 installation, Explorer drag and drop and 100% and 125% display scaling. Combined-source hosted Windows desktop CI and unsigned packaging have passed; signing remains release work. [Desktop validation](DESKTOP.md) · [W10 acceptance criteria](PLAN-WINDOWS.md#w10-windows-desktop-delivery)

### Windows foundation work

- **W0 — Real samples and parser accuracy.** Verify what the analyzer reads from real signed PE and MSI distributions and installed program folders against reference tools reading the same samples. This is a development acceptance check. Keep signature evidence and Windows trust-policy results distinct. [Windows CLI baseline](spikes/windows-baseline.md)
- **W1 — File access.** Resolve or document the remaining cases around ancestor replacement, mapped network drives, cloud files and EFS. [File-access coverage](spikes/windows-file-access.md)
- **W2 — Worker supervision.** The CLI can terminate an entire run. Define and test per-analyzer hard timeouts, descendant-process cleanup and the rules for returning partial reports. [CLI supervision](spikes/cli-supervision.md)

## Qualify releases and deepen existing Windows coverage

| Area | Remaining work |
|---|---|
| Cross-platform delivery | Broaden OS baselines beyond those recorded for the published unsigned 0.2.1 packages. Extend the hosted Linux window checks to physical-display and packaging acceptance. Move the signed and notarized macOS release into CI when signing material is available. Desktop automatic updates are a separate delivery milestone. |
| Entry points and scripts (W3–W4) | Broaden Unicode path and alias coverage for shortcut relationships. Extend bounded PowerShell and batch syntax coverage with real samples and native references where available. |
| Driver packages (W5) | Add independent built INF/CAT packages, CAB and tag-media cases, and broader signature and catalog-member coverage. |
| MSIX (W6, deferred follow-up) | Cover dependency and AppInstaller relationships, and extend manifest, signature and bundle profiles. |
| Package metadata (W7) | Extend the version matching and relationship profiles behind the shared component inventory. Version 0.2.1 contains initial NuGet, VSIX and WinGet support. |
| Existing coverage gaps | Obtain representative packed APK, XAPK, encrypted DMG and Inno Setup 6.4 samples. Investigate the Xcode pkg CMS issue and the partially read device-support DMGs. |

## Later input formats and workflows

Select from this backlog when the report reviews establish a recurring blind spot. Each
new format retains the independent completion gates in [ANALYZERS.md](ANALYZERS.md).

- **Executable bundles and installers.** Broaden the documented .NET single-file and PyInstaller profiles (W8), then address MSI action conditions and explicitly supplied payloads, and Burn (W9).
- **Linux and language packages.** Broaden the initial deb/rpm profiles and add AppImage, Flatpak, snap, Python wheels, npm tarballs and Java archives. Reuse the component inventory for dependency and package metadata.
- **Containers, platforms and documents.** Add OCI and Docker archives with layer provenance, HarmonyOS HAP, browser and VS Code extensions, Office macro and embedded-object analysis (W11), and PDF scripts and attachments.
- **Disk images and firmware.** Evaluate ISO, WIM and virtual disks separately (W12). Expand filesystem coverage to ext4, squashfs and FAT where it enables useful, bounded readers.
- **Deeper analysis and policy.** Add offline advisory matching, broader API and call-flow analysis, IDA and desktop deep-analysis integration, configurable rules and CI policy files.
- **Integration and report workflows.** Build on the documented JSON contract and rooted agent server, add GitHub Action recipes, and make optional AI interpretation easier to configure, query and include in reports.

A new format is ready when it has reproducible evidence from constructed and redistributable real samples, a native comparison where a reference tool exists, and tested output for unsupported or partially read inputs. See [Adding an analyzer](ANALYZERS.md).

## Analysis guarantees

- Analysis reads inputs as data. It executes, installs, loads and decrypts none of them.
- Ordinary analysis is offline. Optional AI interpretation receives only findings from a finished report.
- The same input, options and version produce the same report.
- Findings carry evidence and confidence. Coverage and limitations record what could not be established.
- Reports describe observations and leave the verdict to the reader.

## How to help

When reporting a wrong or missing finding, include the relevant fragment of `report.json`. Share the input only if you can redistribute it. For contribution and test requirements, see [AGENTS.md](../AGENTS.md).
