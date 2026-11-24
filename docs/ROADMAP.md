# Roadmap

The latest stable release is [v0.1.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.1.1) for Apple silicon Macs. [v0.2.0-preview.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.0-preview.1) adds unsigned CLI archives for Windows x64, Linux x64 and ARM64, and Apple silicon macOS. The release workflow ran tests and self-checks for all four targets. The downloaded Windows ZIP also passed its self-check on the development machine.

The Windows x64 desktop app has passed local W10 acceptance, including offline NSIS installation. Hosted Windows and Ubuntu 24.04 x64 Linux desktop checks have also passed. The immediate work is **final combined 0.2–0.5 regression and packaged-artifact qualification**. The [delivery plan](PLAN-VERSIONS.md) defines the four product milestones; the [Windows plan](PLAN-WINDOWS.md) retains format-specific scope and acceptance gates. [TODO.md](TODO.md) tracks implementation, and [LIMITATIONS.md](LIMITATIONS.md) records supported profiles and verification gaps.

## Product milestones

The purpose of a report is to explain an unfamiliar supplied artifact: what it is, what it
contains, what capabilities and actions it declares, how its parts relate, and what could
not be established. The following milestones build that workflow in order. They are planned
acceptance groups, not claims that those versions have shipped.

| Milestone | User outcome | Main work |
|---|---|---|
| 0.2 — Reliable use | Obtain a working build and understand incomplete analysis | Cross-platform delivery, packaged-artifact verification, cancellation, resource limits and accurate platform documentation |
| 0.3 — Understand the supplied software | Read a coherent explanation with traceable details | Entry-point, payload, component and integrity relationships; report orientation and artifact-specific coverage |
| 0.4 — Read more contents | Inspect software currently hidden inside unsupported packaging | Bounded .NET single-file, PyInstaller, deb and rpm profiles that reuse the artifact tree |
| 0.5 — Find and reuse answers | Retrieve evidence efficiently from a finished report | Offline structured queries, report navigation, JSON compatibility and explicit agent analysis workflows |

Report readability, explicit limitations and real-sample verification accompany every
milestone. New formats are chosen
for the workflow they complete, with independent completion gates for each profile. See
[PLAN-VERSIONS.md](PLAN-VERSIONS.md) for acceptance requirements.

## Available today

`analyze-anything <file or folder>` builds an evidence-linked report. Ordinary analysis runs offline and produces the same report for the same input, version and options. It inventories unfamiliar inputs through file detection, digests, nested contents and observable strings. Format-specific readers add findings about areas such as signatures, configuration and dependencies.

| Input | Selected coverage |
|---|---|
| Apple | App bundles, IPA, DMG with HFS+ or APFS, and pkg. Code signatures, sealed resources, entitlements, provisioning profiles and privacy manifests. |
| Android | APK, AAB, and selected XAPK, APKS and APKM profiles. Signing schemes from v1 through v3.1, manifest and resources, DEX, permissions and network configuration. |
| Windows | PE, Authenticode, .NET, MSI, NSIS, Inno Setup, CAB, Electron, and selected MSIX profiles. The preview adds Windows entry-point and script readers, INF and catalog relationships, and NuGet, VSIX and WinGet package metadata. |
| Executable bundles and Linux packages | Bounded .NET single-file and PyInstaller CArchive contents; deb control/data archives and RPM v4 headers/CPIO payloads, with dependency, script and link declarations. |
| Other files and archives | Mach-O, ELF and PE hardening, nested ZIP, TAR, 7z and supported compressed streams, URLs and hosts, likely credentials, entropy and duplicate files. |

Reports are available as HTML, PDF, Markdown, text, JSON, SARIF and CycloneDX. The CLI can explain a finding, compare reports and verify exported files. The macOS desktop app adds a report and evidence viewer, history and comparison. A read-only MCP server serves finished reports. Optional deep analysis uses [Ghidra or Hopper](DEEP.md). Optional [AI interpretation](AI.md) works from findings in a finished report.

## Windows x64 desktop acceptance

The portable and NSIS-installed builds passed real-window WebView2 checks with byte-for-byte CLI export comparisons. Local checks covered Unicode and long paths, a locked input, cancellation and cleanup, native dialogs, keyboard navigation and driver source mapping. A disconnected Windows 10 x64 guest qualified offline WebView2 installation, Explorer drag and drop and 100% and 125% display scaling. Hosted Windows desktop CI has passed; final combined regression and signing remain release work. [Desktop validation](DESKTOP.md) · [W10 acceptance criteria](PLAN-WINDOWS.md#w10-windows-desktop-delivery)

### Windows foundation work

- **W0 — Real samples and parser accuracy.** Verify what the analyzer reads from real signed PE and MSI distributions and installed program folders against reference tools reading the same samples. This is a development acceptance check. Keep signature evidence and Windows trust-policy results distinct. [Windows CLI baseline](spikes/windows-baseline.md)
- **W1 — File access.** Resolve or document the remaining cases around ancestor replacement, mapped network drives, cloud files and EFS. [File-access coverage](spikes/windows-file-access.md)
- **W2 — Worker supervision.** The CLI can terminate an entire run. Define and test per-analyzer hard timeouts, descendant-process cleanup and the rules for returning partial reports. [CLI supervision](spikes/cli-supervision.md)

## Qualify releases and deepen existing Windows coverage

| Area | Remaining work |
|---|---|
| Cross-platform delivery | Qualify the Windows and Linux CLI previews on clean systems for formal distribution. Verify the Linux desktop app in a real window. Move the signed and notarized macOS release into CI when signing material is available. Desktop automatic updates are a separate delivery milestone. |
| Entry points and scripts (W3–W4) | Broaden Unicode path and alias coverage for shortcut relationships. Extend bounded PowerShell and batch syntax coverage with real samples and native references where available. |
| Driver packages (W5) | Add independent built INF/CAT packages, CAB and tag-media cases, and broader signature and catalog-member coverage. |
| MSIX (W6, deferred follow-up) | Cover dependency and AppInstaller relationships, and extend manifest, signature and bundle profiles. |
| Package metadata (W7) | Extend the version matching and relationship profiles behind the shared component inventory. The preview contains initial NuGet, VSIX and WinGet support. |
| Existing coverage gaps | Obtain representative packed APK, XAPK, encrypted DMG and Inno Setup 6.4 samples. Investigate the Xcode pkg CMS issue and the partially read device-support DMGs. |

## Later input formats and workflows

- **Executable bundles and installers.** Broaden the documented .NET single-file and PyInstaller profiles (W8), then address MSI action conditions and explicitly supplied payloads, and Burn (W9).
- **Linux and language packages.** Broaden the initial deb/rpm profiles and add AppImage, Flatpak, snap, Python wheels, npm tarballs and Java archives. Reuse the component inventory for dependency and package metadata.
- **Containers, platforms and documents.** Add OCI and Docker archives with layer provenance, HarmonyOS HAP, browser and VS Code extensions, Office macro and embedded-object analysis (W11), and PDF scripts and attachments.
- **Disk images and firmware.** Evaluate ISO, WIM and virtual disks separately (W12). Expand filesystem coverage to ext4, squashfs and FAT where it enables useful, bounded readers.
- **Deeper analysis and policy.** Add offline advisory matching, broader API and call-flow analysis, IDA and desktop deep-analysis integration, configurable rules and CI policy files.
- **Integration and report workflows.** Define a versioned JSON report contract, add GitHub Action recipes, extend the agent tools to request analysis, and make optional AI interpretation easier to configure, query and include in reports.

A new format is ready when it has reproducible evidence from constructed and redistributable real samples, a native comparison where a reference tool exists, and tested output for unsupported or partially read inputs. See [Adding an analyzer](ANALYZERS.md).

## Analysis guarantees

- Analysis reads inputs as data. It executes, installs, loads and decrypts none of them.
- Ordinary analysis is offline. Optional AI interpretation receives only findings from a finished report.
- The same input, options and version produce the same report.
- Findings carry evidence and confidence. Coverage and limitations record what could not be established.
- Reports describe observations and leave the verdict to the reader.

## How to help

When reporting a wrong or missing finding, include the relevant fragment of `report.json`. Share the input only if you can redistribute it. For contribution and test requirements, see [AGENTS.md](../AGENTS.md).
