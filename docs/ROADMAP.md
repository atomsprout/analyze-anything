# Roadmap

The published download baseline is [v0.2.2](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.2), including bounded MSI action context. The 0.2.3 candidate implements Arch/ar and Linux declarations, but its build and release qualification are still in progress; it has not been published. The later 0.2.4 source candidate implements SquashFS, AppImage Type 2 and snap, with its own integrated qualification and publication gates. Artifact and platform checks retain their recorded source and package scope. The latest signed and notarized macOS/Homebrew release remains [v0.1.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.1.1).

The preceding [v0.2.1](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.1) passed [source CI](https://github.com/atomsprout/analyze-anything/actions/runs/45893998208) and [release gates](https://github.com/atomsprout/analyze-anything/actions/runs/45893998676), including extracted-package analysis/query/agent workflows. Its Windows portable app passed 67 real-window checks. That record does not qualify later installers: the earlier disconnected Windows guest qualification was not repeated with the 0.2.1 or 0.2.2 installer.

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

## Delivery order from 0.2.2

| Order | User outcome | Bounded scope | Acceptance |
|---|---|---|---|
| Completed foundation | Read a useful report and reliably finish or stop an analysis | Five representative real-input scenarios, source corrections and packaged CLI/agent automation, shipped through PR #8 in 0.2.1 | [Recorded report review](spikes/report-workflow.md); platform-specific CI/release gates retain their own revision and runtime scope |
| Completed in 0.2.2: MSI action context | Follow a declared operation to its condition, source and supplied target | MSI action sequences, phase/order, literal conditions and supported Binary-table payload links; reuse existing entry-point relationships and evidence navigation | Preserve original table/row evidence, ambiguous or missing targets and unread semantics; validate real redistributable samples against read-only native inspection. Reports and queries must expose the same facts without asserting execution. |
| Implemented: format catalogue | Know how many format families have useful readers and which profiles were qualified | One catalogue with stable IDs, aliases, bounded profiles, evidence and limits; `formats --json` and generated public counts | Implementation and qualification boundaries are explicit; CI checks the matrix and public counts; extracted-package checks compare the compiled catalogue and version with source |
| Implemented in 0.2.3 candidate; building/qualification gates open: Linux expansion A | Explain Arch packages, static libraries and application/service entry declarations | Arch package metadata over TAR/streams; general ar members; bounded systemd, Desktop Entry and AppStream readers; supplied ELF library relationships | The A increment reaches 30 primary/compression families in release order. Linux references at 9731df0 passed 22 ar, 56 Arch and 68 declaration checks; these do not establish final candidate/package qualification or publication |
| Implemented in 0.2.4 source; qualification/publication gates open: Linux expansion B | Open filesystem-backed Linux applications | Little-endian SquashFS v4 gzip/XZ, AppImage Type 2 extents/AppRun evidence and snap declarations/supplied-file links | The B increment reaches 33 primary/compression families in release order. PR #12 and the source/release pipeline are underway; 0.2.4 is not published. Canonical hello-world and external AppImageKit 12 have Windows 7-Zip references and 84 Linux unsquashfs checks at a600591; final integrated/package gates remain separate. No mounting, runtime invocation or installation |
| Implemented, 0.2.5 release gates pending: language package expansion C | Explain software delivered through language ecosystems | Registered wheel, npm tarball and JAR readers over ZIP/TAR/streams; identity, literal dependency/entry/script/manifest declarations, metadata provenance and captured member inventories | Three MIT-licensed published samples; 15 matching Windows CLI reference checks and a separate OpenJDK manifest/member reference at 929703f. Engine integration covers evidence and deterministic reports. C adds three families, reaching 36 in the A/B/C delivery sequence. JAR qualifies one Java family; WAR/EAR remain unqualified |
| Implemented, 0.2.6 release gates pending: final breadth D | Explain Alpine packages, complete Flatpak bundles and supplied container image layers | Alpine APK v2; empty-base inline V0 Flatpak bundles; one OCI/Docker-save family; independent-block LZ4 frames | Licensed or project-owned native-writer fixtures, independent static references, deterministic engine/component integration and hostile-input budgets. The merged A/B/C/D source catalogue has 35 primary + five compression families = 40; 11 declaration families are separate. [Exact profiles and references](spikes/final-format-breadth.md); no installation, bundle import, image execution or merged-filesystem claim |
| Following depth work: explain static code references | See which method contains a capability-related reference and why it matters | Start with one .NET IL profile using existing CLR metadata; bounded method-body decoding, supported call/string/token references and a small set of explainable same-method evidence combinations | Real licensed samples and independent static-reader references; method/token and proven byte locations, malformed/unsupported cases and budgets; no runtime loading and no inferred execution or complete reachability. Deepening this existing family adds no format count |
| Following depth work: clarify software composition | Distinguish a declared dependency from a component actually present | Extend packaged manifest/lockfile relationships from the npm increment and existing Electron profile, reusing component IDs and CycloneDX | Source file/field, declared range versus captured version, missing/ambiguous targets and declared licence provenance remain distinct; no registry lookup or host dependency resolution |
| Optional follow-up: retain raw evidence | Revisit selected byte evidence after the original input is unavailable | User-selected bounded fragments for saved reports/history, with hashes, explicit omissions and export controls | Define storage caps and secret/redaction handling first; reopened fragments verify against their manifest; do not delay semantic readers for a full portable-evidence archive |

Breadth A, B, C and D are separate formal-release deliveries (0.2.3, 0.2.4, 0.2.5 and
0.2.6); implementation does not complete their CI, packaging or publication gates.
Evidence navigation and explicit unknowns are acceptance requirements for every increment.
Format breadth now takes priority, starting with Linux software, while each addition must
explain useful structure or declarations. .NET IL remains the first code-depth candidate;
Python bytecode/PYZ and hybrid JavaScript remain separate later profiles.

Signing/notarization, broader OS baselines and installed-package qualification continue as
separate delivery work, with claims limited to the actual artifacts and environments tested.

### Format inventory and count policy

The source inventory for 0.2.2 yields **24 selected primary input-format families and four
compressed-stream formats**, or **28 implemented catalogue entries**. This is a conservative
inventory of registered implementations, not a claim that every variant has independent
real-sample qualification. It does not enumerate every nested structure or declaration
reader. The first breadth increment implements [the audited source catalogue](FORMATS.md)
with **26 primary families + four compression formats = 30**. The merged A/B/C/D
source, version 0.2.6, contains **35 primary families + five compression formats = 40**,
with 11 separately tracked declaration families (including the existing Windows readers).
Every entry lists its bounded implementation profile and evidence; the source count does
not expand qualification or assert publication.

| Category | Count | Families in the implementation baseline |
|---|---:|---|
| Native binaries and executable containers | 5 | ELF; PE; Mach-O; .NET single-file bundle; PyInstaller CArchive |
| Software packages and installers | 13 | IPA; DMG; macOS PKG/XAR; Android APK family; AAB; MSI; NSIS; Inno Setup; MSIX/AppX; NuGet; VSIX; Debian deb; RPM |
| General archives | 6 | ZIP; TAR; 7z; CAB; ASAR; CPIO |
| Compressed streams | 4 | gzip; bzip2; xz; Zstandard |

The registrations are in [the standard engine](../crates/aa-engine/src/lib.rs),
[binary readers](../crates/aa-binary/src/lib.rs),
[Apple readers](../crates/aa-apple/src/lib.rs),
[Android readers](../crates/aa-android/src/lib.rs),
[Windows readers](../crates/aa-windows/src/lib.rs),
[Linux readers](../crates/aa-linux/src/lib.rs) and
[general/executable unpackers](../crates/aa-unpack/src/lib.rs).
The [stream reader](../crates/aa-unpack/src/stream.rs) implements the four baseline compressed streams;
the D increment adds the bounded [LZ4 frame reader](../crates/aa-unpack/src/lz4.rs).

Use stable family IDs and these rules for every later count:

- Merge aliases and variants: EXE/DLL/SYS are PE; APK/APKS/XAPK/APKM share the APK
  family; MSIX/AppX and their bundles share one family; thin/fat Mach-O share one family.
  PKG/XAR and CPIO variants are each counted once in this baseline.
- `.tar.gz`, `.tgz`, `.tar.xz` and `.tar.zst` combine existing archive and compression
  families. A new suffix, CPU architecture or format version does not increase the total.
- A semantic package family can reuse a general container, but must add identity,
  useful package declarations and attributable payload relationships. ZIP extraction alone
  does not qualify wheel or Java archive support; TAR extraction alone does not qualify
  Arch or npm package support.
- App bundles and installed directories are analysis scenarios. Nested HFS+/APFS, pbzx,
  DEX, Android XML/resources, plist and signature structures remain a separate capability
  list in this primary catalogue. Configuration, entry-point and script readers also have
  their own list: systemd unit suffixes form one declaration family, not eleven formats.
- Record detection, structural parsing, extraction, declaration analysis and signature
  verification separately. Recognition or generic string scanning does not add a family.
  An implementation entry and an independently qualified entry are different statuses.
  Report output formats such as HTML, PDF and JSON are not input-format entries.
- Every added family needs the existing [format completion gates](../AGENTS.md#adding-a-format):
  constructed and hostile-input tests, a licensed real sample, an independent static
  reference where available, deterministic evidence, bounded resources and tested limits.
  Record sample hash, source/licence, qualified profile and reference-tool revision.

The [machine-readable catalogue](../crates/aa-core/src/formats.json) now supplies README,
website-source and support-matrix totals. CI checks unique IDs, aliases and matching public
counts. Keep aliases, nested capabilities, qualification records and limitations visible.
The combined-source headline retains the split: **"35 primary format families + five
compression formats"**, linked to the same matrix. Planned additions are never included
in released totals. Counts describe implemented profiles, not complete support for every
variant. A/B/C/D are merged in the 0.2.6 source, while their formal releases retain
separate qualification and promotion gates; the published baseline remains 0.2.2.

Wheel, npm tarball and Java archives contribute three families; JAR is the qualified
Java profile, and WAR/EAR application profiles remain unqualified. npm's `.tgz` wrapper
and wheel's ZIP container add no entries. Alpine APK, full Flatpak bundles, OCI/Docker
variants counted together, and LZ4 contribute four families. See
[the C boundaries](LIMITATIONS.md#language-package-breadth-c-profiles) and
[D scope and native records](spikes/final-format-breadth.md).

### Linux breadth increments

The counts below show the ordered progression from the implementation baseline of 28.
All four increments are implemented in the merged source. Source counts become release
claims only after each increment's integrated and packaged qualification gates pass.

| Increment | New primary families | Projected total | Minimum useful scope |
|---|---|---:|---|
| A implemented: packages and libraries | Arch package; general ar archive | 30 | Bounded `.PKGINFO`, selected build/install declarations and payload/link inventory; normal GNU/BSD ar members reach existing ELF analysis, while symbol indexes remain declarations and thin references stay external |
| B implemented in 0.2.4 source: filesystem-backed applications | SquashFS; AppImage Type 2; snap | 33 | Bounded v4 gzip/XZ metadata/file decoding; proven Type 2 image extents and AppRun evidence; `meta/snap.yaml`, application/interface/hook declarations and supplied-file links. [Qualification boundaries](LIMITATIONS.md#linux-breadth-b-image-profiles) remain explicit |
| C: language packages, implemented; 0.2.5 pending | Python wheel; npm package tarball; Java archive family | 36 | Registered wheel metadata/dependency/entry-point reader; npm identity/dependency/script/TAR-declaration reader; JAR manifest/main-class/class-path and literal Maven-property reader, with captured inventories and source evidence. Three published samples and scoped native records are retained. WAR/EAR remain unqualified profiles in the same Java family |
| D: final breadth, implemented; 0.2.6 pending | Alpine APK; full Flatpak bundle; OCI/Docker image family; LZ4 frames | 40 | APK v2 control/payload authority; bounded empty-base inline V0 Flatpak object graph; descriptor/config/DiffID-bound ordered image layers; independent-block LZ4 integrity. Native and real fixtures qualify the documented profiles, without execution, installation, bundle import or merged image filesystems |

A also implements systemd unit, Desktop Entry and AppStream declaration readers. Keep these
three additions separate from the primary total. Relate literal entry targets and ELF
`DT_NEEDED`/SONAME declarations only to unambiguous supplied artifacts; do not consult the
host or predict loader selection. Kernel `.ko` metadata and Linux core-note readers are
later ELF profiles and add zero primary families. Linux desktop packaging and runtime
qualification also add zero input formats.

The reuse rationale follows the upstream formats:
[Arch packages](https://man.archlinux.org/man/alpm-package.7.en) use compressed TAR plus
package metadata; [ar](https://sourceware.org/binutils/docs/binutils/ar.html) contains
member objects and may hold thin references; [AppImage Type 2](https://docs.appimage.org/reference/architecture.html)
and [snap](https://snapcraft.io/docs/reference/development/yaml-schemas/the-snap-format/)
share SquashFS but have distinct package declarations. The three entry/identity formats
are specified by [systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
[Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest/) and
[AppStream](https://www.freedesktop.org/software/appstream/docs/chap-Metadata.html).
These are implementation priorities, not measured popularity or effort rankings.

The four D profiles are implemented and have licensed or project-authored native-writer
fixtures with independent static references. [Flatpak uses OSTree](https://docs.flatpak.org/en/latest/under-the-hood.html);
the reader handles the bounded complete-bundle profile recorded in [D scope](spikes/final-format-breadth.md),
rather than counting repository/reference documents as bundle support. OCI/Docker layer
order, whiteout/link declarations, descriptor digests and captured sources stay separate
from merged-filesystem or runtime semantics. Broader Flatpak operations, OCI profiles,
ISO/ext4 and other disk/firmware formats remain later work.

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
results to choose the next increment. The bounded MSI action-context increment is
implemented; Burn, patch/transform semantics and broad script control-flow analysis have
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
| Linux breadth | Arch package and ar members; systemd/Desktop Entry/AppStream declarations; SquashFS v4 gzip/XZ, AppImage Type 2 extents/AppRun evidence and snap metadata/supplied-file profiles. Source implementation and qualification are recorded separately. |
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

- **Executable bundles and installers.** Broaden the documented .NET single-file and PyInstaller profiles (W8), broaden MSI declaration/payload profiles, and evaluate Burn separately (W9).
- **Linux and language packages.** The Arch/ar, SquashFS/AppImage/snap and wheel/npm/Java increments are implemented above. Broaden the implemented deb/rpm, Alpine and Flatpak profiles after their scoped deliveries. Reuse the component inventory and keep package declarations distinct from captured dependencies.
- **Containers, platforms and documents.** Broaden the implemented OCI/Docker archive profile with its layer provenance; add HarmonyOS HAP, browser and VS Code extensions, Office macro and embedded-object analysis (W11), and PDF scripts and attachments.
- **Disk images and firmware.** Evaluate ISO, WIM and virtual disks separately (W12). Broaden the initial SquashFS profile and evaluate ext4 and FAT where they enable useful, bounded readers.
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
