# What is left to do

Phase one (the command line) and the macOS desktop app of phase two (D0–D5) are done, and so is the optional AI interpretation of phase three. This file lists what is not finished, item by item; the direction and the order of the larger work are in [ROADMAP.md](ROADMAP.md). Known limits of what the program does are in [LIMITATIONS.md](LIMITATIONS.md); the desktop app is described in [DESKTOP.md](DESKTOP.md).

## Delivery milestones: 0.2 through 0.5

The implementation is being collected in one pull request, in the order defined in
[PLAN-VERSIONS.md](PLAN-VERSIONS.md). A checked subtask does not complete its milestone.

- [ ] **0.2 — Reliable use:** hosted platform checks, packaged CLI qualification,
  cancellation and limit semantics, and current installation documentation.
  - [x] Bind browser tests and readiness checks to the same explicit IPv4 address;
    production page build, 14 unit tests and 28 WebKit/Chromium tests passed on Windows.
  - [ ] Verify packaged Windows ZIPs and Linux x64/ARM64 archives in the release workflow.
  - [ ] Verify final hosted CI and release rehearsal and record supported runtime baselines.
- [ ] **0.3 — Understand the supplied software:** evidence-linked relationships,
  report orientation and attributable coverage, with ambiguous and unresolved cases.
- [ ] **0.4 — Read more contents:** bounded .NET single-file, PyInstaller, deb and rpm
  profiles, each with real samples, native comparisons and tested limitations.
- [ ] **0.5 — Find and reuse answers:** offline report queries, report navigation,
  JSON compatibility and explicit agent analysis requests.

Existing diff functionality remains available; comparing versions is not a milestone theme.

## Release qualification after 0.2.0-preview.1

The CLI preview shipped for Windows x64, Linux x64 and ARM64, and Apple silicon macOS. Local Windows x64 desktop acceptance (W10) passed. [ROADMAP.md](ROADMAP.md) gives the delivery order and [PLAN-WINDOWS.md](PLAN-WINDOWS.md) records the scope and acceptance criteria.

1. Finish hosted Windows desktop CI and the release rehearsal. A fresh, disconnected Windows 10 x64 guest without `VCRUNTIME140.dll` reproduced the launch failure with the published preview.1 CLI. The statically linked preview.2 candidate ran its full CLI self-test in the same guest and exited successfully.
2. Extend Windows native CLI comparisons (W0), file-access coverage (W1) and worker isolation (W2).
3. Qualify the Windows and Linux CLI previews on clean systems. Expand coverage for entry points, scripts, drivers and package metadata (W3–W5, W7). MSIX follow-up work remains deferred (W6).
4. Scope modern executable bundles and installer relationships separately (W8, W9). Office and disk images remain separate projects (W11, W12).

Also investigate the Xcode pkg CMS parsing limitation and obtain real samples for the formats below. Linux desktop verification and signed release automation have their own acceptance criteria.

## Windows expansion

The detailed scope and completion gates are in [PLAN-WINDOWS.md](PLAN-WINDOWS.md). Items remain open until their full implementation and recorded comparisons are complete; partial checks are listed explicitly.

- [ ] **W0 — Windows CLI baseline**: run real installers and installed program folders on the available x64 machine; compare embedded and MSI signatures with `signtool` and the Windows signature view. Record tool versions, sample digests and the differences in cryptographic checks versus system trust policy.
  Initial x64 no-AI build and 12 native checks passed; [the baseline record](spikes/windows-baseline.md) states the exact samples and remaining coverage.
- [ ] **W1 — Local file boundaries**: test Unicode and long paths, reparse points, locked files, extraction-name collisions and remote/cloud content; define named-stream coverage without making ordinary reports depend on machine metadata.
  Initial checks refuse explicit UNC/device/stream paths, reparse points and recall/encrypted file attributes; real junction, hardlink, named-stream, long Unicode path and locked-file tests pass. Ancestor replacement races, mapped network drives and real cloud/EFS samples remain open; see [the file-access record](spikes/windows-file-access.md).
  Generated archive tests also verify safe disk spilling of Windows-special logical names and preservation/reporting of duplicate and ASCII-case aliases.
- [ ] **W3 — Entry points**: read LNK, URL, REG and exported Task Scheduler XML, with evidence and unresolved-target limitations.
  Initial URL and LNK readers preserve supported declarations without opening targets/icons or expanding variables. The REG reader preserves writes/deletions and typed values. Task XML records literal triggers, actions, principals and settings. Native comparisons and independent licensed fixtures are recorded. A bounded tree pass now links unambiguous LNK relative declarations to supplied artifacts and records unresolved reasons for host-dependent references. Unicode alias profiles and broader coverage checks remain open; see [shortcuts](spikes/windows-shortcuts.md), [registry exports](spikes/windows-registry.md), [tasks](spikes/windows-tasks.md) and [input references](spikes/windows-input-references.md).
- [ ] **W4 — Scripts**: bounded static reading of PowerShell and batch syntax; no evaluation or host command resolution.
  PowerShell and batch have bounded literal syntax inventories and one-level EncodedCommand provenance. PowerShell has native AST references and administrator declarations. Batch expansion, complex syntax and broader declaration semantics remain open. See [Windows script scope](spikes/windows-powershell.md).
- [ ] **W5 — Driver packages**: INF declarations, catalog signature and membership checks, and links to supplied payloads.
  The bounded INF reader retains ordered section occurrences, decorations, fields and source lines, with a separate conservative neutral-string projection. Read-only SetupAPI comparisons cover Microsoft NullFilter/ECHO sources and controlled fixtures. Supported CatalogFile declarations can link to unique supplied CAT siblings. A bounded graph and bilingual details expose device IDs, install/service candidates, startup properties, copy sources, media and registry rows. Copy filenames and decimal media IDs retain declaration alternatives. Explicit logical INF/root assignments now travel through engine/worker/CLI and the optional desktop home-page control, mapping supported loose-file source paths to supplied digests, with size checks and conditional missing-candidate status. CAB/tag media, broader directive applicability, independent built packages and native Windows qualification of the desktop control remain open; see [the INF record](spikes/windows-inf.md), [declaration graph scope](spikes/windows-inf-relationships.md) and [source/root mapping profile](spikes/windows-inf-source-mapping.md).
  The catalog reader records CTL entries, bounded name/value attributes and supported member digest declarations, and checks signed attributes, content digests, signature values and embedded certificate links offline. Native-generated v1/v2 catalogs and content/signature mutations are compared with CryptCAT and signature-only SignedCms. A bounded tree pass compares supported flat/default-PE SHA-1/SHA-256 declarations with supplied bytes in the same container. Seventeen native SIP layouts, six controlled package layouts and five layouts of a pinned usbipd-win x64 snapshot cover initial agreement and unresolved cases. Broader SIP/CMS profiles, named missing-versus-changed relationships and additional independent built packages remain open; see [the catalog record](spikes/windows-catalogs.md), [membership scope](spikes/windows-catalog-membership.md) and [driver-corpus record](spikes/windows-driver-corpus.md). W5 is not complete.
- [ ] **W6 — MSIX integrity**: block-map checks, package signatures, bundle coverage and declared dependencies.
  The initial content layer reads bounded block-map declarations and checks SHA-256/384/512 blocks and the checked 2021 whole-file-hash extension against captured uncompressed bytes. Three SDK-built profiles and an independent Microsoft test APPX are compared with native AppxPackaging declarations and byte hashing across 23 original/tampered/missing/duplicate cases. ZIP duplicate names now mark enumeration incomplete. A separate bounded ZIP32/ZIP64 reader checks original record correspondence, raw block-map source binding and physical local-header/uncompressed sizes, with SDK unpacking and eight independent header comparison cases. Physical stored/independently decodable DEFLATE block extents now bind to captured targets, with independent hashes, mapped CRCs, empty final streams and final-segment terminators. Initial SHA-256 SIP/P7X declarations, CMS mathematics and five original package-region/footprint hashes now have CryptoAPI and independent comparison cases on one pinned Microsoft APPX. Manifest namespace/path/cardinality projections now preserve ambiguity and literal dependency/device-family/resource declarations, with four native references and five variants. A qualified publisher-to-verified-signer comparison now keeps signed manifest coverage separate, with native subject/literal comparison probes and controlled package cases; see [publisher scope](spikes/windows-msix-publisher.md). Base bundle declarations now bind stored OPC packages, original offsets/sizes, inner identities/architecture/type and separate outer signed-byte coverage, with three native references and six independent negatives; see [bundle scope](spikes/windows-msix-bundles.md). Bundle resource dimensions and 2018 target-device declarations now compare against captured inner manifests, with four native references and fourteen variants. Broader publisher encodings/certificate policy, full manifest schema/extension coverage, wider signature/bundle/resource profiles, dependency/appinstaller relationships and wider naming/compression/ZIP profiles remain open; see [the MSIX record](spikes/windows-msix-integrity.md) and [manifest record](spikes/windows-msix-manifest.md). W6 is not complete.
- [ ] **W7 — Package semantics**: NuGet, VSIX and WinGet metadata and supported dependency relationships in the existing component inventory.
  NuGet, VSIX 2.0 and WinGet 1.x now feed the shared component inventory. NuGet links supported exact stable dependencies and VSIX links qualifying exact nested dependencies. WinGet associates supplied manifest sets, links installer declarations to supplied bytes by SHA-256 and records supported package dependency candidates. See [NuGet](spikes/windows-nuget.md), [VSIX](spikes/windows-vsix.md) and [WinGet](spikes/windows-winget.md) for reference comparisons. Broader version matching and additional package and manifest profiles remain open.
- [ ] **W8 — Modern bundles**: supported .NET single-file and PyInstaller contents, beyond the existing metadata and marker recognition.
- [ ] **W9 — Installer relationships**: MSI action conditions and ordering, explicitly supplied external payloads, and a separate Burn feasibility check.
- [ ] **W11 — Documents**: staged Office container, macro-source and embedded-object analysis, with explicit limits for unread content.
- [ ] **W12 — Images**: separate feasibility and implementation gates for ISO, WIM and virtual disks, without mounting them.

W2 is tracked under "Loose ends of phase one"; W10 is the Windows part of D6 under "After phase two".

## Done (2026-11-19, on one Apple silicon Mac)

- [x] **The command line tried on a Mac**: 8 installed apps, 5 real IPAs and DMGs. 332 points agree with `codesign`. Five problems were found and fixed: files added by the App Store reported as "added after signing"; wildcard profiles and sandbox entitlements reported as exceeding the profile; a private-key marker with no key material reported as "embedded private key (high)"; an empty name when the input folder is itself an app; English file types inside Chinese reports.
- [x] **Encrypted IPAs from the App Store**: FairPlay encryption is recognized; metadata, signature and resources are analyzed in full.
- [x] Findings that are the same for every slice of a universal binary are merged into one, with the architectures in brackets.
- [x] An MSI's own digital signature: content digest, metadata digest, signature value and certificate chain are verified (compared with osslsigncode).
- [x] Mach-O export tries, chained fixups and bind opcodes (compared with `dyld_info`, `nm`, `objdump`).
- [x] Temporary folders left by a run that was killed are removed when the next run starts.
- [x] Scripts that compare against real samples are in the repository: `tools/native-compare/macos_real.py` (signatures), `macos_symbols.py` (imports and exports).
- [x] A stuck analyzer is really stopped in the desktop app, which runs the analysis in a child process and kills it on cancel. The command line still only stops waiting.
- [x] The desktop app, D0–D5: spikes, engine additions, the main flow, evidence and the hex view, history and comparison (with `analyze-anything diff`), packaging, signing and notarization.
- [x] Released through Homebrew: the command line and the desktop app install separately; Apple silicon only.
- [x] Reports and the app are in English unless another language is asked for.
- [x] The command is `analyze-anything` everywhere (it was `aa`, which macOS already has as Apple Archive), with the short name `aaaa`; a bare path is analyzed; the report goes to `<input>.report`.
- [x] The optional AI interpretation: the model looks things up in the report through read-only tools; run by a model service with an API key, Claude Code, Codex, Ollama, or a command; settings in `~/.analyze-anything/config.toml`. See [AI.md](AI.md).
- [x] CI passes on Linux, macOS and Windows for the current code (run of 2026-11-19). It found two things macOS had hidden: a worker that ended before it was asked was reported as a broken pipe, and two imports unused outside Unix.
- [x] An interface for AI agents: `analyze-anything mcp` serves a report's read-only tools over MCP.

## Done for 0.1.1 (2026-11-20)

- [x] **Every app in the Applications folder of one Mac**: 52 apps, 677,336 files, about seven and a half minutes, no failure. What looked wrong was compared with `codesign`, and six things were fixed:
  - a program whose bundle's `Info.plist` names no executable (the key absent, or empty) was reported as a file added after signing; the system goes by the bundle's name then, and so does this now;
  - a main program with a plist section of its own was reported as having a broken seal, though its Info.plist slot seals the bundle's file;
  - a framework that holds two versions (Chrome keeps the previous one beside the new) was reported as replaced code;
  - a TIFF picture was taken for an HFS+ disk because of two letters;
  - team-prefixed macOS app groups were reported as beyond the provisioning profile;
  - a bundle given as a folder was called "a folder".
- [x] Counts read right: "1 file", "1 URL scheme", "1 kind / 1 finding", with the verb agreeing, in rule texts, limitation details and the report's own words.

Left from that run, both honest limitations rather than wrong findings:

- [ ] The CMS signature of one Apple pkg inside Xcode (`XcodeSystemResources.pkg`) is not read: a tag the parser does not expect.
- [ ] The file system of Xcode's device-support disk images (`*_DDI.dmg`) is read only in part ("block 12 is not a B-tree node").

## The AI interpretation

- [x] Run the `claude` engine for real: done with a signed-in Claude Code on a 456-finding IPA report (no statement dropped).
- [x] Run the `codex` engine for real: done with Codex CLI 0.170 on the same report (no statement dropped).
- [x] Run the `ollama` engine against a real Ollama: done with `qwen3:4b` on a 456-finding IPA report (no lookups made by this small model, no statement dropped). A larger model that uses the tools has not been tried.
- [x] Run the Anthropic protocol of the `api` engine with a real key: done with `claude-opus-5-5` on a 456-finding IPA report (9 lookups, no statement dropped).
- [ ] Put the interpretation into the HTML and PDF reports as a chapter of its own, marked AI-generated.
- [x] Offer it in the desktop app: a panel beside the report, with the same settings file. Setting it up from inside the app, and stopping an interpretation that is under way, are not there yet.
- [ ] Follow-up questions about a report: `analyze-anything ask out/ "which hosts does it mention?"`.
- [ ] A SKILL.md, and a tool-server mode in which an agent can also ask for an analysis.

## The deep level

Done: `--deep` with Ghidra and Hopper, tried on a real IPA with both ([DEEP.md](DEEP.md)).

- [ ] IDA as a third tool. The interface is there; it has to be written where IDA can be run.
- [ ] Try it on Windows programs (PE), and Ghidra on Linux and Windows.
- [ ] Confirm that Hopper closes the documents the level opens: the script asks it to, and the windows are no longer on screen, but this was not looked at in the app itself.
- [ ] A longer list of APIs, and one a user can add to.
- [ ] Offer the level in the desktop app (the worker has to be told to use it).

## Waiting for a person

- [ ] GitHub Actions refused to start jobs for this organization while the repository was private ("recent account payments have failed or your spending limit needs to be increased"). Public repositories are not affected, so CI runs now; the billing notice still stands for anything private.
- [ ] The website is published by hand with `tools/site/publish.sh`; a workflow could take that over.
- [x] **Three manual checks of the desktop app**: native menus and shortcuts, drag and drop, the system's open and save dialogs. Done on 2026-11-19 with the released 0.1.0 (see [DESKTOP.md](DESKTOP.md)); to be repeated when the shell changes.
- [ ] **Read a real report through**: where `report.html` and `report.pdf` are wordy or lack something takes a person to judge. How much each chapter says, and how many findings of a kind are listed before they are merged (10 now), wait for that.
- [ ] Wire the two new scripts of [tools/native-compare/](../tools/native-compare/) into the "Native comparison" workflow. They need real apps on the machine; samples must be chosen for GitHub's runners first.

## Needs real samples

These formats were tested with constructed data only:

- [ ] **Packed APKs** (360, Tencent Legu, Bangcle and the like): confirm that the packer is recognized and that the report says the real code is not visible.
- [ ] **XAPK / APKS / APKM**. An `.apks` can be made from an AAB with Google's bundletool:
      `java -jar bundletool-all.jar build-apks --bundle=app.aab --output=app.apks`
- [ ] **Encrypted DMGs**: only "recognized as encrypted, and no content is claimed" was verified.
- [ ] **Inno Setup 6.4 installers**: the files come out, but the reference tool `innoextract` cannot read this version, so the result is unchecked.

## Loose ends of phase one

- [ ] English fragments left in Chinese rule text: file types follow the language now; the technical reason a signature failed (an error text from the parsing library) does not.
- [ ] **W2 — CLI worker supervision**: make whole-run cancellation and cleanup reliable, and establish the isolation and partial-report contract needed for hard per-analyzer timeouts. Reusing the desktop worker alone does not stop an individual timed-out thread at its deadline; see [PLAN-WINDOWS.md](PLAN-WINDOWS.md).
  Windows worker startup now requests no console window; worker lifecycle/protocol tests and Clippy pass. Manual window behavior and hard per-parser timeout semantics remain open.
  CLI analyze now supervises a child with the original rule/deep configuration, supports Ctrl+C and `--run-timeout`, and exports only a received report. Initial CLI parity, YARA/threshold, startup-failure and deadline tests pass; an unresponsive real worker is forcibly terminated and cleaned up in a test. Per-parser isolation, disassembler descendants and supervisor-crash cleanup remain open.
  Process workers now stop after parent-pipe loss; locked ownership markers support next-start recovery after both owners exit. Scratch locations inside the input are refused before worker creation. [The supervision record](spikes/cli-supervision.md) distinguishes tested disconnect/recovery behavior from remaining hard-isolation and crash cases.
- [x] In a comparison, known artifact display parameters are compared relative to the input. Input labels and the largest-file path no longer cause changes solely because the input was renamed; product names and embedded paths remain literal. Verified with export regressions and two generated ZIP reports on Windows.

## After phase two

- [ ] D6: the desktop app for Windows and Linux (build, installers, platform differences, end-to-end automation on Linux).
  Local Windows x64 acceptance passed. Windows portable and NSIS-installed builds each passed 67 native WebView2 checks on the development host. A clean, disconnected Windows 10 x64 guest verified per-user WebView2 installation, 40 native self-checks, byte-for-byte CLI export parity, Explorer drag and drop and 100% and 125% scaling. Hosted Windows desktop CI, signed delivery and Linux desktop verification remain open. See [DESKTOP.md](DESKTOP.md).
- [ ] Qualify Linux and Windows CLI builds for formal distribution. The published preview passed the release workflow self-checks. The statically linked Windows x64 preview.2 candidate passed its clean-system self-test. Linux clean-system checks and verification of the hosted release artifacts remain open.
- [ ] Automatic updates (out of scope for phase two).
- [ ] The signed release build is made on a developer's Mac with `tools/release/macos.sh`. Moving it into CI needs the certificate and the notarization credentials as repository secrets.

## Phase three: the ecosystem

- [ ] More inputs: Linux packages (deb, rpm, AppImage), HarmonyOS HAP, PyInstaller and similar bundles.
- [x] A `deep` level: done with Ghidra and Hopper; what is left of it is under "The deep level" above.
