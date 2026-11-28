# What is left to do

Phase one (the command line) and the macOS desktop app of phase two (D0–D5) are done, and so is the optional AI interpretation of phase three. This file lists what is not finished, item by item; the direction and the order of the larger work are in [ROADMAP.md](ROADMAP.md). Known limits of what the program does are in [LIMITATIONS.md](LIMITATIONS.md); the desktop app is described in [DESKTOP.md](DESKTOP.md).

## Next delivery cycle

Current published baseline: [v0.2.6](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.6)
uses unsigned CLI/Windows desktop packages. Four stable breadth releases completed
30 → 33 → 36 → 40 primary/compression families: 35 primary, five compression and 11
separately tracked declaration families. Their frozen sources, CI/package gates and
public attachment checks are in [delivery qualification](spikes/delivery-qualification.md#format-breadth-releases).
Signed macOS/Homebrew remains at 0.1.1. The next depth and qualification priorities
are in [ROADMAP.md](ROADMAP.md#delivery-order-from-022).

- [x] **Complete the current report workflow.** [Review and reproduction](spikes/report-workflow.md),
  with five hash-bound real-input scenarios, reading/native/process records and concrete
  report corrections. Extracted-package analysis/query/agent gates passed for the four
  0.2.1 CLI archives; the published Windows portable app passed 67 real-window checks.
  Qualification of older candidates remains scoped to their named artifacts/environments.
- [x] **MSI action context and captured Binary targets.** Extend the existing CustomAction
  and LaunchCondition inventory with supported action sequences, phase/order, literal
  conditions and Binary-table payload links. Preserve original table/row evidence,
  ambiguity, unresolved states and unread semantics in reports and queries. Link supported
  declarations to captured targets without predicting installation or consulting the host.
  Read-only Windows Installer comparisons passed 97 constructed, 75 7-Zip and 107 OpenJDK
  checks; the profile has malformed, missing/ambiguous target and resource-limit tests.
  See [W9 scope and records](PLAN-WINDOWS.md#w9-installation-declarations-and-payload-relationships).
  Burn, external-payload profiles
  and MSP/MST semantics retain separate W9 gates.
- [x] **Audit the format catalogue and public count.** Start from the implemented
  baseline of 24 primary input families plus four compressed-stream formats. Record stable
  IDs, aliases, profiles, analysis depth, real-sample/reference evidence and limitations;
  distinguish implementation from independent qualification. Produce one machine-readable
  catalogue/support matrix from which README, website and release totals can be derived;
  check unique IDs, aliases and matching public totals in CI.
  The published 0.2.6 catalogue lists 35 primary + five compression families,
  and 11 separately tracked declaration families. Extracted-package checks verify the compiled profiles/count
  and program version against source. See [count policy](ROADMAP.md#format-inventory-and-count-policy).
- [x] **Linux breadth A implementation: Arch packages and general ar archives.** Added two primary
  families (28 to 30 including streams), following the baseline audit. Reuse TAR/streams
  for package identity, bounded `.PKGINFO`, build/install declarations and payload/link
  evidence. Qualify normal GNU/BSD ar names, indexes and captured member bytes; retain
  thin references without reading outside the supplied input. Generic deb ar parsing is
  not general ar support. Use licensed real packages/libraries and independent references.
- [x] **Linux declarations alongside A.** Add bounded systemd unit, Desktop Entry and
  AppStream readers as three separately counted declaration families. Preserve source
  fields/lines, unknown keys and unsupported substitutions. Add unambiguous supplied-file
  entry and ELF-library relationships; no host lookup, startup or runtime-loader claims.
- [x] **Qualify and publish breadth A as 0.2.3.** Frozen source
  `8d8f4787f57d9ecb595e95584a4957b3abb0fc4d` passed source/native/package gates;
  all 11 published attachments, their checksums and the extracted CLI version/catalogue
  were verified. [Delivery record](spikes/delivery-qualification.md#format-breadth-releases).
  Native records retain their named source and input scope.
- [x] **Linux breadth B implementation: SquashFS, AppImage Type 2 and snap.** The 0.2.4
  release adds three primary families (30 to 33 including streams): bounded
  SquashFS v4 gzip/XZ metadata/file decoding, checked Type 2 extents and AppRun evidence,
  and snap metadata/application/interface/hook declarations with supplied-file links.
  Canonical hello-world 29 and external AppImageKit 12 have hash-bound Windows 7-Zip
  records and 84 Linux unsquashfs checks at a600591; other ELF and fragment/inode
  profiles retain constructed or pending native qualification. Never mount an image or
  invoke its runtime, including extract switches.
- [x] **Qualify and publish breadth B as 0.2.4.** Frozen source
  `2d92c117f26ff33eb1bd7c0e9c5090c4c2a31225` passed final-source native,
  cross-platform and packaged gates. Published attachment checks and the extracted CLI
  confirmed 33 families. [Delivery record](spikes/delivery-qualification.md#format-breadth-releases).
  Keep the sample/compressor and platform scope in
  [the image limitations](LIMITATIONS.md#linux-breadth-b-image-profiles).
- [x] **Language package breadth C implementation: wheel, npm tarball and JAR.** Three
  semantic readers are registered over the existing ZIP/TAR/stream pipeline. They retain
  identity, literal dependency/entry/script/manifest declarations, source metadata and
  captured member inventories. Constructed ambiguity, malformed-input and budget cases,
  three unchanged MIT-licensed published samples and independent references are checked
  in; the engine integration test covers source evidence and deterministic repeated reports.
  Java contributes one family with a qualified JAR profile; WAR/EAR remain unqualified.
  See [profile boundaries and records](LIMITATIONS.md#language-package-breadth-c-profiles).
- [x] **Publish breadth C as formal 0.2.5 after breadth B.** Frozen source
  `ccce4f795114e342c38c789318be0d35f96b2213` passed source/native/package gates;
  public attachment and extracted CLI checks confirmed 36 families. Independent package
  references retain their source/sample scope. WAR/EAR add no family and remain unqualified.
  [Delivery record](spikes/delivery-qualification.md#format-breadth-releases).
- [x] **Final breadth D implementation.** Alpine APK v2, full empty-base inline V0
  Flatpak bundles, one OCI/Docker-save family and independent-block LZ4 frames are
  registered with bounded metadata/payload provenance, licensed or project-owned native
  fixtures, independent static references and real engine/component tests. Flatpak
  output/path guards at 56fce92 passed native run 46109882704. Other base/opcode,
  filesystem/runtime and compression profiles remain explicit unknowns. See
  [D scope and records](spikes/final-format-breadth.md).
- [x] **Publish breadth D as formal 0.2.6 after A/B/C.** Frozen source
  `3a51020f6e680c611b46876461bf52c5f2947638` passed source/native/package gates;
  public attachment and extracted CLI checks confirmed 35 primary + five compression
  families = 40, with 11 declaration families separately counted. Final merged-main CI
  and Alpine native checks also passed. OCI/Docker variants count once; JAR does not
  qualify WAR/EAR. [Delivery record](spikes/delivery-qualification.md#format-breadth-releases).
- [ ] **Following breadth: bounded .NET IL references and capability explanations.** Qualify one
  profile using existing CLR metadata: method bodies, supported call/string/token
  references, and a small set of explicit same-method evidence combinations. Establish
  method/token and proven byte locations, budgets, supported versions and tested gaps
  with licensed real samples and independent static references. Do not load assemblies
  into a runtime or claim execution/reachability from static references. Python bytecode
  and hybrid JavaScript are separate later profiles.
- [ ] **Following breadth: deepen one component relationship profile.** Build on Electron/npm
  metadata and scope packaged manifests/lockfiles. Distinguish declared ranges from
  captured versions and declared dependencies from present components; retain source
  fields, declared licence provenance, ambiguity and missing targets. Reuse component
  IDs, queries and CycloneDX; no registry lookup or host resolution.
- [ ] **Optional follow-up: retained byte evidence.** Define user-selected bounded
  fragments, manifest/hash binding, omissions, storage caps and secret/redaction handling
  before adding saved-report/history byte retention. Existing hex views, textual evidence
  and report-only queries are the baseline. Improve evidence navigation within each
  feature; retaining raw bytes is not a prerequisite for reading more captured code.


## Completed delivery groups: 0.2 through 0.5

The implementation and scoped acceptance evidence are collected in
[PR #6](https://github.com/atomsprout/analyze-anything/pull/6), in the order defined in
[PLAN-VERSIONS.md](PLAN-VERSIONS.md). Their scoped implementation shipped together in
preview.2, with the additional worker-root correction in PR #7. These are historical
acceptance groups; the broader Windows and ecosystem projects below remain open.

- [x] **0.2 — Reliable use:** hosted platform checks, packaged CLI qualification,
  cancellation and limit semantics, and current installation documentation.
  - [x] Bind browser tests and readiness checks to the same explicit IPv4 address;
    production page build, 14 unit tests and 38 WebKit/Chromium tests passed on Windows.
  - [x] Verify packaged Windows ZIPs and Linux x64/ARM64 archives in the release workflow.
    Rehearsals 45360483004 and 45382485314 passed; the downloaded Windows archive passed its checksum,
    self-test and two independent CRT import checks. See [qualification](spikes/delivery-qualification.md).
  - [x] Verify hosted CI and release rehearsal and record supported runtime baselines.
    Combined-source CI 45382506185 at d047df8 passed all seven jobs, as did CI
    45386227144 after the final cancellation correction at 9dab32b. Windows/Linux
    real-window checks each passed 67 checks. Rehearsal 45382485314 passed all four
    builds, Windows desktop packaging and Linux x64/ARM64 self-tests in Ubuntu 24.04
    and Debian trixie-slim. Exact revisions and archive hashes are recorded in
    [delivery qualification](spikes/delivery-qualification.md).
  - [x] Compare a real signed MSI and installed directory; 127 native checks passed,
    including independent digests for 107 installed files. See [the record](spikes/windows-baseline.md).
  - [x] Resolve the url/cookie advisory gate through patched lockfile versions;
    the hosted advisory/license job passed again for the combined d047df8 source.
- [x] **0.3 — Understand the supplied software:** evidence-linked relationships,
  report orientation and attributable coverage, with ambiguous and unresolved cases.
  - [x] Add bilingual opening questions that cite existing findings and confidence,
    with direct HTML navigation to their evidence.
  - [x] Index supported supplied-file, driver-source, catalog-digest and package-dependency
    facts, preserving unknown targets, reasons, candidates and truncation.
  - [x] Distinguish lost content from complete byte reads in every report format and
    expose artifact-specific versus run-wide limitation counts.
  - [x] Pass 24 rendering regressions, the multi-file engine-to-renderer test and 38
    browser checks. English/Chinese PDF pages were visually inspected; see
    [the acceptance record](spikes/report-understanding.md). Combined-source CI
    45382506185 passed, including the expanded 38-check browser suite.
- [x] **0.4 — Read more contents:** bounded .NET single-file, PyInstaller, deb and rpm
  profiles, each with real samples, native comparisons and tested limitations.
  Hosted CI 45374182266 passed all three core and desktop platforms and the license
  gate at 52bb060; combined-source CI 45382506185 passed again at d047df8.
  - [x] Add bounded .NET single-file and PyInstaller CArchive readers, with original
    metadata evidence, native fixtures and published WinSW/yt-dlp comparisons. See
    [the profiles](spikes/executable-bundles.md).
  - [x] Implement and qualify deb/rpm metadata, payloads and declared installation scripts.
    The readers and 17 local tests pass; native run 45374169192 passed 125 checks,
    including source text and trigger declarations. See [the supported profiles](spikes/linux-packages.md).
- [x] **0.5 — Find and reuse answers:** offline report queries, report navigation,
  JSON compatibility and explicit agent analysis requests.
  - [x] Share offline bounded finding/evidence/file/coverage queries between the CLI,
    optional interpretation and read-only MCP, including the no-AI build. See [queries](QUERY.md).
  - [x] Check the schema header before parsing a report body, with explicit unsupported
    versions and tests of same-layout optional defaults. See [the JSON contract](JSON.md).
  - [x] Complete large-report navigation and its browser checks: isolated finding view,
    stable fragments, keyboard focus and filter retention; 38 browser checks passed.
  - [x] Add explicit rooted agent analysis separately from finished-report queries,
    with snapshot IDs, cancellation, deadlines and private worker cleanup. Windows
    process tests passed, as did hosted Unix path checks and combined CI 45382506185.
    CI 45386227144 passed again after fixing cancellation during deadline shutdown.

## Earlier release qualification after 0.2.0-preview.1

The CLI preview shipped for Windows x64, Linux x64 and ARM64, and Apple silicon macOS. Local Windows x64 desktop acceptance (W10) passed. [ROADMAP.md](ROADMAP.md) gives the delivery order and [PLAN-WINDOWS.md](PLAN-WINDOWS.md) records the scope and acceptance criteria.

1. Hosted Windows desktop CI and packaged-artifact qualification passed as recorded above. A fresh, disconnected Windows 10 x64 guest without `VCRUNTIME140.dll` reproduced the launch failure with the published preview.1 CLI. The statically linked preview.2 candidate ran its full CLI self-test in the same guest and exited successfully; that guest was not rerun with later rehearsal archives.
2. Extend Windows native CLI comparisons (W0), file-access coverage (W1) and worker isolation (W2).
3. Broaden the recorded Windows/Linux runtime baselines and prepare formal distribution. Expand coverage for entry points, scripts, drivers and package metadata (W3–W5, W7). MSIX follow-up work remains deferred (W6).
4. Scope modern executable bundles and installer relationships separately (W8, W9). Office and disk images remain separate projects (W11, W12).

Also investigate the Xcode pkg CMS parsing limitation and obtain real samples for the formats below. Linux desktop verification and signed release automation have their own acceptance criteria.

## Windows expansion

The detailed scope and completion gates are in [PLAN-WINDOWS.md](PLAN-WINDOWS.md). Items remain open until their full implementation and recorded comparisons are complete; partial checks are listed explicitly.

- [ ] **W0 — Real samples and parser accuracy**: read real installers and installed program folders on the available x64 machine; verify embedded and MSI signature results against `signtool` and the Windows signature view for the same samples. Record tool versions, sample digests and the differences in cryptographic checks versus system trust policy.
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
- [ ] **W8 — Modern bundles**: initial bounded .NET single-file and PyInstaller CArchive contents shipped in preview.2. Broader host/layout profiles and opaque code contents remain open; see [the qualified profiles](spikes/executable-bundles.md).
- [ ] **W9 — Installer relationships**: the initial five-table MSI sequence/condition and captured Binary-source profile shipped in 0.2.2. UI events, broader source/condition semantics, explicitly supplied external payloads and Burn retain separate gates.
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
- [x] A separate rooted tool-server mode in which an agent can explicitly request analysis; see [AGENT-SERVER.md](AGENT-SERVER.md).
- [ ] A SKILL.md for agents using the program.

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
  Local Windows x64 acceptance passed. Windows portable and NSIS-installed builds each passed 67 native WebView2 checks on the development host. A clean, disconnected Windows 10 x64 guest verified per-user WebView2 installation, 40 native self-checks, byte-for-byte CLI export parity, Explorer drag and drop and 100% and 125% scaling. Hosted Windows WebView2 and Ubuntu 24.04 x64 WebKitGTK checks each passed 67 checks at d047df8. Linux physical-display acceptance, broader packaging and signed delivery remain open. See [DESKTOP.md](DESKTOP.md).
- [ ] Broaden Linux and Windows delivery beyond the qualified unsigned 0.2.6 archives. The four stable breadth releases passed their packaged and public attachment checks; [delivery qualification](spikes/delivery-qualification.md#format-breadth-releases) records the frozen sources and runtime boundaries. The earlier statically linked preview.2 candidate passed a clean Windows 10 guest self-test; these later archives/installers were not rerun there. Broader OS baselines and signed delivery remain separate work.
- [ ] Automatic updates (out of scope for phase two).
- [ ] The signed release build is made on a developer's Mac with `tools/release/macos.sh`. Moving it into CI needs the certificate and the notarization credentials as repository secrets.

## Phase three: the ecosystem

- [ ] More inputs: broaden the qualified initial deb/rpm, PyInstaller and SquashFS/AppImage/snap profiles; add the planned language packages, HarmonyOS HAP and similar bundles.
- [x] A `deep` level: done with Ghidra and Hopper; what is left of it is under "The deep level" above.
