# Windows feature research and implementation plan

2026-11-20. Proposed work after 0.1.1. This plan expands the directions in
[ROADMAP.md](ROADMAP.md); the execution list remains in [TODO.md](TODO.md).

Use the Windows development machine first to establish a reproducible native baseline,
then deepen Windows package analysis and add the entry points people actually receive:
shortcuts, scripts, configuration files, driver packages and modern application bundles.
Follow with documents and disk images through separate, bounded projects. Most of the new
readers should work on Linux and macOS too; Windows supplies reference tools and real samples.

## What Anything should mean

A useful report answers six questions: what the input is, what it contains, where its
identity and integrity claims come from, what actions it declares, how its parts relate,
and what remains unread. Recognizing another extension alone does not finish a feature.

For each input family, track four levels separately: recognized, structure read, contents
analyzed, and compared against a reference on real samples. A format can reach different
levels for different versions or compression methods. The report must expose those gaps.
This is a coverage framework, not a safety verdict or a percentage claiming to measure
understanding of arbitrary software.

The five existing invariants remain requirements: read only, offline analysis, deterministic
reports, evidence with confidence, and no verdict. Native reference tools belong in development
checks under tools/native-compare, never as automatic dependencies of the analysis. The existing
optional deep level keeps its explicit boundary.

## Current capabilities and the Windows environment

The following baseline comes from source inspection. It does not replace a Windows test run.

| Area | Already present | Extension worth making |
|---|---|---|
| PE | Headers, imports including delay imports, exports, resources, manifests, debug references, load configuration and hardening, including CFG and CET indicators | Real architecture coverage, richer relationships between executables and libraries, selected newer structures after comparison |
| Signatures | Embedded Authenticode, nested signatures, timestamps, certificate chain checks; MSI content and metadata digest checks | Explicit catalog membership and driver-package coverage; more native reference cases |
| Installers | MSI, NSIS, Inno Setup, CAB and self-extractors; registry, service, shortcut and command declarations | Installation conditions and ordering, supported sibling payloads, Burn bundles; patches and transforms later |
| MSIX and APPX | ZIP contents plus AppxManifest.xml identity, capabilities and entry points | Block-map integrity, package signatures, bundles, dependencies and external references |
| .NET | CLR metadata, references, P/Invoke, resources; runtimeconfig.json and deps.json in a folder | Single-file bundle contents, stronger package relationships, explicit ReadyToRun and Native AOT coverage |
| Application folders | Signer and vendor summaries, capabilities, Electron settings and frameworks; PyInstaller marker detection | Evidence-backed links among launchers, scripts, libraries, services, packages and updates |
| Components | Shared component inventory, NuGet information from deps.json, CycloneDX export | Package manifests, dependency edges and declared-versus-observed relationships |
| Desktop | Shared engine, worker, evidence viewer, history and comparison | Windows packaging, WebView2 behavior, native interaction and end-to-end checks |

Code anchors: [Windows registration](../crates/aa-windows/src/lib.rs),
[MSIX manifests](../crates/aa-windows/src/appx.rs),
[installer model](../crates/aa-windows/src/installer.rs),
[MSI tables](../crates/aa-windows/src/msi.rs),
[folder analysis](../crates/aa-windows/src/tree.rs),
[PE analysis](../crates/aa-binary/src/pe.rs), and
[component correlation](../crates/aa-correlate/src/components.rs).

The current host reports Windows version 10.0.26200.0 on x64 and PowerShell 7.6.9. Cargo,
Rust, Python, Node, dotnet, makecab, DISM and certutil are discoverable. SDK directories
10.0.22621.0 and 10.0.26100.0 contain x64 SignTool executables, although SignTool is not on
PATH. Sigcheck, dumpbin, LLVM inspection tools and 7z were not found on PATH; that does not
establish that they are absent elsewhere. No CLI executable was found in the checkout's
usual target/debug or target/release locations. Tool discovery is not a successful build,
signature comparison, desktop run or Windows release qualification. ARM64 hardware is not
established by this inventory.

The existing Windows native comparison script checks embedded signatures and CAB extraction.
Its catalog branch handles the difference from Windows' result, but does not verify the catalog
itself. CI's desktop job currently runs on macOS, and the Tauri bundle targets are app and dmg.
These are concrete starting points for Windows work, rather than reasons to rebuild the analyzers.

## Research findings that determine the design

**File reads can have Windows-specific effects.** Reparse points can redirect access, including
through file-system filters. Named NTFS streams are separate sequences of bytes, and Windows
path namespaces have aliases and reserved names. Our design inference is that the file boundary
must be explicit before accepting more complex inputs. See Microsoft's
[reparse-point documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points),
[file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams), and
[path naming rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).

**Offline includes file access.** Microsoft's file attributes distinguish encrypted files and
files whose content can be recalled from remote storage when opened or read. A local-looking
path therefore needs more attention than the absence of HTTP calls. The proposed default is
to skip unresolved reparse points, remote inputs and content requiring recall, with a limitation;
do not hydrate cloud placeholders or trigger transparent EFS decryption. See
[file attribute constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants).

**An embedded signature and a package signature answer different questions.** A driver package
combines INF declarations, a catalog and its payloads. Microsoft documents catalog hashes as
the link between those files. A PE with no embedded signature can still be covered by a catalog.
Our extension should distinguish these observations instead of importing the machine's trust
decision. See [driver-package components](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/components-of-a-driver-package).

**MSIX manifest support is only one part of MSIX support.** Microsoft describes integrity through
AppxBlockMap.xml and AppxSignature.p7x, and notes that a signed bundle can cover its internal
packages without each being signed separately. This calls for a tree-level package model, with
separate checks for content hashes, signature integrity and coverage. See
[MSIX signing](https://learn.microsoft.com/en-us/windows/msix/package/signing-package-overview).

**Windows entry points have structured evidence.** LNK has a published binary format, and Task
Scheduler has an XML schema. These are suitable first additions because a report can cite the
target, arguments, trigger and declared principal directly. They do not require opening a shortcut
through Explorer or registering a task. See [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943)
and the [Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema).

**Script intent needs a language boundary.** PowerShell has expression and argument parsing
modes. A command-looking string alone is insufficient evidence that the command executes.
Start with bounded syntax and literal declarations; dynamic expressions remain unknown. Do not
invoke PowerShell or import modules to inspect an input. See
[PowerShell parsing](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_parsing).

**Modern executables can contain another application.** .NET single-file publishing includes
runtime configuration and dependencies in a bundle, whose marker locates its metadata. PyInstaller
also documents archive members inside an executable. Extracting those supported structures into
the artifact tree allows the existing analyzers to do more work. See
[.NET deployment](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview),
[the .NET bundler design](https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md),
and [PyInstaller archive documentation](https://pyinstaller.org/en/stable/advanced-topics.html).

**Package manifests can improve the existing component inventory.** NuGet's nuspec describes
identity and dependencies; WinGet manifests describe installers. Read the supplied files and
relate them to supplied payloads, without resolving or downloading anything. NuGet author and
repository signatures are a separate later integrity feature. See
[nuspec](https://learn.microsoft.com/en-us/nuget/reference/nuspec),
[WinGet manifests](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest), and
[NuGet signed packages](https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference).

## Feature priorities

The priorities below are product judgments based on reuse, evidence quality and the cost of
validating hostile-input readers. They are not measured demand or delivery commitments.
Size is relative: S is a narrow reader or integration, M spans several modules, L includes
a substantial parser or protocol change, and XL needs a separate feasibility project.
Real-sample acquisition and review can change the size.

| ID | Priority | Feature | Size | Prerequisite |
|---|---|---|---|---|
| W0 | P0 | Real samples and parser accuracy verification | M | Existing code |
| W1 | P0 | Local file boundary and Windows path handling | M–L | W0 |
| W2 | P0 | Worker termination and precise timeout semantics | L | W0; design spike |
| W3 | P1 | LNK, URL, REG and exported scheduled tasks | M | W1 |
| W4 | P1 | Bounded PowerShell and batch analysis | L | W3; parsing spike |
| W5 | P1 | Catalogs and INF driver-package relationships | L | W0, W1 |
| W6 | P1 | MSIX integrity and package relationships | L | W0, W1 |
| W7 | P1 | NuGet, VSIX and WinGet semantics in the component inventory | M–L | Existing components; W3/W4 for scripts |
| W8 | P2 | .NET single-file and PyInstaller contents | L each | W1, W2 |
| W9 | P2 | Installation conditions, sibling payloads and Burn | L | W1, W2, W4 |
| W10 | P1 | Windows desktop delivery and native usability | M–L | W0, W1, W2; existing D6 work |
| W11 | P2 | Office containers, VBA and embedded objects | L–XL | Bounded shared compound-file reader |
| W12 | P3 | ISO, WIM and virtual disks in separate increments | XL | W1, W2; per-format feasibility |

P0 establishes the Windows foundation. P1 is the first feature wave; it can ship in several
releases. P2 follows demonstrated sample demand. P3 is exploratory and does not block a
Windows release. W5 and W6 can be developed independently after the foundation.

### W0 Real samples and parser accuracy

This is development verification: the analyzer and reference tools read the same sample,
and their shared observations are checked for agreement. It establishes the accuracy of
the explanation of one supplied artifact.

Build the CLI without AI, run the repository checks on this host, and record exact tool versions
and sample digests in a development result file. Extend the comparison harness to discover SDK
tools without assuming PATH, accept explicit sample paths, and separate embedded, catalog and MSI
cases. Keep machine information in the test record, outside the product report.

Use SignTool for explicit signature and catalog comparisons, Get-AuthenticodeSignature for the
Windows view, and makecab for reproducible CAB samples. Native tools may apply trust, revocation
and time policies that differ from this analyzer; compare the shared cryptographic claims and
record policy differences separately. See [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
and [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck). Sigcheck is an
optional development reference, with its online lookup features excluded from the harness.

Exit: recorded x64 CLI results on real installers and application folders; embedded and MSI
signature cases compared; explicit pending cases for catalogs and unsupported versions; no
unchecked claim of Windows ARM64 or desktop readiness.

### W1 File access and extraction boundaries

Test Chinese names, spaces, long paths, case-only differences, hard links, junctions, symbolic
links, permission failures, file sharing locks, sparse files and changes during a read. Exercise
both direct inputs and archive entries. Check the root input as well as descendants; prefix
string comparison is not a sufficient containment check.

Keep archive member names as logical identifiers. Store extracted bytes under generated internal
names so that CON, trailing dots, colons, drive prefixes, duplicate names and case collisions
cannot become host paths or silently overwrite one another. Preserve distinct logical names
and report ambiguity. Use the existing sink and budgets rather than format-specific extraction
directories.

Reject device namespaces and remote sources before content access. Inspect available file
attributes and reparse information without following the target. Skip cases that cannot be
opened locally without recall or decryption, and report why. Use safe standard-library APIs or
a reviewed dependency exposing a safe interface; the repository's unsafe prohibition stays.
Resolve the safe-API feasibility during this milestone rather than promising unsupported cases.

Named streams need an explicit input contract. In the first wave, document the unnamed-stream
scope and report when additional stream coverage could not be established. A later opt-in
capture can freeze named stream bytes and relative associations into a canonical portable
input. It must define sorting, budgets, naming and digests before implementation. Do not let the
normal report silently depend on ambient ADS, ACLs, the registry, the current user's profile,
the local certificate store or the current machine's DLL search path. A captured Zone.Identifier
is origin metadata, not a statement about safety.

Exit: bounded local reads, deterministic treatment of hostile names and collisions, limitations
for inaccessible or skipped content, and tests proving no out-of-root reads or cloud recall in
the tested cases. Unresolved races must remain documented; a preliminary attribute check alone
does not prove a race-free boundary.

### W2 Process isolation and timeout semantics

The CLI currently calls the engine directly. The engine abandons timed-out analyzer threads;
the desktop worker can be killed on cancellation. Merely reusing that worker does not make an
individual analyzer killable at its deadline. The current worker protocol returns the report
at completion, so killing it early also does not automatically preserve a partial report.

Run a design spike with two contracts: a supervised worker for the whole run, and isolated work
units that can be terminated individually. First deliver reliable whole-run cancellation and
cleanup through the first-party worker. Keep per-analyzer timeout wording accurate. If preserving
completed results after a hard timeout is required, define bounded checkpoints or supervisor-owned
results before claiming it works. Do not synthesize a successful report from progress messages.

Account for CLI deep options, no-AI builds, progress, exit codes and packaging; the current desktop
Analyze request only supplies paths and limit overrides. Avoid widening the normal analyzer
contract to launch foreign tools. A Windows process-tree mechanism, if needed for the optional
deep level, requires a safe API and a demonstrated test; it is not an isolation guarantee by itself.

Exit: a deliberately hung test analyzer and unpacker cannot keep the supervisor alive indefinitely;
cancellation ends the intended processes, console windows do not flash in the desktop flow,
temporary files are recoverable, and the presence or absence of a valid partial report is explicit.

### W3 Shortcuts and configuration entry points

Add bounded readers for LNK, Internet Shortcut URL files, REG exports and exported Task Scheduler
XML. Report LNK target text, arguments, working directory, icon references and requested flags;
REG keys, value types and declared writes/deletions; task triggers, actions, run level and declared
principal. Preserve environment-variable references as text instead of substituting host values.

Relate a target to another artifact only when it is supplied inside the input and the resolution
is unambiguous. Never resolve a shortcut through COM or Explorer, fetch a URL, import REG data or
register a task. Reuse installer classification for autostart, services and protocol handlers
where its semantics match; distinguish a declaration from an observed installation.

Exit: known fields match the source format, evidence names a field or byte range, malformed and
oversized structures produce limitations, and external/ambiguous targets remain unresolved.
Reference LNK fields against a trusted test fixture's native property reader without resolving
or launching it; compare REG and task data against documented formats and exported fixtures.

### W4 Scripts with bounded static interpretation

Start with ps1/psm1 and cmd/bat. Recognize syntax, literal commands, literal URLs and paths,
administrator requests and declarations related to downloads, startup, services, tasks and
security configuration. A first parsing spike must select an in-process Rust implementation
or a clearly limited syntax subset, with acceptable licensing and resource behavior.

Treat cmd and PowerShell quoting separately. Never evaluate substitutions, resolve commands
against the host, import a psd1, run MSBuild targets, or execute an embedded script. Literal
Base64 command text may be decoded under a byte budget, with source-to-decoded provenance;
decoding a representation is not permission to evaluate it. Dynamic expressions and unsupported
syntax get explicit coverage limits. Extend to VBS, JScript, WSF and HTA only in later increments.

Use separate fixed-severity rules for separate observations. A string match can be heuristic;
a parsed literal command is a verified syntactic declaration, not proof that a branch runs or
that an action succeeds. Redact likely credentials in derived findings and facts as today.

Exit: each supported syntax family has positive, negative and unsupported cases; quoted text
and comments are not presented as executed commands; decoding is bounded; all results work
without PowerShell installed. Native AST comparisons, where used in development, are limited
to trusted fixtures and do not become part of analysis.

### W5 Catalogs and driver packages

Implement INF structure and decorated sections first, then catalog content and signature
verification, then tree-level relationships among INF, CAT, SYS and supporting files. Surface
provider, declared driver version, device IDs, target architectures, file references, service
startup and registry declarations, each with source evidence.

Derive membership using the appropriate subject hashing rules, not an assumed ordinary SHA-256
of every file. Distinguish catalog signature integrity, member digest agreement, missing supplied
members and an absent catalog. Leave Windows trust, revocation, WHQL acceptance and installation
eligibility outside the conclusion. Include/Needs references outside the supplied package remain
unresolved; do not consult the installed Driver Store.

Exit: catalog-only, embedded-only, dual-covered, modified-member and missing-member cases compared
with explicit-catalog SignTool checks on a controlled Windows environment. Invalid or unsupported
catalog formats produce a limitation instead of an unsigned verdict.

### W6 MSIX package integrity

Add an explicit package and bundle model over the existing ZIP tree. Read the block map and
verify supported hashes, then parse and verify the package signature's binding to the package
structures. Report these as separate checks; an internally consistent block map alone does not
authenticate a package. Handle duplicate member names, conflicting identities and malformed XML.

Read bundle architecture/resource packages, declared dependencies, target-device requirements
and appinstaller references. Explain the capabilities already read from the manifest in that
context. Never fetch a dependency or update URL. Respect bundle-level signature coverage so
unsigned internal packages are not automatically presented as missing required signatures.

Exit: file tampering, block-map tampering, signature tampering, unsigned test packages and signed
bundles have distinct results; real redistributable packages are compared with SDK inspection
and signature tools. A package being installable on this machine is not a report finding.

### W7 Package identity and dependency relationships

Read nupkg/nuspec identity, license declarations, framework-specific dependency ranges, runtime
assets, and build/targets or scripts shipped with a package. Add VSIX manifests and WinGet YAML
identity, architecture, installer type, hash and switches. Existing ZIP extraction is reused;
each format needs its own semantic reader, not a replacement ZIP unpacker.

Extend composition.components instead of creating another component list. Preserve package
versions, assembly versions and dependency ranges as different values. Add dependency edges
and declared-versus-present links only where the input supplies evidence. A filename or an
assembly name alone must not become a verified package URL. Package signatures, Chocolatey
script semantics and offline vulnerability matching are separate follow-ups.

Exit: manifests and nested binaries feed the shared inventory without duplicate guessed packages;
unresolved dependency ranges stay unresolved; CycloneDX export preserves the supported identities
and relationships; no package restore, installation or network access occurs.

### W8 Applications inside executables

Make .NET single-file bundles a dedicated unpacker with explicit supported bundle versions,
checked offsets and decompression budgets. Emit managed assemblies and configuration files as
children so the existing metadata and component readers see them. Compare signed/post-processed
hosts as well as ordinary bundles. ReadyToRun and Native AOT need separate recognition and
coverage statements; Native AOT does not imply recoverable IL. See Microsoft's
[Native AOT overview](https://learn.microsoft.com/en-us/dotnet/core/deploying/native-aot/).

For PyInstaller, progress from the existing marker heuristic to a validated CArchive table and
supported entries. Handle supported PYZ metadata with a bounded parser; never use Python import,
pickle or marshal loading of an input. Encrypted or unsupported contents remain unread. Compare
against a pinned archive viewer on trusted fixtures during development, and verify emitted bytes
against the producer's source payloads. Do not copy a dependency with an incompatible license.

Exit: the contents, offsets and digests agree on producer-built and real redistributable examples;
missing or unsupported entries are visible. Implement .NET and PyInstaller in separate patches
and releases if necessary; neither waits for pseudocode decompilation.

### W9 Installation declarations and payload relationships

MSI CustomAction and launch-condition data are already read. Extend them with execution-sequence
and condition context so a declared custom action is not described as unconditional behavior.
Relate supported Binary-table code to child artifacts and script findings. Use read-only table
inspection as a reference; [Orca](https://learn.microsoft.com/en-us/windows/win32/msi/orca-exe)
is a development tool, not a runtime dependency or a reason to install the input.

Resolve external CABs or loose payloads only inside an explicitly supplied package root.
A standalone MSI does not authorize arbitrary sibling-directory searches. Add Burn manifest
and attached-container support in a separate spike; downloaded payloads remain references.
The producer documents [Burn inspection tools](https://docs.firegiant.com/wix/tools/wixexe/)
that can serve as development references without running the bundle itself.

Recognize MSP/MST early with limitations, then scope their semantics separately: applying
a transform or patch virtually requires a supplied base and a precise model. Squirrel and
Velopack update packages are later candidates after representative samples are available.

Exit: a report distinguishes supplied payloads, external references, declared conditions and
unread custom-action logic. No msiexec administrative extraction, setup /extract mode or installer
launch is used by analysis.

### W10 Windows desktop delivery

Implement the Windows part of D6 with the same analysis engine and report. Start with a portable
x64 build and one installer; choose NSIS first, with MSI later if deployment requirements justify
maintaining both. Validate WebView2 presence and an explicit offline installation option. Tauri's
default installer can download a WebView2 bootstrapper, while it also offers offline choices;
choose and document the policy before release. See
[Tauri 2 Windows installers](https://v2.tauri.app/distribute/windows-installer/).

Test Unicode paths, long paths, drag and drop, native open/save dialogs, scaling, keyboard use,
report URI handling, worker startup/cancellation and locked-file cleanup. Add Windows desktop CI
and real-window self-checks. Explorer integration should be a later optional installer component,
not a prerequisite for analysis. Sign distribution artifacts when credentials are available;
keep signing credentials outside the repository. CLI release qualification can finish first.

Exit: installed and portable Windows flows pass the documented checks, CLI and desktop exports
match byte for byte for the same input and options, and missing-WebView2 behavior is tested.
Windows ARM64, Linux desktop and automatic updates keep their separate release gates.

### W11 Office and embedded content

Build on ZIP and a bounded compound-file abstraction for OOXML and OLE containers. Begin with
content types, relationships, embedded files, external targets and macro presence. Then add
supported MS-OVBA compressed source streams and evidence for auto-entry declarations. OLE and
VBA have published structures; see [MS-CFB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-CFB/53989ce4-7b05-4f8d-829b-d08d6148375b)
and [MS-OVBA relationships](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/8d60e379-761d-4e44-a51f-1ea81e6d276e).

The existing compound reader is private and tailored to MSI hashing. Preserve its raw-directory
semantics and MSI signature regressions if a shared reader is extracted. Distinguish source
streams from compiled macro behavior; do not claim macro absence from unread streams. Handle
XLM, XLSB, RTF objects, compiled/source discrepancies and PDF active content in separate increments.
Encrypted documents are identified and limited, never decrypted. Office automation is unnecessary.

Exit: emitted embedded artifacts and supported macro source match licensed samples; encrypted,
malformed and unsupported content has explicit limits. This work should benefit all three hosts.

### W12 Disk and system image expansion

Start with ISO 9660/Joliet structure and contents, then consider UDF as its own supported
filesystem. [ECMA-119](https://ecma-international.org/publications-and-standards/standards/ecma-119/)
is the primary starting specification. Recognition of an ISO does not imply UDF support.

WIM begins with image indexes and metadata, then selected compression and resource layouts
under streaming budgets. Split WIM and ESD variants require explicit gates. DISM can provide
development reference information; it does not become an analysis subprocess. See
[DISM image management](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14?view=windows-11).

VHD/VHDX needs a block-image reader followed by partition and filesystem readers. Implement
fixed/dynamic disks before differencing chains; never follow a stored parent locator into the
host. Parent images must be explicitly supplied. Microsoft's [VHDX overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83f6b700-6216-40f0-aa99-9fcb421206e2)
explains that differencing images depend on parent disks, which is why a single-file promise
would be misleading. FAT, NTFS and ext4 are separate scopes. No image mounting, driver attachment,
write repair or decryption belongs in the analyzer.

Exit for each increment: documented supported variants, bounded reads and decompression, a
redistributable real sample, byte-level reference comparison, and explicit partial coverage for
everything else. Do not promise the entire ISO → WIM → filesystem → program chain in one release.

## Shared architecture and report behavior

Keep container extraction in Unpacker and semantic reading in Analyzer. Native Windows readers
extend aa-windows and aa-binary. Independently useful script, package, document and image readers
may become separate crates when that prevents platform-family coupling. Register new facts before
the correlation pass that consumes them. There is no need for a general plugin rewrite first.

Reuse the existing evidence, installer model and component inventory. Add typed relationships
incrementally, for example shortcut → supplied script, INF → catalog → supplied driver,
MSIX manifest → supplied executable, and package → declared dependency. Store the observation,
source artifact, field or range, resolution state and confidence. A candidate library found in
the input is not proof of Windows loader selection; API-set, side-by-side, runtime and search-path
resolution that cannot be established remain unknown.

Begin with facts and findings that existing exports can render. Introduce an explicit graph
schema only when several readers need it; specify compatibility and deterministic ordering then.
If the serialized report shape breaks, version it according to aa-core. Extend CycloneDX
relationships deliberately rather than assuming the current component-only exporter has them.

Extracted and decoded content gets its own stable artifact identity, parent, digest and logical
byte locations. A byte range in a decompressed child is not a contiguous range in the original
container; report and hex navigation must preserve that distinction. Schema changes for richer
provenance need fixtures and backward-reading rules.

Show a concise account of declared entry points, payloads, components, signature coverage and
limitations in the existing chapters. Large inventories remain inspectable facts with bounded
examples in prose. Keep rule IDs stable, severities fixed per rule, and every new title and
sentence available in English and Chinese. Do not add an overall risk score.

## Sample and verification strategy

Use two corpora. Small generated fixtures and redistributable real samples live in the repository
with producer versions, source and license in NOTICE. Larger installers, installed folders and
system files stay outside it; a development manifest records hashes, versions and expected facts.
An open-source application can bundle separately licensed assets, so its project license alone
does not establish permission to redistribute its whole installer.

| Family | Proposed sample coverage | Reference or independent check |
|---|---|---|
| PE and signatures | x86/x64 plus ARM64/ARM64EC files; embedded, catalog-only, dual and damaged signatures | SignTool, Windows signature view, SDK or LLVM structure reader when available |
| MSI/CAB/installers | Existing fixtures, signed real MSI, external CAB, conditional actions, current and older supported NSIS/Inno variants | Read-only MSI tables, SignTool, makecab and known source payloads |
| Shortcuts/configuration | LNK with arguments and environment references, URL, REG typed values, task XML, non-ASCII text | Format specifications, trusted native fixture properties, exported source values |
| Scripts | Literals, comments, quoting, dynamic constructs, malformed and oversized input | Trusted fixture AST comparison where suitable, expected syntax and evidence spans |
| Driver packages | INF decoration, catalog-only package, missing and altered members | Explicit catalog verification and source declarations; no driver loading |
| MSIX | Signed/unsigned test packages, bundle coverage, resource packages, damaged blocks | SDK tools and producer payload hashes; no package installation |
| Modern bundles | .NET bundle versions and compression, ReadyToRun, Native AOT; PyInstaller variants | Producer source payloads, pinned metadata/archive readers |
| Documents/images | Supported macros and embedded objects; selected ISO/WIM/VHDX variants | Known source trees and independent read-only references for each promised variant |

These rows specify targets, not completed runs. Choose real package names and versions during W0
and each format spike, after checking availability and redistribution rights.

For every parser, include malformed lengths and offsets, deep nesting, duplicate names,
decompression expansion and unsupported versions. Exercise limits and cancellation where the
parser can consume substantial resources. Extend the whole-analysis fuzz target with useful
seed families; never replace a missing sample with a broader claim.

Verify reproducibility on repeated complete runs, CLI/desktop parity, and equivalent supplied
trees on Linux/macOS/Windows. Compare paths containing spaces and Chinese characters. Host I/O
errors and hard resource termination may differ; canonicalize error categories and keep
environmental diagnostics outside portable report content. If a portable capture is introduced,
its bytes and options define the comparison input. Do not describe time-limited partial runs as
guaranteed identical across machines.

Keep native reference commands out of report generation. Run references on controlled copies,
with read-only inspection modes and network constrained when measuring offline behavior. Never
launch an installer or analyzed program, register its components, load a driver or open its
documents in an application. No VirusTotal upload or lookup is needed.

## Delivery sequence and acceptance gates

| Milestone | Deliverables | Gate to move on |
|---|---|---|
| M0 Windows evidence | W0, input-name diff regression, inventories for W1 and W2 | Actual host baseline recorded; failures and missing tool/sample requirements named |
| M1 Bounded foundation and entry points | W1, W2 spike and whole-worker supervision, W3 | Tested file boundary; real cancellation; honest timeout contract; usable new entry-point reports |
| M2 Package integrity | W5 and W6, independently releasable | Catalog/driver and MSIX tampering cases compared, including unsupported cases |
| M3 Application relationships | W4, W7; selected W8 and W9 after their spikes | Supported syntax and bundle versions explicit; shared inventory and relations validated |
| M4 Windows product delivery | W10; can ship after M1 without waiting for all M2/M3 | Windows native interactions and CLI/desktop parity checked; installation policy documented |
| M5 Broader Anything inputs | W11, then selected W12 increments | Each format independently meets real-sample, evidence and resource-limit gates |

Do not tie these milestones to version numbers before M0/M1 establish the cost. The first
bounded release can consist of a validated Windows CLI and W3. Catalogs, MSIX integrity and the
desktop are separate useful releases. Add effort estimates in developer-days after the worker,
PowerShell and catalog/MSIX format spikes; calendar dates before those would be speculative.

The first implementation patches should be:

1. Native-tool discovery and an explicit Windows comparison manifest; run and record the baseline.
2. The existing input-name diff fix with regression cases that preserve meaningful changes.
3. Windows path/read-boundary cases and the resulting bounded behavior.
4. Worker supervision with a documented distinction between run termination and per-task timeout.
5. LNK/URL readers, followed by REG and task XML, each with real-sample provenance.

Use the repository's required format, lint, workspace tests and no-AI build checks for code
changes. Changes to reports or desktop behavior also need their existing fixture, browser and
native self-check layers. Keep the current Mac CMS and device-support DMG problems visible in
TODO; Windows expansion does not resolve or replace them.

## Follow-on directions and limits of this plan

After the first Windows wave, return to the roadmap's cross-platform gaps: deb/rpm/AppImage,
OCI image layers, wheels/npm/JAR packages and browser extensions. Reuse the same container,
component and relationship mechanisms rather than building a Windows-only second engine.
Offline vulnerability matching and user policies should follow trustworthy package identity and
an explicit, versioned local database. A generic PE version string is insufficient identity.

Offline registry hives, EVTX, crash dumps and memory images are candidates for a later artifact
or forensics track. They need their own product questions, evidence model, sample rights and
resource budgets; reading exported REG or task files does not imply those capabilities. Live
host inventory, persistence monitoring, reputation lookups, sandbox execution, automatic
remediation and whole-machine scanning are outside this feature wave.

The unresolved feasibility decisions are specific: safe local-file APIs without weakening the
unsafe rule; the isolation granularity and partial-report contract; supported script syntax;
catalog member hashing and MSIX signature variants; redistributable real samples; Windows
desktop signing and WebView2 distribution; and ARM hardware validation. Each belongs to its
named milestone and has a smaller deliverable if the full scope cannot yet be verified.
