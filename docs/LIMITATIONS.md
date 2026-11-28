# Known limitations

This lists what the tool itself cannot do or has not been verified to do. Specific problems met during a single analysis are written in the "Coverage and limitations" chapter of that report.

## Not done by design

- It does not execute, install or dynamically debug the object being analyzed.
- It starts no other program, with one exception that is off unless asked for: `--deep` hands program files to Ghidra or Hopper to be disassembled (see [DEEP.md](DEEP.md)). What that level was tried on, and what it misses, is said there.
- It does not decompile to pseudocode.
- It does not decrypt, unpack protected code, or bypass any protection. The main executable of an IPA downloaded from the App Store is encrypted with FairPlay, and its code segment cannot be read; the real code of a packed APK is not visible. These cases are identified and written into the report.
- Analysis does not use the network. It therefore does not check certificate revocation, whether a root certificate is trusted, or Apple notarization status. The only thing that uses the network is the optional AI interpretation, which does nothing until you set it up (see [AI.md](AI.md)).
- The AI interpretation checks only that the findings each statement cites exist in the report. It does not check that the model understood them, or that it drew no conclusion of its own from several of them. Each of its engines has produced a full answer for real at least once; [AI.md](AI.md) says exactly what was tried and with which model.
- It gives no "safe / unsafe" verdict and no single score; it only lists findings and their severity.

## Published preview and report workflow

[v0.2.0-preview.2](https://github.com/atomsprout/analyze-anything/releases/tag/v0.2.0-preview.2)
is a published unsigned prerelease, not the signed stable/Homebrew release. It has four
CLI archives (Windows x64, Linux x64/ARM64, macOS ARM64) and Windows x64 portable/offline
NSIS desktop packages. Release run 45436464060 passed all seven jobs; CI on its source
and the merged main also passed. All 11 public attachment digests were verified. The
published Windows CLI archive hash is
`0fce07982a62e9fc49d7a8d3a181e2e3fe72d2686e2026a551f6ef7ab1b099ce`.
Its OS-only imports were checked independently; no separate Visual C++ runtime is needed.
Linux archive runtime checks used Ubuntu 24.04 and Debian trixie containers with no network
and read-only roots. This does not qualify older glibc baselines or physical Linux windows.
The earlier disconnected Windows 10 desktop qualification used a preceding candidate;
the published NSIS package was not reinstalled in that guest.

The [five-scenario workflow review](spikes/report-workflow.md) records the exact inputs,
reading answers and packaged CLI checks. Source corrections after preview.2 distinguish
installation declarations from execution and explicitly report unsupported installer
execution semantics and unread .NET IL method bodies. These corrections do not add MSI
condition evaluation, managed call-flow analysis or new runtime/OS qualification.

## MSI action-context profile

The 0.2.2 increment preserves five sequence tables, literal conditions, CustomAction
scheduling flags and supported Binary-source links. Windows Installer read-only references
passed for a constructed inert package, 7-Zip 24.08 and OpenJDK 25.0.3+9; exact sample hashes,
observations, native records and limits are in [W9](PLAN-WINDOWS.md#w9-installation-declarations-and-payload-relationships).
No condition is evaluated. UI-event invocation, property substitution, effective privileges,
installed-file action targets and action-code behavior are unresolved. A captured Binary
stream is not proof that an action executes it. An action absent from the read sequence
tables is not proof that it never executes. Table/field/index limits and unsupported schemas
are reported explicitly; no host files are searched for targets. Python/.NET code-depth and
portable raw-evidence retention remain later roadmap work.

## Linux breadth A profiles

The 0.2.3 candidate implements the first breadth increment, with Arch Linux packages
and general ar archives. Its build/release qualification is in progress and it is not
published; the native records below qualify only their named source and inputs. The
machine-readable [format catalogue](FORMATS.md) distinguishes primary families,
compression and declaration readers; its counts describe implemented profiles, not
complete qualification of every version, compression method or platform.

- Arch: bounded root `.PKGINFO`/`.BUILDINFO`, literal dependencies and `.INSTALL`
  text, `.MTREE` identity/digest only, and TAR entry/link declarations. Duplicate or
  noncanonical controls, truncated archives, unsupported text and exhausted budgets
  remain explicit. No package authentication, MTREE verification or dependency resolution.
  The pinned real libutf8proc 2.12.0-1 fixture uses zstd; see [source and licence](../crates/aa-linux/tests/data/ARCH.md).
- ar: normal GNU/BSD member names and GNU 32/64-bit symbol-index declarations.
  BSD/COFF index semantics remain unread. Thin archives retain references and never
  open external files. Pinned LLVM-generated GNU/BSD/thin archives and a real BSD-2-Clause
  xxHash library have independent ar/nm references; [scope and source](../crates/aa-linux/tests/data/AR.md).
- Linux declarations: selected systemd unit, Desktop Entry and upstream AppStream
  metadata. Repeats, resets and source positions are retained; substitutions, unknown
  schema semantics, host state and command execution remain unresolved. Pinned upstream
  Syncthing and Flameshot files have [source/licence records](../crates/aa-linux/tests/data/declarations/README.md).
- Supplied ELF relationships compare literal unmodified dependency names with filename
  or SONAME in a complete captured namespace and the same recorded machine, class and
  byte order. ABI compatibility, symbol versions, RPATH/RUNPATH search, symlink/loader
  selection and host libraries remain unresolved. Truncated/sanitized names, ambiguous
  candidates and incomplete listings cannot produce confirmed targets.

Windows read-only CLI comparisons passed 22 ar checks over three archives and 68
declaration checks over four upstream files. Linux native-comparison run
[46104680253](https://github.com/atomsprout/analyze-anything/actions/runs/46104680253)
at 9731df0 passed 22 ar, 56 Arch and 68 declaration checks, plus the existing 125
Debian/RPM checks. Native declaration validators retain their actual diagnostics;
unsupported templates or absent host executables are not represented as validation
success. No local Linux VM was qualified. Later source changes still require their
own final CI and package checks.

## Linux breadth B image profiles

The 0.2.4 source increment implements three additional primary families: SquashFS,
AppImage Type 2 and snap. With A, C and D now merged, the 0.2.6 source catalogue has
35 primary + five compression families (40 total); 11 declaration families are counted
separately. Implementation does not establish publication, complete format coverage or
new OS/runtime qualification.

- SquashFS: little-endian v4.0 metadata and file bytes with gzip/XZ compression,
  common/extended file and directory inodes, ID/fragment tables and sparse blocks.
  Blocks are bounded to 8 KiB metadata / 1 MiB data; shared decoded metadata and
  fragment caches are each capped at 16 MiB, individual files at 256 MiB, total
  data decoding at 512 MiB and XZ decoder memory at 32 MiB. Symlinks and special
  files remain declarations; xattr/ACL effects, export lookup, mounting and runtime
  behavior remain unresolved. Other versions, compressors and unsupported names
  have explicit gaps. [Fixture, limits and native record](../crates/aa-linux/tests/data/SQUASHFS.md).
- AppImage: the initial Type 2 profile proves its filesystem offset from ordinary
  ELF section/program extents, captures only the checked SquashFS `bytes_used`,
  and records root Desktop Entry identity and literal AppRun-to-supplied-file
  evidence. Type 1, absent/extended section counts and unsupported layouts remain
  unread. Absolute/escaping links, multiple hops, renamed or ambiguous entries and
  incomplete namespaces cannot establish a target. No AppImage runtime or extract
  option is invoked. Desktop Entry `Version` describes its declaration format;
  application release version remains unresolved. [Scope and external reference](../crates/aa-linux/tests/data/APPIMAGE-SNAP.md).
- snap: one original direct `meta/snap.yaml` in a complete captured SquashFS
  namespace supplies name/version and literal application/interface/daemon/environment/
  hook declarations. YAML is bounded to 256 KiB per file, 16 MiB aggregate, 12000
  events and depth 24. Duplicate keys, aliases/anchors/tags, merge keys and multiple
  documents are explicit gaps. Supplied commands and observed hook files have source
  evidence, without host lookup, symlink following, command evaluation, confinement
  enforcement or signature/store-assertion verification. [Scope and sample](../crates/aa-linux/tests/data/APPIMAGE-SNAP.md#snap-metadata).

The unchanged MIT-declared Canonical hello-world 6.4 revision 29 fixture is a real XZ
SquashFS input. Its hash-bound 7-Zip 25.00 reference covers all nine paths/types/modes/
owners and all six regular-file sizes and SHA-256 values; snap tests also exercise
its four application targets. The external AppImageKit 12 `appimagetool` sample is
ELF64 little endian with gzip SquashFS; its Windows 7-Zip record contains 135 checks.
The AppImage binary is not redistributed. Other ELF classes/byte orders and broader
fragment/inode combinations retain constructed-test or pending native qualification.
Linux `unsquashfs` 4.6.1 passed 84 checks (22 snap and 62 AppImage) at `a600591` in
[the native workflow](https://github.com/atomsprout/analyze-anything/actions/runs/46109240238).
The [hash-bound reference](../crates/aa-linux/tests/data/linux-images-native.ref.json)
records header values, complete paths, link targets and every regular-file size/hash,
plus selected snap declarations. The AppImage's three fragment blocks are exercised
by its captured file bytes; this does not qualify all fragment/inode combinations.
Reports include image identity components with their captured metadata path/hash and
an index of supplied AppRun/command/hook relationships. Image component records share
a 4 MiB budget; omitted records mark the inventory truncated. The real snap and a
constructed Type 2 AppImage have deterministic engine/report integration checks.
Final integrated-head CI and packaged 0.2.4 qualification still require their own
results before publication; earlier checks do not qualify later source or packages.

## Language package breadth C profiles

The C source at 929703f registers three semantic readers over already captured ZIP,
TAR and compressed-stream children. This is implemented scope for the pending 0.2.5
delivery, not a published release or qualification of every package variant. The Java
archive family is counted once, with JAR qualified; WAR/EAR application profiles remain
explicitly unread. See [the reader profile](../crates/aa-packages/README.md).

- Wheel: one root `.dist-info` directory, numeric WHEEL 1.x/Core Metadata 2.x,
  literal identity, compatibility tags, repeated `Requires-Dist` and entry-point metadata.
  Ranges, extras and environment markers are not evaluated. RECORD and signatures are
  not verified; installation eligibility, description-body semantics, Python source,
  bytecode and `.pth` effects are not established. Ambiguous scalar fields and indented
  entry-point continuations remain explicit gaps.
- npm: one original regular `package/package.json`, bound to the exact original TAR
  bytes; identity, four dependency groups, script text, selected module/platform fields,
  TAR paths/link declarations and captured inventory. The initial profile accepts normal
  octal-sized common/USTAR TAR within 256 MiB. PAX/GNU-long-name/sparse extensions and
  concatenated archives remain unsupported. Links and special files are declarations;
  targets are not followed. Registry authenticity, dependency/module/exports resolution,
  platform eligibility and lifecycle effects are unresolved. Retained text redacts
  recognizable credentials.
- JAR: canonical UTF-8 `META-INF/MANIFEST.MF` 1.0 with folded attribute source spans,
  main/entry attributes, literal launch/module/agent/class-path declarations and simple
  Maven `pom.properties` identities with source-path agreement. The manifest profile is
  bounded to 1 MiB, 72-byte physical lines, 65,535-byte unfolded values, 8,192 attributes
  and 256 sections. Class-path previews stop at 1,024 declarations; URLs are never opened.
  Maven properties are literal UTF-8 `key=value`, at most 64 KiB/256 fields per file and
  256 files; Java escapes, continuations and legacy encodings are unsupported. Bytecode,
  module dependencies, OSGi/service-provider behavior, effective sealing, versioned-class
  selection, signatures and runtime privileges are not established.

All three require a complete captured namespace with original unique member names.
Normalized/colliding names and incomplete listings prevent confirmed identity. Shared
bounds are 256 package candidates, 100,000 members, 4,096-byte member paths and 16 MiB
of aggregate member paths; inventory previews retain 5,000 rows with a total and explicit
truncation. Wheel/npm metadata is UTF-8 within 1 MiB. Wheel lines/unfolded fields and
npm JSON strings are bounded to 16 KiB; wheel headers/entry-point rows and npm JSON
values are bounded to 8,192. npm JSON additionally rejects duplicate keys at every object
depth and nesting beyond 32. Malformed metadata, unsupported profiles and exceeded budgets
have constructed coverage and explicit limitations. No package, class, entry point or
script is imported, loaded or executed; no host or package registry is consulted.

The unchanged MIT-licensed samples are sampleproject 4.0.0, isarray 2.0.5 and SLF4J API
2.0.16. [Sources, licences and hashes](../crates/aa-packages/tests/data/SOURCES.md) and
`NOTICE` bind those inputs. The checked-in Windows
[CLI reference record](../crates/aa-packages/tests/data/native-cli.ref.json) contains
15 matching checks: seven wheel, six npm and two JAR, including every regular member's
name/size/SHA-256 (9, 4 and 60 members respectively). The
[comparison helper](../tools/native-compare/language-packages.py) uses independent Python
metadata readers and JDK `jar`/Windows `tar` listings. A separate
[OpenJDK 25.0.3+9 JarFile reference](../crates/aa-packages/tests/data/java/README.md) supplies
all 20 main-manifest attributes and 60 member digests, compared in the hash-bound Rust
fixture test without loading input classes. Captured component identities use actual
METADATA/package.json sources, or Maven properties whose identity agrees with their path.
PyPI names and package URLs are normalized by ecosystem rules; JAR display titles never
become inferred Maven coordinates. Dependency markers/ranges and class-path entries stay
literal unresolved declarations in every report view, without resolved CycloneDX edges.
The engine integration test covers all three
readers through the shared container pipeline, evidence presence and repeated-report
equality. These records do not establish hosted cross-platform, final release-package or
every tool-version qualification; those release gates remain pending.

## Final format breadth D profiles

D implements three primary families (Alpine APK, full Flatpak single-file bundles and
one OCI/Docker-save image family) and one compression family (LZ4 frames). With A, B and
C merged, the 0.2.6 source catalogue contains **35 primary + five
compression families = 40**, with 11 separately counted declaration families. These are
implemented source profiles for the pending 0.2.6 release. A's 0.2.3 candidate build and
promotion, B's PR #12 source/release pipeline, and later release/package gates remain
separate. See [the D scope and references](spikes/final-format-breadth.md).

- Alpine APK v2: at most eight exact gzip members, separating signature, control and
  payload namespaces. Gzip CRC/ISIZE, TAR header checksums and extents are checked.
  Identity, literal dependency/provider/replacement/install-if/trigger declarations and
  script text come only from the authoritative control member. Effective local PAX names
  are checked before assigning that role; aliases and duplicate controls cannot establish
  identity. Links and special files remain declarations. Limits include 256 MiB compressed
  input, 1 MiB per signature/control member, 128 MiB payload, 136 MiB total decoded data,
  100,000 entries per TAR, 16 MiB of names and 1 MiB of PAX metadata per TAR. Full artifact
  paths are capped at 8,192 bytes, offered paths at 32 MiB and serialized previews at
  16 MiB. APK v3/ADB, global PAX, GNU long-name/sparse metadata, PAX size overrides and
  base-256 numbers remain unsupported. Package signatures, declared datahash/member hashes,
  installation eligibility and script effects are not verified or evaluated.
- Flatpak: empty-base OSTree static-delta single-file bundles, inline version-0 parts,
  stored or bounded XZ compression and complete literal `S` object records. The reader
  checks typed GVariant framing, canonical object labels and the captured
  commit/dirtree/dirmeta/file graph; identity, runtime and permission declarations cite
  original metadata. A branch is never treated as a software version. Compressed inline
  parts, decoded layers and payload/filename source spans remain separate evidence.
  Limits include 256 MiB input, 64 MiB per decoded part, 256 MiB total decoded data and
  256 MiB of hashing work,
  4,096 parts and 100,000 objects. The output guards added at 56fce92 cap full artifact
  paths at 8,192 bytes, aggregate offered paths at 32 MiB and the shared serialized
  part/file/directory inventory at 16 MiB; exhaustion reports `flatpak.output-limited`.
  Missing objects preserve independently readable siblings. Nonempty bases, fallback or
  external objects, other opcodes/compression and signed-superblock envelopes remain
  unsupported. Signatures, remotes, runtime availability and effective sandbox policy
  are unresolved; links and extended attributes remain declarations.
- OCI/Docker-save: original layout/index/manifest/config sources, ordered layers,
  descriptor SHA-256/size agreement and config `rootfs.diff_ids` against captured
  uncompressed TAR bytes. Docker-save's measured layer hashes are distinguished from
  original declared descriptors. Literal argv, redacted environment, ports, volumes,
  labels and annotations are configuration declarations. Entry metadata preserves links,
  whiteouts and local PAX/GNU extension spans, distinct from the actual base header.
  The profile caps TAR inputs and the captured-data budget at 256 MiB, JSON at
  2 MiB per document/16 MiB
  aggregate, published layer-entry data to 16 MiB, manifests to 64 and layers to 1,024,
  with a shared entry budget. Duplicate/noncanonical namespaces, missing or mismatched
  blobs, graph cycles, global PAX, sparse metadata and unfinished TARs remain explicit.
  Layers are never merged or applied. No effective filesystem/configuration, registry
  resolution, signature trust, installation eligibility or runtime behavior is established.
- LZ4: one modern independent-block frame, stored/compressed blocks, optional content
  size and declared header/block/content checksum checks. Bounds are 4 MiB per block,
  65,536 blocks and 256 MiB decoded data. Linked blocks, dictionaries, legacy/raw streams,
  skippable frames and concatenated frames remain unsupported. Checksum agreement does
  not authenticate the input.

The pinned samples and independent native scopes are recorded separately:

| Profile | Checked evidence and boundary |
|---|---|
| [Alpine](../crates/aa-linux/tests/data/ALPINE.md) | Unchanged BSD-2-Clause libxxhash 0.8.3-r0 and two project-authored inert packages; 227 recorded Windows checks using independent gzip/TAR readers and native tools. Broader real script packages and APK v3 remain unqualified. |
| [Flatpak](../crates/aa-linux/tests/data/FLATPAK.md) | Native project-authored Apache-2.0 writer fixtures and an external hash-bound RustDesk 1.5.3 bundle; run 46107713148 passed 1,104 Flatpak BundleRef/GLib/object/payload/source-span checks. The external bundle is not redistributed; this record precedes later output guards. |
| [OCI/Docker](../crates/aa-linux/tests/data/OCI.md) | Native umoci/skopeo exports of project-authored Apache-2.0 inert data; run 46108449511 passed 326 checks over two three-layer profiles. Later local PAX provenance probes have separate writer records; the original pinned bytes are unchanged. An unfinished native-writer TAR remains a negative fixture. |
| [LZ4](../crates/aa-unpack/tests/data/LZ4.md) | Four native LZ4 1.9.4 frames of project-authored Apache-2.0 text; run 46107713119 passed 40 checks against `lz4 -dc`, original bytes and digests. |

The later Flatpak native run
[46109882704](https://github.com/atomsprout/analyze-anything/actions/runs/46109882704)
passed at `56fce923d295a7fe093b8e626fed0013590516fd`, including the output guards above.
It built the no-AI CLI and compared the checked-in writer bundle, a fresh native-writer
bundle and the external hash-bound RustDesk bundle. This qualifies those three inputs
at that revision, without broadening the supported base/opcode/compression profile.

Constructed regressions cover malformed profiles, ambiguity, missing captures and exhausted
budgets; real/native-writer records qualify their named bytes and tools. Native helpers do
not install/import bundles or packages, load/run images, mount filesystems or execute hooks.
Analysis itself remains offline and uses no external program. Complete capture, inventory,
digest agreement and authenticity are distinct claims; final integrated-source CI and
extracted release-package qualification retain their own gates.

## Parts not verified on real samples

The initial Linux package readers have native Linux references for Debian node-isarray
2.0.5-1, Fedora xxhash-libs 0.8.4-2.fc43 and project-authored script packages. Debian
metadata is read only from its captured control archive; dependency alternatives
and constraints remain literal. TAR link declarations are retained without
following targets. The RPM profile reads 3.0 leads, v4 headers and declared
CPIO payloads using shared gzip/bzip2/xz/zstd streams. Raw LZMA, RPM v6/07070X,
old Debian containers and unsupported metadata profiles remain explicit gaps.
SVR4 CPIO newc/crc has constructed checksum and late-hardlink tests; unresolved
groups and special files remain limitations. Neither package authentication nor
declared package checksums, installation eligibility, script control flow or host
dependency resolution is established. See [Linux package scope](spikes/linux-packages.md).

The bounded .NET single-file reader supports manifest versions 1.0, 2.0 and 6.0;
version 6 has published WinSW and SDK-built stored/compressed comparisons. Versions
1/2 have constructed tests only. Unsupported versions/layouts, ambiguous markers,
invalid ranges and malformed compression remain explicit. The PyInstaller reader
supports the 88-byte CArchive profile with stored/zlib members, native-writer fixtures
and a published yt-dlp Windows executable comparison. Python marshal objects and PYZ
modules are not loaded or decoded; symbolic/external references are not followed.
Other executable platforms, legacy cookies and real signed trailers remain unqualified.
See [the exact profiles and comparisons](spikes/executable-bundles.md).

The NuGet reader has been compared with the Windows .NET SDK on the published
NuGet.Versioning and NuGet.Configuration 6.11.1 packages. Ambiguous sibling
packages and incomplete listings have constructed coverage. Only exact stable
ranges can link to supplied packages. Framework choice, package signatures and
package restore are outside this profile. See [the NuGet record](spikes/windows-nuget.md).

The VSIX 2.0 ZIP and manifest reader has been compared with .NET ZIP and XML
APIs on one published Visual Studio extension. Nested dependency matching and
root-name ambiguity have constructed coverage. The documented profile leaves
interval dependencies, runtime eligibility, the older manifest schema and
signature verification open. See [the VSIX record](spikes/windows-vsix.md).

The WinGet 1.x reader was compared with `winget validate` on the published
7-Zip 24.09 manifest set, with two supplied x64 installers checked by SHA-256.
Singleton manifests, dependency candidates, duplicate payloads and rejected
YAML forms have constructed coverage. Client installer selection, version
ordering and catalog resolution are outside the supported profile.
See [the WinGet record](spikes/windows-winget.md).

The following features have only been tested with data we constructed ourselves, and have not been compared against reference tools on real samples:

- **Apple**: APFS snapshots and multiple volumes, ECDSA signatures. An encrypted DMG is identified but cannot be read. FairPlay-encrypted IPAs downloaded from the App Store have been verified on real samples: the encryption is identified, metadata, signatures and resources are analyzed as usual, and the encrypted code cannot be read.
- **Windows**: Inno Setup 6.4 files can be extracted, but the reference tool cannot read this version, so the result cannot be checked; NSIS 1.x / 2.x and forked versions are untested; an MSI's own digital signature is verified (content digest, metadata digest, signature value, certificate chain), with osslsigncode as the reference tool. The initial signed MSI fixture produced Windows UnknownError and a nonzero SignTool result for an unestablished reason. A subsequent real signed OpenJDK MSI comparison passed all four offline cryptographic checks, with Windows Valid and SignTool exit zero; the same run checked an installed 7-Zip directory. These representative results do not establish Windows trust equivalence or every signature profile; see [the baseline](spikes/windows-baseline.md). The position of the `MsiDigitalSignatureEx` stream in the digest has two readings, and when only the other reading matches, it is reported as "could not verify" without drawing a conclusion; a RAR self-extractor only has its appended data exported and is not unpacked (for license reasons); Quantum-compressed CABs, multi-volume CABs and external CABs are not unpacked.
- **Android**: XAPK / APKS have only been tested with hand-built samples; packers, Janus and unusual compression methods have only been tested on constructed samples; for AAB only the base module is analyzed in depth; a manifest in text format (apktool output) is not decoded.
- **Binaries**: Mach-O imports and exports are read from the symbol table, the export trie, chained fixups and bind opcodes, and have been compared against `dyld_info`, `nm` and `objdump`; compressed symbol names in chained fixups and the big-endian format are not read (recorded as a limitation). PE delay imports have only been verified on samples we constructed ourselves.

## Systems it has been verified on

The initial MSIX/APPX content checks read bounded block maps and compare supported
SHA-256/384/512 blocks and the checked 2021 FileHash extension with captured uncompressed
bytes. A separate original-ZIP layer checks a bounded contiguous single-disk ZIP32/ZIP64
profile, raw block-map byte binding, and declared local-header/uncompressed sizes.
It requires original captured archive bytes; folders and standalone maps cannot supply
them. Other ZIP versions/flags/methods/names, prefixes, gaps and inconsistent records
remain unresolved. A third layer binds bounded stored/independently decodable DEFLATE
segments to captured targets, compares physical block lengths/digests and mapped payload
CRCs, and checks empty final streams or stream ends included in the final segment.
Missing Size declarations, nonrestartable compression, incomplete listings, stale or
ambiguous targets and budget exhaustion remain explicit limitations. These layers do
not establish package trust. An initial P7X layer checks bounded SHA-256 SIP capsules,
CMS signature mathematics and original AXPC/AXCD/AXCT/AXBM/optional AXCI digests for
the final-signature-record ZIP32/ZIP64 profile. One pinned Microsoft RSA-2048/SHA-256
APPX has been compared with CryptoAPI and independent hashes. Other SIP/signature
profiles, broader bundle profiles and publisher subject encodings, timestamp/revocation/certificate
policy, Windows trust and installation eligibility remain unestablished. Name binding uses the shared conservative
ASCII Windows path profile and requires complete, unambiguous input enumeration.
Three SDK-built profiles and Microsoft's pinned test APPX have native declaration and
content comparisons; broader profiles and W6 acceptance remain open. See
[the MSIX scope record](spikes/windows-msix-integrity.md).

The MSIX manifest reader projects known namespace/hierarchy paths and bounded separate
declarations. Missing/unsupported/duplicate direct identities do not select a first
identity; repeated properties, application IDs and dependency/device-family names are
explicit. Dependencies, device-family versions and resource metadata remain literal,
with no installed-state, external-target or host-version resolution. Unknown namespaces,
attributes, modern qualifiers and nested behavior remain unread issues. Schema validation,
full certificate policy and installability are not established. The separate publisher
layer compares a unique manifest identity with a uniquely verified embedded CMS signer
under a bounded static Windows reverse-X.500 spelling profile. Unknown OID aliases,
unsupported legacy encodings, control characters, redaction and ambiguity remain unresolved.
Literal comparison and signed manifest coverage are separate; neither establishes Windows
trust. See [the publisher scope](spikes/windows-msix-publisher.md). Native comparisons now
include 2010 manifests inside the signed bundle fixture as well as Windows 10 manifests.
See [the manifest scope record](spikes/windows-msix-manifest.md).

The bundle layer reads the 2013 base namespace, keeps bounded identity/package/resource
declarations, and compares supported stored OPC packages with original ZIP extents and
captured inner manifests. Separate APPX-bundle SIP and outer CMS/package-digest coverage
have one pinned signed Microsoft reference. Qualified resource declaration sets and the
2018 bundle target-device declarations are compared with captured inner manifests.
The native references include language, scale, DirectX and escaped-space OPC names.
Language aliases, fallback and default ordering, optional/flat bundles, other modern
extensions, external dependencies and host selection remain unresolved. Raw ZIP, name,
capture, decompression and output budgets apply. Two SDK-built application/resource
bundles and eight upstream positive/negative fixtures are recorded in
[the bundle scope](spikes/windows-msix-bundles.md). Broader signed bundles and W6 remain open.

PowerShell syntax inspection covers qualified literal commands in PS1 and PSM1
files. Grammar errors are reported and dynamic arguments may be unresolved.
The syntax inventory leaves alias resolution, command binding and execution flow
unresolved. The literal EncodedCommand reader supports a bounded one-level
Base64/UTF-16LE profile. Batch inspection covers simple literal command
segments in CMD and BAT files. Expansion, redirects, continuations, grouped
syntax and nested dispatch remain unresolved. Reference coverage is recorded
in [the Windows script scope](spikes/windows-powershell.md).

ZIP archives whose central directory repeats names receive an explicit limitation:
the current ZIP library collapses those records, so not every version is retained.
Their container listing is incomplete and cannot establish name-unique relationships.
This differs from ASCII-case aliases and duplicate names in formats whose entries are
all exposed to the engine; those retain their existing ambiguity/name-provenance checks.

The initial Windows catalog reader supports a bounded, definite/minimal DER CMS/CTL
profile. It distinguishes CTL entries from digest declarations and does not invent
digests for v2 compatibility entries. Catalog content digests, signature values and
embedded certificate-link signatures are checked using the shared offline primitives;
the separate tree pass compares explicit SHA-1/SHA-256 declarations for supported flat
and default-PE SIP parameter profiles with supplied bytes in the same container.
CatalogFile declarations can link to unique supplied CAT siblings. This is neither
complete package coverage nor platform selection. Custom tags, other SIP/parameter
profiles and broader INF package relationships remain unresolved. Bounded CAT_NAMEVALUE
attributes preserve names, flags and supported text values; they do not resolve named
missing-versus-changed members. Unknown attributes remain length/digest records with limitations. Windows
trust, revocation, timestamps, WHQL and installation eligibility remain unverified.
Native MakeCat/SignTool v1/v2 fixtures and signature-only references are checked, along
with five supplied layouts of one pinned usbipd-win x64 driver snapshot. Broader independent
packages remain open; see [the catalog scope](spikes/windows-catalogs.md),
[membership/native comparison record](spikes/windows-catalog-membership.md) and
[independent driver input](spikes/windows-driver-corpus.md).

The initial INF reader records syntax, ordered section occurrences, literal fields and
source lines under explicit input/count/field/projection budgets. Its optional neutral
string projection does not select a platform or locale, resolve directory IDs or follow
Include/Needs. A separate bounded source graph records supported device/service/file/
registry declarations and section-reference candidates. It retains duplicate occurrences,
unknown numeric values and external references explicitly. It does not select decorated
installation alternatives, infer source-media roots or establish runtime effects.
Copy-source filenames and decimal media IDs have bounded links within
the parsed declaration graph; these do not establish a distribution root or associate
payload bytes. Explicit caller-declared logical roots now enable a separate bounded
loose-file mapping pass, carried through engine/worker/CLI settings. It retains candidate
paths and captured digests without host resolution or installation selection. The initial
profile is ASCII-only, rejects ambiguous directories and leaves CAB/tag media unsupported;
the desktop's optional logical-root control still needs native Windows window qualification.
See [the source-mapping record](spikes/windows-inf-source-mapping.md).
The sibling-CAT association remains separate. Read-only SetupAPI comparisons cover pinned Microsoft
source INF (still containing build placeholders), a controlled syntax fixture and the
pinned usbipd-win INF. Source-field agreement alone does not qualify a built package.
See [the INF scope record](spikes/windows-inf.md)
and [source graph profile and budgets](spikes/windows-inf-relationships.md).

The automated tests pass on Linux, macOS and Windows (GitHub Actions). Release builds were run successfully on Linux x64 / arm64, macOS arm64 / x64 and Windows x64 and passed the self-check. The large-scale comparison using release packages of open source projects was done on Linux.

It has been tested with real samples on one Apple silicon Mac (macOS 27): 8 installed applications (all 332 items match `codesign`), an encrypted IPA downloaded from the App Store and a decrypted IPA, and two DMGs (one of which unpacked to 7461 files). On the same Mac, version 0.1.1 was run over every app in the Applications folder (52 apps, 677,336 files); the findings that looked wrong were compared with `codesign` and the differences fixed ([TODO.md](TODO.md) lists them). Windows x64 desktop acceptance includes local portable/NSIS builds and an offline Windows 10 guest. Hosted Windows WebView2 and Ubuntu 24.04 x64 WebKitGTK under Xvfb/D-Bus each passed 67 native-window checks at d047df8. These scoped runs do not establish physical-display behavior on other Linux distributions or signed Windows/Linux delivery; see [desktop qualification](DESKTOP.md). Native Windows CLI comparisons and file-access checks are recorded in [the Windows baseline](spikes/windows-baseline.md) and [file-access record](spikes/windows-file-access.md); their explicitly pending cases remain open.

## Comparison with the system's own tools

The "Native comparison" workflow runs on GitHub's macOS and Windows machines and checks results against the system's own tools (the scripts are in `tools/native-compare/`). The most recent run passed completely:

- **macOS (98 items)**:
  - An item-by-item comparison with `codesign` of every architecture slice of system applications (Calculator, TextEdit, Terminal, Safari) and Rectangle: cdhash, identifier, team, flags, certificate chain, entitlement keys.
  - After a resource file or the code is modified, both `codesign --verify` and this tool report a failure.
  - Rectangle's DMG matches the mounted volume file by file.
  - HFS+ / APFS images generated on the spot with `hdiutil`, covering six methods (zlib, bzip2, LZFSE, LZMA, ADC, uncompressed) as well as files compressed inside the file system, all match file by file.
  - An encrypted image is identified as encrypted, and no file is claimed to have been read.
  - pkgs generated by `pkgbuild` in both the gzip and pbzx formats match file by file.
- **Windows (132 items)**:
  - A comparison with `Get-AuthenticodeSignature` on more than 40 system and common programs: whether an embedded signature is present, the signing certificate thumbprint, and whether all of this tool's checks pass when the status is "Valid".
  - After one byte is changed, Windows reports HashMismatch, and this tool's file digest check also fails.
  - Files extracted from MSZIP and LZX archives generated by `makecab` are byte-for-byte identical.

These comparisons do not cover: certificate revocation, root certificate trust, notarization status (this tool does not check these); they also do not cover iOS applications or App Store signatures.

## Other

- Windows entry-point references are associated only inside the supplied tree. The initial positive profile uses ASCII names/case folding and excludes namespaces containing non-ASCII names, so unestablished Unicode aliases cannot create false unique matches. Only LNK RelativePath establishes the file-relative base in this pass. Host-based task/REG references, URLs, variables, ambiguous or changed archive names and paths outside the profile remain unresolved. The index caps artifacts at 100,000 and full path bytes at 32 MiB; sources, references and path lengths have further limits. It never searches the host or uses a partial index to assert uniqueness; see [input-reference coverage](spikes/windows-input-references.md).

- Task Scheduler XML recognition checks a Task root/namespace within the first 16 KiB. Inputs are limited to 2 MiB, XML parsing to 20,000 nodes and captured declarations to 4,096. DTDs are refused. Supported literal trigger/action/principal/settings fields are recorded; unknown elements, application Data and unknown attribute values are omitted with limitations. No task is registered, no account/path/COM reference is resolved and no schema defaults, scalar constraints or schedule behavior are inferred. Native serialization and an independent MIT deployment fixture are checked; the latter's UTF-16 declaration conflicts with its UTF-8 bytes and is explicitly marked. See [the task record](spikes/windows-tasks.md) for further bounds and coverage.

- REG exports have a 4 MiB input, 128 KiB logical-line, 4 KiB key-path and 4,096-entry limit. UTF-8/BOM UTF-16 version 5 and ASCII REGEDIT4 declarations are supported; no machine code page is assumed. Writes/deletions remain ordered and are never applied. Binary/unknown values retain type, length and digest only. Malformed entries and exhausted limits are reported, with the first 64 issue details. Registry classification is heuristic path/name matching; effective settings, permissions, hive files and virtualization are not established. The native comparison covers a real code-page metadata subtree, with other value forms covered by constructed tests; see [the registry record](spikes/windows-registry.md).

- Internet shortcuts (`.url`) are read as UTF-8 or BOM-marked UTF-16 declarations, with a 1 MiB text limit and 256 supported fields. No system code page is guessed, no target or icon is opened, and variables are not expanded. Unsupported properties and duplicate keys are reported as limitations. The URL reference fixture is generated by Windows WScript.Shell, not a collection of independently distributed shortcuts. Recognizable credentials are redacted from shortcut declarations and generic HTTP URL facts; this is pattern-based and does not identify every possible secret. URL counts deduplicate the redacted representations.
- Shell Links (`.lnk`, also recognized by header) have a 1 MiB reader limit, at most 128 ExtraData blocks and 4,096 IDList items. UTF-16 and ASCII path/launch declarations, LinkInfo local/UNC path strings and environment target/icon blocks are read. Non-ASCII legacy text has no established code page and is omitted with a limitation. IDList contents, volume/provider metadata and other ExtraData blocks are not interpreted; their presence is reported. Multiple declarations are kept independently; targets are never resolved and precedence is not evaluated. Comparisons cover one Windows-generated fixture and one independent MIT-licensed fixture, not every Shell namespace or extension. Supplied-artifact target relationships remain open.

- Windows file access refuses explicit UNC/device/ADS paths, ambiguous DOS names, reparse points and file attributes indicating remote recall or EFS encryption. Ordinary directory scans cover unnamed data streams only. Attribute checks and final-handle checks do not eliminate ancestor-replacement races or detect drive-letter mappings to network shares. Actual cloud-provider/EFS cases remain unverified; [the Windows file-access record](spikes/windows-file-access.md) lists the tested filesystem cases and remaining work.

- The fonts embedded for PDF only cover Chinese and Latin characters. Other scripts (Korean, Arabic, emoji and so on) appear as boxes in the PDF unless a font is added with `--font`; HTML and JSON are not affected.
- Individual analyzer timeouts (300 seconds per file by default) abandon threads inside the analysis process; they do not immediately terminate a parser. Both CLI analyze and the desktop app use child processes. CLI Ctrl+C or the optional `--run-timeout` asks for cancellation, allowing five seconds for a partial report before terminating the worker; no new report is written if none finishes. This does not yet guarantee termination of external disassembler descendants, cleanup after the supervisor itself is killed, or a partial report after every hard termination. CLI inspect remains in-process. The unpack timeout (900 seconds per container by default) is checked only when the unpacker hands over the next file.
- The executable with PDF is about 49 MB, of which the Chinese font is 8.6 MB.
- macOS has a command of its own called `aa` (Apple Archive). This program was called `aa` in its first releases (0.1.0 to 0.2.0 on Homebrew installed it as `analyze-anything`); it is `analyze-anything` everywhere now, with the short name `aaaa`.
- Heuristic findings (suspected credentials, packing, SDK identification) can be false positives; they are all marked "Heuristic" in the report.
- When the process is forcibly terminated, the files unpacked into the temporary directory are not cleaned up at that time (they are cleaned up on both normal exit and error); the next run clears these leftover directories when it starts.
- When two reports are diffed, findings are paired by "rule + file location within the input". Known artifact display parameters (including the largest-file path and the input bundle label) are normalized relative to the input. Arbitrary strings read from the input, including product names and embedded debug paths, remain literal; a difference in those values is still reported.
- Desktop app: history records only save the report, so a history report that is reopened cannot show hex evidence and the input must be analyzed again; there is no automatic update; on macOS no external tool can drive the system WebView, so the whole flow is covered by the application's self-check mode (see [DESKTOP.md](DESKTOP.md)), and the native menus, drag and drop, and system dialogs can only be checked manually.
- Supervised runs refuse a scratch location inside the selected input folder before creating it. Process workers have a bounded shutdown after parent-pipe loss; recognized scratch folders can be recovered on the next start after both ownership locks are released. Unmarked/legacy folders are left alone. Actual supervisor-kill scenarios beyond pipe-disconnect tests and external disassembler descendant termination remain unverified; see [CLI supervision](spikes/cli-supervision.md).
