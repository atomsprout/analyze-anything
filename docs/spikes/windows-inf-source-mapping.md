# INF source declarations and distribution roots

W5 remains open. The implemented declaration links below are a prerequisite for supplied
payload mapping; they do not establish a distribution root or a Windows installation choice.

## Implemented declaration links

`windows.inf-declarations.source_relationships` refers to indices in that fact's `records`.
Copy-list rows use their source filename, including a rename's second field; direct
`@filename` declarations use the named file. An ASCII filename index links them to
SourceDisksFiles records without reading any target. The shared conservative Windows
component profile excludes variables, streams, reserved names, path separators and
unsupported aliases. An incomplete/redacted/non-ASCII or omitted source namespace
cannot establish a unique lookup. Duplicate records remain separate candidates.

SourceDisksFiles disk IDs link to SourceDisksNames keys as bounded, unsigned decimal
32-bit integers; leading zeroes do not create different IDs. Hexadecimal, signed,
overflowed and unknown identifiers remain unresolved. Architecture-specific source
records retain generic and same-architecture media candidates. Generic source records
retain the different declared media architectures. No host architecture is selected,
and generic/architecture alternatives are not collapsed into a chosen installation row.

Each relationship records its kind, source record, declaration, observed candidate count,
bounded target indices, status and namespace completeness. Both `platform_selected`
and `payload_path_resolved` stay false. A missing source declaration does not mean a
missing installed or supplied file. One Info/Derived summary cites up to six original
source rows, preserving the first two literal fields and any neutral projection.

Section references and these record relationships share the 8,192-edge and 4 MiB
serialized-content budgets. Each relationship retains at most 16 target details while
keeping its observed count; the 4,096-record budget is unchanged. Exhaustion is explicit.
Relationships are constructed only after all retained source nodes, in deterministic
order. They do not copy target sections or recurse into Include/Needs.

Two new unit tests cover rename matching, decimal IDs, generic/amd64/arm64 alternatives,
duplicate media IDs, missing declarations, unsupported Unicode/variable namespaces and
candidate/output limits. A pipeline test exercises both licensed Microsoft source INFs
and the controlled relationship fixture, including positive evidence and the absence of
any extra target artifact. Read-only native comparisons pass again for ECHO (43 fields),
NullFilter (91), the controlled INF (51), and the explicitly scoped BasicDisplay source
(34). The helper also checks retained relationship filenames/IDs and bilingual summary
output. Those are source-field checks, not native install-time path selection.

Format, workspace Clippy, the no-default-feature CLI build and full workspace tests
passed, including damaged-fixture robustness and all 52 Windows pipeline tests. The
local log is `out/windows-baseline/workspace-inf-source-links.log`.
Native records are under `out/windows-baseline/inf/{echo,nullfilter,relationships,basicdisplay}-sources`.

## Why a source root must be explicit

Microsoft defines SourceDisksNames paths relative to the distribution/installation root,
and SourceDisksFiles subdirectories relative to those media paths. The INF's containing
folder is not, by itself, a declaration of that root. A supplied folder may contain several
packages, an INF in a subfolder, or an explicitly selected installed snapshot. A destination
directory ID such as `%13%` in ServiceBinary or DestinationDirs does not supply a source base.

Cabinet/tag declarations and forced-CAB flags also affect source lookup. A correct next
step must retain these cases as unsupported until their semantics are implemented. It
must not join an arbitrary basename to a same-named supplied file and call that the
Windows source. Filename and media-ID links above remain useful even when the base is unknown.

References: Microsoft [SourceDisksNames](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksnames-section),
[SourceDisksFiles](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksfiles-section)
and [CopyFiles](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-copyfiles-directive).

## Caller-declared logical roots

The mapping increment now takes explicit INF-to-distribution-root assignments in
`Options.windows_source_roots`, the worker Analyze request, and the repeatable CLI flag
`--windows-source-root <INF> <ROOT>`. Both identifiers are logical paths within the supplied tree,
never machine paths or permission to read anything else. Bind the root to the named INF
and its immediate parent-container namespace. Root `.` denotes the outer input namespace;
an archive root is its logical container path. Do not apply one archive's root to another.
Ambiguous/conflicting declarations and absent or unenumerated roots cannot yield a unique link.
Assignments are limited to 32, 8 KiB per identifier and 512 ordinary ASCII components.
They are case-folded, sorted and deduplicated before publication as
`engine.windows-source-roots`. Conflicting roots for the same INF are refused. CLI
validation fails before analysis; direct API/worker validation records a bilingual engine
limitation and enables no root mapping. Invalid machine paths are not echoed into reports.

The worker client retains its existing default method and adds an explicit-root method.
Omitted protocol fields default to empty and empty fields are not serialized, preserving
existing requests. Empty settings retain unresolved-base behavior and no mapping fact.
The desktop home page has a collapsed optional logical-root control. Its settings travel
through `aa-app` and the same worker protocol; native command validation happens before
replacing a live run. Returning home clears the draft, while reanalysis of a kept report
uses its validated `engine.windows-source-roots` settings. Browser checks use the stand-in
backend; native Windows window qualification remains open under W10.
The shared engine boundary validates callers independently of CLI parsing.

With an established root, the mapper combines supported media paths, source subdirectories and
literal source filenames. INF root-relative backslash notation is not a host absolute
path; UNC/device/drive/ADS paths, escapes, variables and unsupported aliases remain refused.
Use the existing supplied-artifact index and listing/name-provenance safeguards, not
filesystem resolution. Alternative media declarations and literal/projection evidence are
retained. `windows.source-files` records the caller-declared basis, source/media node
indices, relative candidate path, target artifact/digest, status and independent optional
size comparison. A complete namespace and missing final target can establish
`not-supplied-at-candidate-path`; incomplete listings, unknown directories and other
unsupported cases remain unresolved. This is not absence from a Windows installation.
An Info/Derived finding reports associations with captured digests, independently of CAT
SIP comparisons. Bad nonempty size declarations produce an explicit unresolved check;
known size disagreement is a fact, not a claim that the file was modified.

The loose-file profile supports empty or zero media flags. Tag/CAB declarations, unknown
flags and extra source/media fields remain unsupported even when a same-named loose file
exists. Root-relative backslash directory notation is normalized only inside the declared
logical root. Parent escapes, UNC/device/drive/ADS forms, variables and unsupported names
are refused. Each root is bound to its INF's immediate container; nested ZIP roots work,
while another or outer container cannot supply its missing files. Mapping uses captured
artifact digests and never opens a target or host path.

Distribution-root lookups add a directory-spelling index to reject case-aliased directories.
Prefix processing is capped at 32 MiB of cumulative logical directory-prefix bytes before
allocation, alongside the existing 100,000-artifact/32 MiB path/8 KiB-per-path index limits.
At most 4,096 mapping attempts and 4 MiB of compact mapping records are shared across all
assignments. Exhaustion is explicit; omitted candidates and assignments stay unchecked.
Existing shortcut/reference matching continues to use its own documented index profile.

Focused tests cover direct/worker/CLI byte parity, repeatable flags, rejected host paths,
canonical assignments, subfolders, ZIP and nested ZIP boundaries, missing source paths,
directory-case aliases, incomplete enumeration, unsupported size declarations, directory
notation and both attempt/output budgets. The controlled six-layout package helper now
adds source/media declarations and passes explicit roots for folder/ZIP layouts. All six
cases pass, including missing-path status, captured target digests, declared sizes, repeated
JSON and Chinese report inclusion, with SignTool policy observations kept separate.
The latest native record is `out/windows-baseline/catalog-root-package-final/checks.json`.
Format, workspace Clippy, the no-default-feature CLI build and full workspace regression
passed. The complete log is `out/windows-baseline/workspace-windows-source-roots.log`.
This includes worker/CLI byte parity, the complete damaged-input run and budget tests.

The explicitly selected BasicDisplay folder also passes a caller-root check: the source
declaration associates the supplied BasicDisplay.sys digest, two runs produce identical
JSON and both input hashes remain unchanged. No CAT was supplied and no Windows trust
claim is inferred. Its local record is `out/windows-baseline/basicdisplay-explicit-root/checks.json`;
the system files remain unredistributed. This is one loose-file layout, not the broader
licensed built-package corpus gate.

Remaining acceptance work includes more independent licensed built-package layouts,
CAB/tag media semantics and native directory/alias matrices. Regression cases include
direct API/worker/CLI parity, invalid and conflicting settings,
root/subfolder/ZIP/nested-container layouts, root-relative media notation, cabinet cases,
renames, duplicate/case/Unicode aliases, incomplete input, absent/changed payloads,
unchanged inputs and repeated reports. Connecting an expected catalog digest to a changed
named file additionally needs supported catalog filename attributes; a digest-only no-match
must continue to leave missing versus modified unresolved. Broader independently licensed
built-driver packages remain a separate acceptance gap.

One checked boundary illustrates that last distinction: the controlled v2 CAT fixture's
member attributes contain indirect-data and MemberInfo2 records, without a CAT_NAMEVALUE
attribute. The installed SDK 10.0.26100.0 WinTrust.h defines CAT_NAMEVALUE as OID
`1.3.6.1.4.1.311.12.2.1`, separately from MemberInfo (`...12.2.2`) and MemberInfo2
(`...12.2.3`). A subject digest must not be invented into a filename. These header/fixture
observations do not implement filename attributes or prove their semantics for other catalogs.

The preceding declaration-link increment passed CI for
`da795908d3c8211d36819391fd81fccd2d7e1669`:
[run 44854420385](https://github.com/atomsprout/analyze-anything/actions/runs/44854420385).
Linux/macOS/Windows core checks, macOS desktop and licenses all passed. This does not
cover the explicit-root implementation by itself. That implementation subsequently
passed Linux/macOS/Windows core checks, macOS desktop and licenses at
`f242307cc0b3b209d97319be04d511ef1f7216c1`:
[run 44858583291](https://github.com/atomsprout/analyze-anything/actions/runs/44858583291).
The desktop control is a later increment and needs its own CI run.

For that increment, local format, workspace Clippy, the no-default-feature CLI build
and full workspace tests passed, including the configured `aa-app`/worker/direct-engine
parity test. The log is `out/windows-baseline/workspace-desktop-source-roots.log`.
The page also passed its TypeScript/Vite build, 14 unit tests and 28 browser checks
across WebKit and Chromium. These checks cover the stand-in backend, not a native
Windows WebView2 window or delivery qualification.
