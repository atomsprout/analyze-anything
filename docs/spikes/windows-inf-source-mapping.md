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

## Next implementation: caller-declared logical roots

The next mapping increment should take an explicit INF-to-distribution-root assignment
in analysis settings. Both identifiers must be logical paths within the supplied tree,
never machine paths or permission to read anything else. Bind the root to the named INF
and its immediate parent-container namespace. Root `.` denotes the outer input namespace;
an archive root is its logical container path. Do not apply one archive's root to another.
Ambiguous/conflicting declarations and absent or unenumerated roots cannot yield a unique link.

Carry this setting through engine Options, worker Analyze requests and clients, and CLI
arguments. Record the sanitized logical assignment and its caller-supplied basis in the
report. Default settings must retain today's unresolved-base behavior. Worker protocol
defaults must preserve existing callers. Validate root counts/lengths and names in the
shared engine boundary, rather than trusting just CLI parsing; deterministic settings
ordering is required. This settings and physical-mapping increment is not implemented yet.

With an established root, combine only supported media paths, source subdirectories and
literal source filenames. INF root-relative backslash notation is not a host absolute
path; UNC/device/drive/ADS paths, escapes, variables and unsupported aliases remain refused.
Use the existing supplied-artifact index and listing/name-provenance safeguards, not
filesystem resolution. Preserve alternative media declarations and the literal evidence.
Report missing supplied candidates conditionally on a complete input namespace, separately
from unreadable/unsupported candidates. Compare declared sizes separately from digests.

Required checks include direct API/worker/CLI parity, invalid and conflicting settings,
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
