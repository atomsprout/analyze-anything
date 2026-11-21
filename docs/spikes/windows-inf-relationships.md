# INF source declaration graph

The initial graph implements bounded source relationships after the syntax, catalog
and supplied-digest increments. W5 is still open. This record describes its implemented
profile, design boundaries and remaining acceptance work; [TODO.md](../TODO.md) remains
the completion tracker.

## Implemented profile

`windows.inf-declarations` contains source-indexed records and references, separate from
the original `windows.inf` syntax. Records cover supported Version fields, Manufacturer
and Models entries, AddService, service properties, CopyFiles lists/direct sources,
source media/files, DestinationDirs and AddReg rows. Every record names its section and
entry occurrence, physical line span and literal/neutral-projection basis. A Derived/Info
finding cites retained literal field evidence. Existing catalog comparisons stay separate.

Known local section references retain up to 16 candidate occurrences, an independent
observed count and explicit status. Model install alternatives exclude companion suffixes.
Duplicate sections are retained without selection. An incomplete parse, redacted section
name or non-ASCII section namespace prevents positive local reference resolution. Common unbuilt WDK
`NT$ARCH$` section shapes can contribute source records but never platform selection;
placeholder-bearing references remain explicitly unresolved. External Include/Needs are
recorded without following them. Unknown contexts/directives remain in the syntax fact,
with the always-present installation-scope limitation.

AddService retains optional event-log references and distinguishes the supported
`AddService=,2` NULL-driver form. Unsigned 32-bit decimal/hex values are decoded separately
from literals; StartType 0 through 4 gets a declaration label. Numeric decoding is not
validation of every allowed flag or service-property combination. Invalid numeric values
and supported-shape failures are explicit. Copy source/destination names are separate;
direct `@filename` cannot be mixed with a named list. Registry-list edges retain their
referencing role, so a shared HKR row is not assigned one absolute registry root.

At most 4,096 records, 8,192 references and 4 MiB of serialized record/reference content
are retained. Target-detail omission is counted separately from observed candidates.
Physical sections are not copied per edge; each section/role pair is processed once via
a deterministic work queue, bounding cycles. Source rows come only from the parser's
already bounded and redacted data. Five new unit tests cover alternatives, roles, NULL
services, missing/duplicate/unsupported namespaces, cycles, numeric overflow, copy-source
renames, bare Manufacturer syntax, media-ID duplication, deceptive contexts, redaction
and record/reference/candidate/byte budgets. Two pipeline tests add independent source
graphs and a portable native-field snapshot.

Read-only native/CLI comparisons passed for ECHO (43 fields, 20 projected graph rows),
NullFilter (91 fields, 38 graph rows) and the project-authored relationship fixture
(51 fields, 18 graph rows). Directory-ID-dependent rows are retained literally rather
than populated from SetupAPI's host expansion. The helper also checks source spans,
typed values, unchanged input, repeated JSON and English/Chinese Markdown plus HTML.
The controlled fixture and its snapshot are Apache-2.0, recorded in NOTICE. These are
field/source comparisons, not Windows installation or directive-policy validation.
Format, workspace Clippy and the no-default-feature CLI build passed. Full workspace
tests passed before the final redacted-namespace and early-budget guards; their log is
`out/windows-baseline/workspace-inf-graph.log`. After those guards, aa-windows passed
70 unit tests (one helper ignored) and all 49 pipeline tests, followed by the no-default
build and repeated native/CLI comparisons on all three sources. The focused final log
is `out/windows-baseline/inf/graph-final-tests.log`. Cross-platform CI for the final graph
implementation is the next gate. No report templates or desktop code changed here.

The controlled fixture SHA-256 is
`a83e67591c2b491fb928f2e724f3cfa1fffb9010a2cfc40068ba7be4dcad890a`;
its checked-in SetupAPI reference binds that exact source. Native graph observations
are under `out/windows-baseline/inf/{echo,nullfilter,relationships}-graph`.

## Representation

Keep `windows.inf` as the source record. Add a bounded declaration graph whose nodes
refer to section occurrences and entry start/end lines. Preserve literal fields and
identify any optional neutral projection explicitly. A source declaration, a candidate
section occurrence, a supplied-file association, a digest comparison and an installation
decision are different observations. The graph must not collapse them into one edge.

Record Version provider, DriverVer, class/GUID and catalog declarations independently.
Duplicate scalar fields and sections remain visible; source order is not installation
order. New findings summarize declarations with source evidence and fixed Info severity.
They do not infer active services, installed devices or applied registry state.

## Device and section declarations

Start Models recognition from Manufacturer entries, including the documented bare-name
form. Retain each declared TargetOSVersion and corresponding candidate Models section.
Record model descriptions, install-section bases, hardware IDs and compatible IDs.
Represent supported architecture/version decorations as declared alternatives, without
choosing a host platform. Preserve unknown decorations as unresolved data. Manufacturer
decorations and Models declarations have related but distinct syntax:
[Manufacturer](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-manufacturer-section),
[Models](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-models-section).

Resolve only documented local section-reference forms. Duplicate occurrences, unsupported
name folding, missing names, redaction and incomplete syntax need explicit statuses.
Do not select the first matching occurrence or apply a generic prefix match that could
mistake a `.Services` or `.HW` companion for an install section. A list of candidates is
not a selected Windows section. Include/Needs declarations stay explicit; following an
installed INF or consulting the Driver Store is outside this analyzer.

## Service declarations

Find AddService in documented DDInstall.Services and DefaultInstall.Services contexts.
Retain service name, optional flags, service-install reference and optional event-log
reference. The documented empty-name `AddService=,2` form represents a NULL associated
driver; it must not become a malformed service or an invented name. In referenced
service-install sections, record declared binary, type, start type, error control,
dependencies and other recognized fields. Decode supported numeric values separately
from their literals. Duplicates, unknown flags and unsupported forms remain explicit.
Service declarations do not establish that anything starts on the current machine.
References: [AddService](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addservice-directive),
[DDInstall.Services](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-ddinstall-services-section).

## Files and registry declarations

CopyFiles can name a direct `@filename` or a list section. List rows distinguish source
and destination names, with omitted source meaning the destination name. Preserve copy
flags; a declaration does not prove a copy occurs. Recognize directives only in supported
documented contexts, rather than treating a key named CopyFiles in an arbitrary data
section as an action. See [CopyFiles](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-copyfiles-directive).

SourceDisksFiles and SourceDisksNames use `.amd64`, `.arm64`, etc., rather than `.NTamd64`
decorations. Retain source filename, disk ID, subdirectory, declared size, media path
and optional CAB/tag declarations. Their architecture alternatives and duplicate media
IDs must stay separate. Media paths are relative to a distribution root, which is not
automatically established by the INF's current location. Cabinet fallback and forced-CAB
flags also prevent a generic basename lookup from proving a source mapping. Never use
host files to fill missing media:
[SourceDisksFiles](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksfiles-section),
[SourceDisksNames](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-sourcedisksnames-section).

DestinationDirs and ServiceBinary directory IDs describe destinations, not where supplied
source bytes reside. Do not strip `%12%` or `%13%` from a service path and claim the
remaining basename resolves its driver. A later supported source mapping can link supplied
bytes and their digest; its assumptions and source declarations must be evidence.

AddReg references list sections whose rows contain root, subkey, value name, flags and
data fields. HKR's root depends on the referencing install/service/interface context;
there is no single machine-independent absolute key. Record each use context separately
from a shared row, retain numeric flags and conditional operation semantics, and carry
the existing credential redaction into every derived field. Do not label every AddReg
row as an unconditional value write. See [AddReg](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-addreg-directive).

## Budgets and acceptance

Use the existing bounded parser as the only text source. Add explicit graph node, edge,
expanded-text and per-reference candidate limits. A repeated reference must not copy an
entire section on every edge. Stop amplification before allocation; omitted records and
unsupported semantics must be counted in facts and reported as bilingual limitations.
Use deterministic ordering and no host-dependent selection or name normalization.

Required regression cases include multiple architectures, absent/duplicate sections,
NULL service, unknown/overflowed numerics, shared service/registry sections, renamed copy
sources, conflicting media IDs, external Include/Needs, unknown directory IDs, deceptive
directive keys in unrelated sections, Unicode case ambiguity, credential propagation,
cycles and exhausted graph/output budgets. Every positive finding needs retained evidence.

Compare controlled and licensed source fixtures with read-only SetupAPI field inspection.
That reference can validate decoding and source fields, but cannot prove install-time
selection or execution semantics. Existing NullFilter covers a DefaultInstall service
graph but contains an unresolved `$ARCH$` build placeholder; the controlled Models
fixture now supplies an explicit architecture case. An independent Models source fixture is captured as `upstream-echo.inf`,
the unchanged bytes of Microsoft's `general/echo/kmdf/driver/AutoSync/echo.inx` at the
same pinned revision as NullFilter, renamed only for the reader's extension gate.
SHA-256: `3565c645713180cc91ebada8d78008482b214be3b881262e5938f3f88ebbd548`.
Its MS-PL license and notices are retained in NOTICE and tests/data. Read-only SetupAPI
and the CLI agree on 43 projected fields, with repeated JSON and bilingual/HTML output
checked. `$ARCH$` and `$KMDFVERSION$` remain source build placeholders. This validates
source parsing, not a built driver package. No driver installation,
loading or registry changes were performed.

The new portable regression preserves the model's `root\ECHO` hardware ID, the
unexpanded architecture decoration and the neutral AddService flag projection. All
47 Windows pipeline tests, format checking and aa-windows Clippy with warnings denied
passed after adding it. Native CLI output is recorded under
`out/windows-baseline/inf/echo-report`; the portable test log is
`out/windows-baseline/inf/echo-pipeline.log`.
Cross-platform CI for that source-fixture increment passed at
`5fdaa313a5461a032adb7d6ce6a764e60f9f4cc9`:
[run 44849942411](https://github.com/atomsprout/analyze-anything/actions/runs/44849942411).
Linux/macOS/Windows core checks, macOS desktop and licenses all passed. This precedes
the graph implementation described above; the graph needs its own CI run.

For package relationships, extend the existing six-layout catalog check with source
declarations and explicit supplied paths. Only a proven filename/source association
can help distinguish a missing declared source from bytes that disagree with an expected
digest. The current digest-only no-match status must remain unresolved when no such
association exists. W5 still requires a broader licensed built-package corpus.
