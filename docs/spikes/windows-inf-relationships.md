# INF declaration relationships: implementation boundary

Research for the remaining W5 work, following the initial syntax, catalog and supplied
digest implementations. This document specifies the next increment; the relationships
below are not yet implemented. [TODO.md](../TODO.md) remains the completion tracker.

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
graph but contains an unresolved `$ARCH$` build placeholder; add a controlled Models
fixture. An independent Models source fixture is now captured as `upstream-echo.inf`,
the unchanged bytes of Microsoft's `general/echo/kmdf/driver/AutoSync/echo.inx` at the
same pinned revision as NullFilter, renamed only for the reader's extension gate.
SHA-256: `3565c645713180cc91ebada8d78008482b214be3b881262e5938f3f88ebbd548`.
Its MS-PL license and notices are retained in NOTICE and tests/data. Read-only SetupAPI
and the CLI agree on 43 projected fields, with repeated JSON and bilingual/HTML output
checked. `$ARCH$` and `$KMDFVERSION$` remain source build placeholders. This validates
source parsing, not the proposed graph or a built driver package. No driver installation,
loading or registry changes were performed.

The new portable regression preserves the model's `root\ECHO` hardware ID, the
unexpanded architecture decoration and the neutral AddService flag projection. All
47 Windows pipeline tests, format checking and aa-windows Clippy with warnings denied
passed after adding it. Native CLI output is recorded under
`out/windows-baseline/inf/echo-report`; the portable test log is
`out/windows-baseline/inf/echo-pipeline.log`.

For package relationships, extend the existing six-layout catalog check with source
declarations and explicit supplied paths. Only a proven filename/source association
can help distinguish a missing declared source from bytes that disagree with an expected
digest. The current digest-only no-match status must remain unresolved when no such
association exists. W5 still requires a broader licensed built-package corpus.
