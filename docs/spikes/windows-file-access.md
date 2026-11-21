# Windows local file access checks

2026-11-20. Partial W1 implementation; the full milestone remains open.

The engine now checks Windows path components before content access. Explicit UNC and device
namespaces, ambiguous DOS names and explicit named-stream paths are refused. Reparse points
are checked along the supplied path and before directory enumeration. Metadata for offline,
recall-on-open and recall-on-data-access content prevents reading it. Encrypted files are refused;
an encrypted directory's creation-default attribute alone does not suppress unencrypted children.

Every stored artifact read repeats these checks. Windows opens use OPEN_REPARSE_POINT and
OPEN_NO_RECALL, and check the opened handle's attributes before content reads. Small files are
read from that handle rather than reopened by path, with a limit of the observed length plus
one byte; a length change is reported as unreadable. These flags are documented in Microsoft's
[CreateFileW reference](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).
No new unsafe code or analysis subprocess was introduced.

Skipped directory entries receive engine.local-content-skipped with English and Chinese rule
text and a relative artifact path. Listing limitations now contribute to content_lost, so skipped
content makes the report partial. A refused root cannot be opened and returns an input error.
Ordinary Windows folder scanning covers the unnamed data stream; it does not enumerate ADS.

On Windows x64, 7 engine unit tests and 28 engine integration tests passed. Three additional
Windows filesystem tests passed with actual junctions, named NTFS streams, hardlinks, an
exclusively locked file and a nested Unicode path longer than 260 characters. A junction was
refused as a descendant, root and ancestor of a requested file. Attribute-policy tests use
constructed bit flags: they do not prove behavior on actual EFS or cloud-provider files.
Engine Clippy with warnings denied passed.
The complete workspace test run after the initial disk-access change also passed, including
the damaged-fixture sweep. The subsequent archive-name changes were checked with the targeted
engine integration suite and Clippy as described below.

The next archive-name increment passed all 29 engine integration tests. A generated tar.gz
contains CON, colon and trailing-dot names, a drive-like path, ASCII case aliases and duplicate
names, with entries large enough to force disk spilling. Every logical child remained readable
with its own expected bytes, internal spill files used numeric names, and repeated reports were
byte-identical. Name collisions now produce engine.entry-name-collision while preserving both
streams; this ambiguity notice does not increment content_lost. Matching beyond ASCII case is
not established by this check.

The implementation is not a filesystem sandbox. A parent directory can still be replaced
between metadata checks and access; checking the final handle only closes the final-component
case. A drive-letter mapping to a network share is not identified by lexical namespace checks.
Actual EFS/cloud-provider cases, mapped drives, handle-based ancestor containment, portable ADS
capture and wider Unicode filename equivalence need further work. Large files retain
the existing read-only mapping behavior, including its documented concurrent-truncation risk.
