# Supplied catalog members and INF catalog declarations

This W5 increment compares declarations with supplied bytes. W5 remains open: the
result does not select an installation platform, establish package completeness or
apply Windows trust policy.

## Supported comparisons

The tree pass adds `windows.catalog-membership` beside the file reader's
`windows.catalog` fact. The latter's `payloads_checked: false` remains a file-pass
scope marker; the separate tree fact records exactly which comparisons were made.
No blanket package-verification Boolean is inferred from a positive comparison.

Explicit SHA-1/SHA-256 indirect-data declarations are compared only for recognized
flat-file/default-PE SIP GUID, data-OID and parameter combinations. Catalog v1
reference tags or v2 binary subject identifiers must agree with the declared digest.
Compatibility entries without an explicit digest remain distinct, uninterpreted
entries. CAB SIPs, page-hash and other parameter profiles, custom tags and unsupported
algorithms remain unresolved; an ordinary file hash never substitutes for a PE SIP hash.

Flat comparisons use the engine's captured digests. PE comparisons take a bounded
snapshot of supplied bytes and require its whole-file SHA-256 to agree with the
engine's captured digest before hashing. The supported PE catalog profile omits the
checksum, fixed security-directory slot and terminal certificate table. An unsigned
file is padded to an eight-byte boundary. Header/section extents and certificate-table
placement are checked. Unsupported layouts remain unresolved. These catalog-specific
rules do not change the existing embedded-signature digest implementation.

Only artifacts in the same immediate parent-container namespace are compared. A ZIP's
members cannot borrow payloads from the surrounding folder or another archive. Digest
agreement does not resolve a path: identical bytes under several supplied names all
remain matches. Unicode names are acceptable for digest comparisons; the separate
conservative Windows path association profile still excludes ambiguous Unicode scopes.

Each entry records its status, hash profile, declared digest, observed match count,
search completeness and bounded match details with whole-file SHA-256 identifiers.
Incomplete enumeration or unsupported/unreadable PE data cannot support a complete
search claim. Positive mathematical agreement may still be shown with that uncertainty.
No match cannot distinguish an absent file from a modified file, so neither is guessed.

The Info/Derived `windows.catalog-digest-agreement` finding cites both the declaration
and supplied-byte digest evidence. Signers whose supported content and signature checks
passed are listed separately. Their presence binds the compared declaration to signed
content; it does not establish a trusted signer, a complete chain or installation eligibility.
Both Windows trust and catalog-API acceptance flags remain false.

## INF links

Known `CatalogFile`, `.NT`, `.NTx86`, `.NTia64`, `.NTamd64`, `.NTarm` and `.NTarm64`
Version-section declarations participate in `windows.input-references`. A single literal
field, or its conservative neutral-Strings projection, can identify a unique supplied
CAT sibling. Evidence retains the original literal and marks any neutral projection.
Subdirectories, parent paths, host paths, variables without a supported projection and
ambiguous/incomplete namespaces remain unresolved. Every decoration is retained; none
is selected as the host's installation choice. The link describes a declared filename,
independently of the catalog's signatures or digest coverage.

## Budgets

The index admits at most 100,000 artifacts, 32 MiB of logical path bytes and 8 KiB per
path. A PE snapshot is at most 64 MiB, with 512 MiB total attempted snapshot bytes.
At most 256 catalogs and 32,768 CTL entries are compared. Detail output is limited to
eight matches per entry, 4,096 globally and 2 MiB of match-path bytes. Truncation and
exhausted budgets produce explicit limitations; observed counts are separate from
retained detail. A finding is emitted only with retained supporting evidence.

## Native observations and portable tests

`windows-sip-fixtures.py` generates 17 controlled layouts from the existing unsigned,
signed and PE32 fixtures. `windows-sip-hash.py` calls read-only
CryptCATAdminCalcHashFromFileHandle2 for SHA-1 and SHA-256. The checked-in
`native-sip-hashes.ref.json` records each input's whole-file SHA-256 and native result
or error. Portable Rust tests regenerate the layouts in memory and compare both hashes
or require rejection. The 12 accepted and five rejected layouts cover unsigned trailing
lengths, signed trailing data, section gaps/overlap/out-of-bounds extents, oversized
headers, a zero directory count, a zero certificate offset and truncation. These are
observations of the available Windows SDK/host profile, not every possible SIP provider.

`windows-catalog-package-check.py` passed six controlled layouts: catalog-only, dual
embedded/catalog signatures, modified payload, missing payload, embedded-only and ZIP
containment. It compares native SIP observations with the CLI facts and INF associations,
checks unchanged input and repeated JSON, and reads English/Chinese Markdown and HTML.
Explicit-catalog SignTool output is retained as development evidence: original/dual
inputs fail Windows policy on the self-issued root, changed payloads are not found in
the specified catalog, and missing files fail file lookup. Embedded-only checks have
their own certificate/time-policy failures. Nonzero policy results are not reclassified
as successful Windows trust checks.

Four new unit tests (including the 17-layout matrix) and four pipeline tests also cover
stale PE snapshots, snapshot/index/detail budgets, absent namespace metadata, Unicode
digest matches, archive scope, original INF literal evidence and refusal to substitute
a flat hash for a PE member digest. The complete Windows pipeline suite passed 46 tests.
Workspace Clippy with warnings denied and the no-default-feature CLI build passed.
`cargo fmt --all --check` and `cargo test --workspace` passed, including the damaged
fixture robustness run; the complete local log is
`out/windows-baseline/workspace-catalog-membership.log`. Cross-platform CI for this
increment passed for `e6f38d035c2be543269cb2fec6afb42639d0488a`:
[run 44849363474](https://github.com/atomsprout/analyze-anything/actions/runs/44849363474).
Linux/macOS/Windows core checks, macOS desktop and licenses all passed.
No report templates or desktop code changed in this
increment; the native CLI checks cover its actual new Markdown/HTML/Chinese output.

Native development output lives under `out/windows-baseline/catalog-package-checks`
and is not a deterministic report or redistributed host snapshot. The new golden data
is project-authored from the existing project fixtures; no new binary or private key
is distributed.

## Still open

Typed INF installation/device/service/source-file relationships, broader member/SIP
and CMS profiles, independent licensed built-driver packages and their native reference
matrix remain open. Native-generated fixtures alone do not close W5.

Subsequent increments add bounded INF declaration/source-root relationships and the
[independent usbipd-win snapshot](windows-driver-corpus.md). Its five layouts distinguish
changed, missing and renamed supplied SYS files; the catalog's File/OSAttr attributes
now remain readable without invalidating unrelated digests. This is one x64 snapshot,
not the broader independent package matrix. Named missing-versus-changed member
relationships are still open; digest-only no-match remains unresolved.

References: Microsoft [catalog hashing API](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatadmincalchashfromfilehandle2),
[INF Version section](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/inf-version-section)
and [SIP-dependent PE signatures](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures).
