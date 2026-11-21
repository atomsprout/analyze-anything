# MSIX content, ZIP records, physical blocks and signature digests

W6 remains open. These increments implement content, physical structure and initial
SHA-256 signature-envelope/byte-binding checks required by
[PLAN-WINDOWS.md](../PLAN-WINDOWS.md), alongside the existing manifest reader. Package
and bundle models, publisher/certificate policy, dependencies and appinstaller references
retain their separate acceptance work.

## Implemented representation

The file pass recognizes `AppxBlockMap.xml` by name and its 2010 block-map namespace.
`windows.msix-blockmap` records the raw source SHA-256, declared hash URI, file names,
uncompressed sizes, local-header sizes, ordered blocks, optional compressed sizes and
the checked 2021 `FileHash` extension. SHA-256, SHA-384 and SHA-512 use the published
W3C URIs. Unknown algorithms remain declarations without a hash-agreement conclusion.
The decoder accepts strict UTF-8 or BOM-marked UTF-16, checks encoding declarations,
refuses DTDs and caps XML nodes. Unknown extensions, attributes and structures are
unread instead of silently discarded. `IgnorableNamespaces` supports the observed
2021 FileHash profile only; it does not authorize arbitrary extension semantics.

File names remain literal, with credential redaction. Supported relative names use
the shared ordinary ASCII Windows component profile; slashes/backslashes are input
separators, not permission to resolve host paths. Duplicate/case-aliased declarations,
redacted names, unsupported aliases and inconsistent size/block counts remain explicit.
The first layer supports fixed 64-KiB uncompressed blocks and the final remainder.
The observed 2021 whole-file digest uses the map's algorithm and is checked separately.

The tree pass publishes `windows.msix-blockmap-checks`. It anchors each source to its
captured source digest and its containing logical directory within the immediate
parent-container namespace. It requires complete enumeration and unambiguous names
and directory spellings before binding targets. It does not read neighboring host
files or cross into another supplied archive. Re-read target bytes are frozen and
must match the report's captured SHA-256 before size or content comparisons are made.

Each result records the target and its captured digest, size agreement, checked/failed
blocks, bounded failure witnesses and an independent optional whole-file hash check.
Missing targets, incomplete listings, stale bytes and unsupported profiles remain
unresolved; they are not content mismatches. Info findings summarize agreement and a
fixed High rule records actual size/content-hash disagreement, with expected/computed
values as evidence. Neither finding identifies when or which part changed. Standalone
block maps receive a bilingual opening description.

Within this content-layer fact, `package_signature_checked`, `zip_structure_checked`,
`compressed_block_sizes_checked` and `windows_trust_checked` stay false. Original ZIP
records have a separate result described below. Manifest facts also make their
unverified authentication/ZIP-signature scope explicit. A matching map is not package
authentication.

## Original ZIP records

`windows.msix-zip-layout` on the original container checks a bounded, contiguous,
single-disk ZIP32/ZIP64 profile. The original bytes must match the captured container
digest. The block map must be the canonical immediate `AppxBlockMap.xml` child of a ZIP
container; its raw stored/DEFLATE stream is decoded with explicit byte and stream-end
limits, CRC checked, and bound to both the captured child digest and declaration source.
Extracted folders or standalone maps do not acquire this result without original bytes.

The reader checks central-directory counts and extents, ZIP32/ZIP64 end correspondence,
local/central names, extraction versions, methods, flags, sizes and CRC fields. Local
file records cover the whole pre-directory region without prefixes, unexplained gaps
or overlaps. Descriptors with or without their signature, and 32/64-bit sizes, are
checked against the directory. Stored and DEFLATE are the supported methods; encrypted
or other flag profiles, non-ASCII or noncanonical relative names, repeated names and
ASCII case duplicates remain unresolved. Unknown extra-field bodies stay opaque;
ZIP64 values are read only for required sentinel fields. No name becomes a host path.

For each supported map path, the physical header length and central uncompressed size
are compared with `LfhSize` and `Size`. Fixed High findings record actual differences
with map positions and original byte offsets. This does not identify their cause.
Header correspondence is separate from the content layer's complete-tree target binding;
it does not claim Windows filename semantics or that every payload has been captured.
The original-record reader does not compute every payload CRC or establish compressed
block boundaries, signatures, publisher consistency, Windows trust or installability.

Limits are 256 MiB per package, 512 MiB of original bytes across at most 32 maps,
16 MiB per directory and 16,384 entries. Raw map decoding is bounded to 8 MiB plain /
16 MiB compressed. At most 4,096 mapped files are compared, with 128 physical records
and six discrepancy examples published per map. Unsupported, stale, absent or exhausted
inputs produce an explicit limitation. The original-record profile is intentionally
narrower than ZIP and is not a general ZIP validity test.

## Physical block checks

`windows.msix-zip-blocks` is a third, separate result on the original container.
It uses the frozen original bytes and source-bound map from the record reader.
The shared distribution index must establish complete enumeration and an unambiguous
captured target in that same container. A bounded full-stream decode must reproduce
the captured target's size and SHA-256 before any physical block agreement is claimed.
No neighboring host file or installed package content is consulted.

Stored blocks have measured 64-KiB/remainder extents; any optional Size declaration
is compared with that measurement. DEFLATE blocks require positive Size declarations.
Each selected compressed segment is independently decoded with a bounded output and
must reproduce the corresponding bytes from full-stream decoding. Intermediate
segments are closed with an empty final marker for this independent check. A separately
stored remainder must itself decode to an empty final stream; its representation is
not limited to `03 00`. A final segment may instead include the original stream end.
Both full and independent decoders require exact input consumption, exact output size
and a completed stream. Cross-block dictionary or other nonrestartable profiles remain
unresolved, even when full-stream content decoding succeeds.

Block hashes, optional whole-file hashes and the mapped payload CRC are then compared
independently. The result records physical offsets/lengths, captured target binding,
expected/computed hashes, measured terminator size and bounded witnesses. The Info
rule counts files with matching blocks and digests. Fixed High findings cover proven
extent overshoots, stored-size disagreements and hash/CRC disagreements. A missing
Size, unsupported boundary, stale/missing/ambiguous target or exhausted budget is an
explicit limitation, never an inferred mismatch. The aggregate distinguishes
`files_with_matching_blocks` from `files_with_verified_block_spans`; a digest mismatch
can coexist with independently verified physical spans.

This layer caps files at 64 MiB plain / 128 MiB compressed, compressed segments and
separate empty remainders at 256 KiB. Across maps it permits 4,096 file attempts,
32,768 blocks and 512 MiB of decode work, charging both compressed and plain bytes
for the full and independent passes. Result records have an 8-MiB shared budget,
with at most 128 records per map, eight initial/failing witnesses per file and six
evidence examples per outcome. Omission counts and limitations expose reduced output.
The record-only fact retains its false compressed-block flag; this separate result
states which files actually received completed physical checks. Neither layer verifies
unmapped footprint payloads, package/bundle signatures, Windows trust or installability.

## Signature declarations and original-byte binding

`windows.msix-signature` reads P7X extensions or the `PKCX` prefix, including standalone
signatures. It requires one bounded definite/minimal DER CMS object, the supported
SpcIndirectDataContent/SIP subject identifier and version, SHA-256 package digest
algorithm, and an exact APPX capsule with unique AXPC/AXCD/AXCT/AXBM declarations and
optional AXCI. Unknown/duplicate labels, missing required records, trailing data,
unqualified SIP fields and other capsule/hash profiles remain unread with a limitation.
The capsule is read from its ASN.1 field; the analyzer does not scan for an APPX marker.

CMS checking reuses the strict catalog envelope primitives with an explicit expected
content type. Digest algorithm declarations, signer-certificate uniqueness, signed
attribute cardinality/order/content type, content digest and RSA/ECDSA mathematics
are separate checks. Embedded-chain observations are retained but do not establish
Windows trust. Missing/ambiguous keys or unsupported checks remain unresolved. P7X
inputs are at most 4 MiB; the shared preflight bounds ASN.1 depth to 32 and nodes to
250,000, with certificate/signer/attribute limits before cryptographic work. Published
facts are capped at 8 MiB, with the existing credential redaction applied to strings.

`windows.msix-signature-binding` on the original container requires the raw P7X bytes
to match both the captured child digest and its signature-declaration source. For the
checked final-signature-record profile, AXPC covers all local records before P7X.
AXCD is computed over the directory without its final signature entry and the restored
unsigned ZIP32/ZIP64 end records: entry counts, directory size/offset and ZIP64 locator
are adjusted. Comments are preserved. Prefixes, overlaps and unsupported ZIP layouts
have already been refused by the record reader; nonfinal signature placement remains
unresolved for the affected region comparison. This initial placement profile is not
a general signer-reconstruction algorithm for arbitrary ZIP layouts.

AXCT, AXBM and optional AXCI compare captured original uncompressed footprint bytes,
with bounded stream decoding and CRC checks. Each digest has its own expected/computed
values and agree/mismatch/unresolved state; one unread footprint does not erase other
comparisons. The footprint read/decode budget is 512 MiB across packages, with the
record reader's 8-MiB plain / 16-MiB compressed per-footprint limits. Missing signatures,
uncaptured/stale P7X children, unestablished CI coverage and exhaustion remain explicit.
Agreement with an unauthenticated digest declaration is never promoted to authentication.

Info findings report declared digest agreement or successful CMS mathematics separately.
Fixed High rules report proven package-digest differences or CMS content/signature
failures, without attributing a cause/time. `all_declared_package_digests_agree` and
`cms_signature_verified` are independent facts. Publisher/certificate correspondence,
code-signing policy, timestamp policy, revocation, system trust and installability are
not checked. Existing content/record facts retain their scoped false signature flags.

## Content limits and name ambiguity

The XML input is at most 8 MiB and 100,000 nodes; declarations are bounded to 4,096
files, 32,768 blocks, 8-KiB logical file names and 8 MiB of serialized facts per map.
The format's larger Unicode-name space is not claimed by this initial name-binding
profile. Hash declarations are limited before base64 decoding; integers are checked
unsigned decimals. A size does not drive an unchecked allocation.

Tree work considers at most 32 maps. Across them, comparison budgets are 4,096 file
attempts, 32,768 blocks, 512 MiB of payload bytes and 8 MiB of comparison records;
one payload is at most 64 MiB. At most eight failing blocks per file and six evidence
examples per outcome are retained, with omission counts. The shared input index has
its own file/path/directory-prefix limits. Exhaustion is explicit.

ZIP 9.7 exposes duplicate central-directory names but collapses their records.
`zip.entry-names-duplicated` now reports that unread versions remain, and marks the
container listing incomplete. Name-based checks refuse that namespace, even when the
retained bytes happen to match a declaration. This does not implement a replacement
ZIP reader that retains every duplicate version. Other formats' duplicate retention
and ASCII-case alias checks continue independently.

## Native and independent samples

`windows-msix-fixtures.py` builds three unsigned project packages with SDK
10.0.26100.0 (MakeAppx reports version 10.0.26100.8249): compressed SHA-256/384 and
uncompressed SHA-512. Each contains six mapped files, including an empty file,
generated PNGs, the existing hello.exe fixture and a 65,543-byte data payload.
No input is executed or deployed. Their native reference JSON records names, sizes,
header sizes, block digests, native compressed/block sizes and ValidateFileHash results.

The independent sample is Microsoft's `src/test/testData/unpack/TestAppxPackage_Win32.appx`
from [msix-packaging](https://github.com/microsoft/msix-packaging) at commit
`25a65f5c1690930813bcc10cdf1d59fa865f2bb1`, MIT License, copyright 2018 Microsoft.
Its unchanged bytes have SHA-256
`c478a36cf7c00f0fcacb004b85a97cf1b6168b4da35c66b3b101b2194874a909`.
It contains eleven mapped files. The source/license and test-only use are recorded in
NOTICE and `LICENSE-msix-packaging.txt`; no private signing key is included or imported.
Its existing signature is not verified by this content-layer increment.

The native declaration and byte comparisons cover 23 cases: six for each generated
profile and five for the older Microsoft sample, which has no FileHash extension.
They distinguish unchanged input, same-size changed payloads, altered block digests,
missing payloads and duplicated ZIP names; modern profiles add altered whole-file
digests. Every case repeats JSON byte-for-byte, checks unchanged inputs and renders
English Markdown/HTML; each profile also checks Chinese Markdown. Portable pipeline tests compare all native
declarations; engine tests cover actual ZIP children, namespace separation, aliases,
tampering and standalone maps. Constructed tests also cover malformed XML, encodings,
overflow, stale digests, credential redaction, empty files and each work budget.

One native API observation is deliberately kept separate: on these modern SDK inputs,
`IAppxBlockMapFile::ValidateFileHash` returned true after changing only a Block hash
when the FileHash still matched. Native GetHash declarations plus independent Python
SHA-2 calculations showed that block's mismatch. The analyzer checks both declarations
and records the difference. This is not a claim about Windows package installation or
signature acceptance; the API's whole-file result is not a package-authentication result.

Local records are `out/windows-baseline/msix-final-*/checks.json`. Native references
use only explicitly supplied files and read-only AppxPackaging streams, never the
installed package store. The reference helper does not download inputs.

Local format, workspace Clippy, locked dependency resolution, the no-default-feature
CLI build and full workspace tests passed. This includes 44 engine integration tests,
85 Windows unit tests (one native helper remains ignored), 53 Windows pipeline tests
and the complete damaged-fixture run. The full log is
`out/windows-baseline/workspace-msix-blockmap.log`. That commit's three core CI platform
jobs and licence check passed; one Chromium frame-loading race was fixed separately.
All five jobs passed for the fix in run
[44875658966](https://github.com/atomsprout/analyze-anything/actions/runs/44875658966).

The original ZIP record increment adds constructed ZIP32 and four descriptor-width
cases, malformed offsets/counts/extra fields, damaged/truncated records, stale or absent
original bytes, and native ZIP64 samples. SDK MakeAppx 10.0.26100.8249 unpacked all four
original packages without `/nv` and returned zero; no package was installed or run.
The new layout helper compares Python's independent ZIP header offsets/sizes with the
report across four originals and four deliberately changed LfhSize declarations.
Each changed declaration yields exactly one header mismatch; reports repeat byte for
byte and inputs remain unchanged. Repacked negatives are not native-qualified MSIX
packages and do not isolate the cause of any native acceptance decision. Records are
`out/windows-baseline/msix-zip-layout-final/checks.json`. English Markdown/HTML and
Chinese Markdown also expose the new bilingual rules. Format, workspace Clippy,
locked dependency resolution and the no-default-feature CLI build passed. The full
workspace test run, including the 294-second damaged-fixture test, is recorded in
`out/windows-baseline/workspace-msix-zip-layout.log`; after the final version/name and
evidence refinements, all five ZIP unit tests and both MSIX engine tests were rerun
successfully, followed by the native helper on the rebuilt CLI. Cross-platform CI for
the ZIP-record increment passed in all five jobs of run
[44876877130](https://github.com/atomsprout/analyze-anything/actions/runs/44876877130).

For the compressed-block step, an independent bounded Python probe checked the
13 mapped DEFLATE streams across these four packages, including empty streams. Their
declared block sizes cover all compressed bytes except a final `03 00`; each declared
segment, with that terminator appended, independently decodes to its corresponding
64-KiB block/remainder. The implemented checker now establishes those properties from
original bytes rather than assuming them. Constructed cases additionally cover an
empty stored final block and a terminator included in the last declared segment.
Local observations are `out/windows-baseline/msix-zip-block-spans.json`.

The raw-block helper now compares 27 original/declaration/profile cases using original
payload streams preserved in constructed ZIP32 wrappers. Cases include changed block
hashes, extent overshoots, missing Size attributes, shifted boundaries, alternate empty
final streams and terminators included in the last segment. Python independently
checks successful original/variant spans with zlib and hashlib; live AppxPackaging
GetHash/GetCompressedSize declarations are compared with report witnesses. Its
ValidateFileHash decision remains a separate recorded observation: on the SHA-256/384
fixtures it again accepted the changed block hash when the payload's whole-file hash
matched. The raw checker still records that block's independently proven mismatch.
Constructed wrappers are not package signature or installation qualification.

All 27 cases repeat JSON byte for byte and preserve inputs; English Markdown/HTML and
Chinese Markdown expose the new rules. Records are
`out/windows-baseline/msix-raw-blocks-extended/checks.json`. The full workspace test run
is `out/windows-baseline/workspace-msix-raw-blocks.log`, including 53 Windows pipeline
tests and the complete damaged-fixture run. After the final empty-stream extension,
all 95 Windows unit tests passed (one native fixture helper is intentionally ignored),
as did all 45 engine integration tests, workspace Clippy and the no-default-feature
CLI build. This includes a portable regression that preserves native compressed
payloads while changing map declarations. Cross-platform CI for this increment
passed in all five jobs of run
[44878595483](https://github.com/atomsprout/analyze-anything/actions/runs/44878595483).
W6 remains open.

The signature increment uses the pinned Microsoft APPX's embedded RSA-2048/SHA-256
signature as its independent real sample. Windows CryptoAPI `CryptMsgControl` with
`CMSG_CTRL_VERIFY_SIGNATURE` checks message mathematics against its embedded public
certificate in memory. No certificate is installed, no trust provider/chain/revocation
lookup is used, and no package/code is installed or run. Five cases compare original
bytes, central metadata only, local+central metadata, a changed CMS signature value
and a changed capsule digest. The respective package mismatch counts are 0, 1, 2, 0,
1; CMS succeeds in the first three and fails in the last two, agreeing with CryptoAPI.
Independent Python region/footprint hashes match the report's five digest records.
All cases repeat JSON byte for byte and preserve inputs, with English Markdown/HTML
and a separate Chinese standalone P7X report. Records are
`out/windows-baseline/msix-signature-final/checks.json`. Constructed DER, malformed
capsules, truncation/corruption, unknown keys, ZIP32 comment preservation, nonfinal
signature placement and footprint budgets have portable tests. Other SIP versions,
digest profiles, modern independent signers/bundles and signer-policy cases still need
their own samples and native references.

Local format, workspace Clippy, locked dependency resolution and the no-default-feature
CLI build passed. The full workspace run is recorded in
`out/windows-baseline/workspace-msix-signature.log`, including the complete damaged
corpus and 53 Windows pipeline tests. After the final independent DER-test helper and
stale-source cases, all 101 Windows unit tests passed (one fixture-generation helper
remains intentionally ignored), as did all 45 engine integration tests. The CMS reuse
also retains the existing catalog regressions. All five jobs passed for this signature
increment in run [44880651282](https://github.com/atomsprout/analyze-anything/actions/runs/44880651282).
W6 is not complete. The next [manifest increment](windows-msix-manifest.md) establishes
bounded namespace/path and ambiguity projections plus literal dependency/device-family
declarations; it does not validate the whole schema or compare publisher certificates.

## Remaining W6 gates

Broaden physical block/ZIP profiles and independent large-file coverage; establish package/bundle
signature/bundle coverage beyond this initial profile and publisher consistency; broaden
manifest namespace/extension/schema coverage, then model bundle architecture/resource
coverage, supported dependency resolution, target-device relationships and appinstaller references. Add
broader Unicode/alias, large-file, alternate-extension and independently signed/bundled
samples with their native references. None of these gates is closed by content agreement.

References: Microsoft [BlockMap](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-blockmap),
[File](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-file),
[Block](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-block),
[GetHash](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nf-appxpackaging-iappxblockmapblock-gethash)
and [ValidateFileHash](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nf-appxpackaging-iappxblockmapfile-validatefilehash),
PKWARE's [ZIP specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT),
and [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951). Signature references include the
pinned Microsoft [digest capsule definitions](https://github.com/microsoft/msix-packaging/blob/25a65f5c1690930813bcc10cdf1d59fa865f2bb1/src/inc/internal/AppxSignature.hpp),
and Microsoft's [CryptMsgControl](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol).
