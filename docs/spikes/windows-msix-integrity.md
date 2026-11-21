# MSIX content declarations and verification

W6 remains open. This increment implements the block-map content layer required by
[PLAN-WINDOWS.md](../PLAN-WINDOWS.md), alongside the existing manifest reader. Package
and bundle models, ZIP/signature binding, dependencies and appinstaller references
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

`package_signature_checked`, `zip_structure_checked`, `compressed_block_sizes_checked`
and `windows_trust_checked` stay false. Local-header/compressed-size fields are preserved
declarations, not verified ZIP extents. Manifest facts also make their unverified
authentication/ZIP scope explicit. A matching map is not package authentication.

## Limits and name ambiguity

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
`out/windows-baseline/workspace-msix-blockmap.log`. Cross-platform CI is the next gate.

## Remaining W6 gates

Verify physical ZIP extents and compressed-block sizes; establish package/bundle
signature bindings, publisher consistency and manifest identity/namespace conflicts; model bundle architecture/resource
coverage, dependencies, target-device requirements and appinstaller references. Add
broader Unicode/alias, large-file, alternate-extension and independently signed/bundled
samples with their native references. None of these gates is closed by content agreement.

References: Microsoft [BlockMap](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-blockmap),
[File](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-file),
[Block](https://learn.microsoft.com/en-us/uwp/schemas/blockmapschema/element-block),
[GetHash](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nf-appxpackaging-iappxblockmapblock-gethash)
and [ValidateFileHash](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nf-appxpackaging-iappxblockmapfile-validatefilehash).
