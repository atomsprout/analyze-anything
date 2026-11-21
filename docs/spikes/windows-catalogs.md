# Windows catalog structure and cryptographic checks

Initial catalog increment of W5, 2026-11-20. W5 is still open. This reader establishes
what the supplied catalog declares and which supported cryptographic checks can be
made on it. The later [membership pass](windows-catalog-membership.md) records bounded
comparisons with supplied payloads separately, without claiming package completeness.

## Representation and boundary

`.cat` files are read in process as a Microsoft CTL inside CMS/PKCS#7 SignedData.
The `windows.catalog` fact retains the catalog subject algorithm, list identifier,
encoded sequence number when present, claimed update times, ordered CTL entries and
signer records. It distinguishes catalog-list v1/v2 subject identifiers. Version 1
hexadecimal UTF-16 reference tags can be decoded; v2 binary identifiers remain hex.

Supported member-info GUID forms and indirect-data attributes retain the literal SIP
subject GUID, data OID, digest algorithm and digest. Bounded CAT_NAMEVALUE attributes
also retain their name, unsigned flags and value length/digest. The checked
`0x10010001` profile exposes well-formed terminated UTF-16LE values as text.
Other flags/encodings remain opaque with a limitation. File and OSAttr legitimately
repeat the same CAT_NAMEVALUE OID; those repetitions do not invalidate an independent
member digest. Duplicate indirect-data or member-info declarations (including mixed
legacy/compact member-info types) still prevent an unambiguous digest binding.
Other attributes retain their OID, encoded length and SHA-256 with a partial-reading limitation.
Unknown source data is never interpreted as an executable, path or instruction.
Declared member digests are not described as verified payload coverage.

Catalog CMS checks use the existing certificate parsing, RSA PKCS#1 v1.5 and ECDSA
verification primitives, without changing the existing PE/MSI verification paths.
The catalog path separately validates the supported envelope shape, declared digest
algorithms and signature algorithm/key consistency. Required signed contentType and
messageDigest attributes must be present, unique and unambiguous. Signed attributes
must be DER ordered; duplicate or unsupported structures cannot become passed checks.
Signer identifiers must name one distinct embedded certificate. Identical repeated
certificates are deduplicated by fingerprint; conflicting certificates sharing an
identifier remain unresolved instead of selecting the first and reporting a false failure.

Per signer, the fact records signed-attribute/algorithm checks, the content digest,
the signature value and signatures of available embedded certificate links. A chain
ending in an embedded self-issued certificate is not Windows root trust. Certificate
validity dates come from input, and update/signing times are not compared with the
machine clock. Signer metadata is redacted before facts/evidence are published.

The cryptographic content is selected according to the encoded envelope: legacy direct
CTL sequences and primitive octet-string encapsulation are distinguished. Native
fixtures below cover legacy direct CTL sequences. Other encodings and algorithm variants
do not gain native-comparison status merely by sharing primitives with PE signatures.

The summary has evidence for content type, subject algorithm, declared/recomputed digests,
signature-field fingerprints and per-signer check results.
A fixed High-severity rule records an actual content-digest or signer signature-value
mismatch. Embedded certificate-link outcomes remain separate facts/limitations; chain
construction does not determine this catalog-integrity finding. Unsupported checks become limitations; nothing calls
the file safe, trusted or eligible for installation. A malformed catalog is unread,
not classified as unsigned. Readable catalogs without signer records keep that absence
explicit in the fact and summary count.

`payloads_checked` remains false for this file pass; supplied-byte comparisons are in
the separate `windows.catalog-membership` tree fact. `windows_trust_checked` and
`timestamps_verified` remain false. Unsigned CMS attributes are presence-marked but
not interpreted. Member data parameters outside the two supported hash profiles,
timestamps, nested-signature semantics, root trust, revocation, current validity, WHQL
policy and installation eligibility remain outside the conclusion. No host catalog
database, certificate store, registry or Driver Store is consulted by analysis. Native
development references are never invoked by the analyzer.

## Resource and encoding profile

- At most 16 MiB of input and 250,000 ASN.1 nodes, with nesting limited to 32.
- Definite, minimally encoded DER lengths/OIDs/integers and ordered universal SETs.
  BER indefinite lengths and unsupported representations become an unread limitation.
- Up to 16,384 CTL entries, 32 attributes per entry and one value for interpreted attributes.
- Subject identifier at most 512 bytes; list identifier 256; encoded sequence number 64.
- Up to 16 signer records/digest algorithms and 64 signed attributes per signer.
- At most 64 embedded certificates, 64 KiB per certificate and 1 MiB for their bag.
- Member digest at most 64 bytes. Unsupported algorithm semantics do not imply a match.

The shared DER/CMS helpers receive bounded data. The encapsulated CTL receives the same
node/encoding checks again before member interpretation. Malformed, unsupported and
exhausted cases produce `windows.catalog-unreadable` or `windows.catalog-partial`, with
the always-present `windows.catalog-scope` explaining remaining coverage.

## Native fixtures and reference results

The project-authored generator uses Windows SDK MakeCat/SignTool 10.0.26100.0 on the
available Windows x64 host. It includes a known text payload and the existing hello.exe
fixture by digest, then signs copies with an in-memory self-issued test certificate.
No source program is run. No certificate is added to a Windows store; the temporary
PFX is deleted in finally. The generated catalogs include only declarations and, in
signed cases, the public signer certificate. They are Apache-2.0 test data, recorded in
NOTICE. Regeneration changes producer-generated identifiers and signatures; fixed
checked-in bytes and SHA-256 references provide the portable regression inputs.

| Fixture | SHA-256 |
|---|---|
| native-catalog-v1.cat | 0a3c46e609bf8d53e91079a36baaaeaa55aba60aa0cb31af0d00602637c37661 |
| native-catalog-v1-unsigned.cat | 81a7109cbc12324390ac8a73d7f8ec9b91d8e287fd5352b24903f3f277a79787 |
| native-catalog-v2.cat | 7aa36456f40f34d9be1df20b08a6c9b234640270bea1f2ef2b2e99ee3014dad1 |
| native-catalog-v2-unsigned.cat | 8c1c9dbc75a42e2bb5f2aa1b8dad2f297847888f3231395d5d1450cd4378c7f0 |

`windows-catalog-check.py` uses read-only CryptCATOpen/CryptCATEnumerateMember and a
signature-only SignedCms reference. Native records agree on subject GUIDs and the
explicit digest declarations. Both signed catalogs pass content/signature checks;
changed-content and changed-signature copies fail the native combined check, while the
analyzer distinguishes which check failed. The CLI helper also checks repeated JSON,
unchanged source bytes, English/Chinese Markdown and HTML inclusion.

**Version 2 is not four payloads.** MakeCat writes four CTL entries for these two source
files: two SHA-256 indirect-data declarations and two compatibility identifiers. The
latter contain no indirect-data attribute in the file. CryptCATEnumerateMember supplies
synthesized SHA-1 indirect metadata for those compatibility records. The analyzer retains
the raw identifiers/GUIDs and leaves their absent digest fields null, instead of claiming
that synthesized API output was read from the catalog. The portable comparison checks
the two explicit digests separately from all four identifiers and subject types.

Constructed tests cover tampering, truncations, unsupported BER/DER/OID encodings,
non-ASCII GUIDs, duplicate/missing/excessive signed attributes, absent digest algorithm
declarations, ambiguous signer certificates, independent certificate-link corruption,
nesting/node/entry and certificate/signer budgets. Whole-engine fixture
mutations automatically preserve `.cat` names. New helpers use only controlled samples;
their corruption assumptions do not describe arbitrary third-party CMS layouts.

## Still open

The [membership increment](windows-catalog-membership.md) adds initial flat/default-PE
hash comparisons, six package layouts with explicit-catalog SignTool observations and
INF sibling-CAT associations. Still open are typed INF device/service/source-file
relationships; richer member attributes/data parameters and SIPs; broader CMS variants;
an independently distributed, licensed real driver-package corpus. These native-generated
fixtures are not an independent vendor package and do not close W5 or qualify Windows trust.

## Local verification

Nine new catalog unit/pipeline tests passed on Windows, including native snapshots,
content/signature/certificate-link mutations and ambiguous signer identity. Workspace
Clippy with warnings denied and the CLI build without default features passed. Native
CLI comparisons for both signed profiles passed again after the identity checks, with
six original/content/signature cases; an unsigned v2 CLI comparison also passed.
The local records are `out/windows-baseline/catalogs/v1-final-checks.json`,
`v2-final-checks.json` and `v2-unsigned-checks.json`.
`cargo fmt --all --check` and the final `cargo test --workspace` passed as well;
the complete local log is `out/windows-baseline/workspace-catalog-final.log`.
Cross-platform CI passed for catalog-reader commit
`f17729152445ab0abdcd9f3c738b73e1486173be`:
[run 44844928822](https://github.com/atomsprout/analyze-anything/actions/runs/44844928822).
The license job, Linux/macOS/Windows core checks and macOS desktop job all passed.
This precedes the separate supplied-member comparison increment.

The desktop sample was regenerated and 22 WebKit/Chromium cases passed three consecutive
runs (66 executions). A WebKit startup race in the drag/drop test was fixed by waiting
for the home view, which is rendered after backend event registration, before sending
the simulated event. This remains a stand-in backend check, not Windows native-window
or real drag/drop qualification. The browser log is `out/windows-baseline/catalog-browser.log`.

References: Microsoft's [MakeCat](https://learn.microsoft.com/en-us/windows/win32/seccrypto/makecat),
[CTL_INFO](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_info),
[CryptCATOpen](https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatopen),
[catalog members](https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-cryptcatmember)
and [SIP-dependent hashing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures).

## Repeated name/value attributes and independent driver input

The named v1/v2 MakeCat fixtures add two member attributes, File and OSAttr, using
`windows-catalog-fixture.ps1 -MemberAttributes`. Their checked-in reference snapshots
come from `CryptCATEnumerateAttr`; tests compare names, flags, value lengths/digests
and decoded text. Both signed profiles pass original/content/signature mutation checks
through the CLI and signature-only SignedCms, including repeated reports and bilingual
output. Constructed cases additionally cover duplicate hash/subject declarations,
bad encodings, unsigned-DWORD flags and name/value byte budgets. Names are limited to
1 KiB of BMPString content and values to 8 KiB, within the existing 32-attribute,
16 MiB input and ASN.1 node/depth limits. No attribute action is performed.

The independent pinned usbipd-win snapshot exposed the original repeated-OID problem.
Its attributes now agree with CryptCAT and its SYS digest agrees with the native SIP;
five supplied layouts are recorded in [the driver-corpus record](windows-driver-corpus.md).
Filename attributes are declarations only: this increment does not resolve a File
attribute into a missing/changed named member or choose installation paths. Compatibility
entries without explicit indirect digests remain unexpanded. Broader catalog metadata,
CTL extensions, flags, timestamp and trust profiles remain open.

Local format, workspace Clippy, the no-default-feature CLI build and full workspace
tests passed for this increment (including 78 Windows unit tests, 52 pipeline tests
and the complete damaged-fixture run). The full log is
`out/windows-baseline/workspace-catalog-name-values.log`. The two named native profiles'
CLI mutation records are under `out/windows-baseline/catalog-named-native`;
the independent package records are under `out/windows-baseline/usbipd-package-final`.
Cross-platform CI remains the next gate for this increment.
