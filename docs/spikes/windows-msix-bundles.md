# MSIX bundle declarations and original-package relationships

This W6 increment reads the base 2013 bundle namespace and relates its declared packages
to captured original ZIP bytes, supplied nested packages and their qualified manifests.
It adds no unpacker, installation, host-architecture selection, dependency fetching or
native API call to analysis. Existing ZIP extraction supplies the children.

## Declarations

`windows.msix-bundle` records source SHA-256, schema version, identity alternatives,
application/resource package fields, architecture/resource identifiers, original offset
and size declarations, and resource qualifiers. Expanded namespaces and direct hierarchy
paths are checked. Repeated identities select none; repeated Packages sections or
colliding file declarations invalidate reusable rows. Missing, redacted, excessive,
unsupported or unread data produces explicit projection issues and omission counts.

The reader supports strict UTF-8/UTF-16 decoding with compatible declarations, no DTDs,
8 MiB XML, 100,000 XML nodes, 8 KiB fields, 1 MiB selected text, sixteen identities,
1,024 packages, 200 resource rows per package, 64 detailed issues and 8 MiB output.
The reader also projects up to 128 target-device rows per package in the 2018
dependency namespace. Optional bundles, flat bundles and other extensions retain
explicit limitations. The producer-built schema-5 fixtures exercise the base package
declarations and 2018 device-family extension.

## Original bytes and inner packages

`windows.msix-bundle-checks` binds the canonical `AppxMetadata/AppxBundleManifest.xml`
to its original stream and captured digest. It requires a complete original ZIP listing,
canonical stored inner packages, matching CRC/SHA-256 and captured ZIP children. The
inner canonical AppxManifest is independently decoded from those original package bytes
and bound to its captured declaration source. Reusable unique identities are required.

Checks compare data offsets (not local-header offsets), sizes, bundle Name/Publisher,
the package row's Version/Architecture/ResourceId, and the nested ResourcePackage type.
Version quads are compared numerically; the bundle's own version is not substituted for
an inner package's version. Defined neutral/empty defaults and the default application
type are applied only in the separate comparison. Unread/ambiguous ResourcePackage
semantics remain a partial result. Both observed and declared values are retained.
Known physical differences remain visible even when an inner package or its identity
cannot be read; the unresolved relationship and its reason are recorded separately.

UTF-8 OPC filename escaping identifies archive parts without becoming a host path.
Noncanonical percent aliases, encoded traversal/separators, collisions, stale captures,
compressed packages, missing original packages and incomplete nested extraction do not
select a first candidate. Original undeclared package parts are separately listed with
redaction and an omission count. Stored packages are the initial physical profile;
full resource-qualifier correspondence is not inferred from a declared architecture
or language. No installed state or external file is consulted.

Raw ZIP limits are inherited (256 MiB per original package and 16,384 entries). This
pass limits sources to 32, artifacts to 100,000, original reads to 512 MiB, nested
package/manifest work to 512 MiB, individual comparison output to 8 MiB and total
comparison output to 16 MiB. Findings retain six representative record witnesses.

## Separate signed coverage

The SHA-256 SIP reader now distinguishes APPX from APPX-bundle subject identifiers.
The latter GUID, `0f5f58b3-aade-4b9a-a434-95742d92eceb`, was checked with Windows
`CryptSIPRetrieveSubjectGuid` on the pinned signed sample and its bounded signed
content. The container binding requires the SIP kind to match one canonical package
or bundle manifest. A standalone P7X does not establish the surrounding container.

For a stored inner package bound to original bytes, bundle signed-byte coverage is
recorded only when the outer CMS mathematics and declared original package-region/
footprint digests agree. The supported AXPC prefix includes the package's original
data. Qualified publisher correspondence uses the canonical bundle identity, and
signed manifest content remains independently linked through AXBM. No requirement for
separate internal package signatures is inferred. Coverage is not Windows trust or a
certificate/installation-policy result.

## Samples and comparisons

The owned `native-msix-bundle.appxbundle` is built by
`windows-msix-bundle-fixtures.py` with MakeAppx 10.0.26100.0. It has an x86 application
and a neutral Chinese-language resource package, both version 1.0.0.0, under bundle
version 2.0.0.0. SHA-256: `e3df18f623af11b634325d152e6fa3790352c309fcfa7e00fd7cbeab573aa503`.

Upstream fixtures are unchanged bytes from
`microsoft/msix-packaging/src/test/testData/unpack/bundles/` at
`25a65f5c1690930813bcc10cdf1d59fa865f2bb1`, under MIT (see [NOTICE](../../NOTICE)).
The local `upstream-` prefix is omitted below; SignedUntrustedCert is the upstream
`SignedUntrustedCert-CERT_E_CHAINING.appxbundle`. Its name is not a trust evaluation
performed by this analyzer.

| Fixture stem | SHA-256 |
|---|---|
| BundleWithIntlPackage | `a4ece5d8d007c17e064690853f5dfc7a4e17b77e5901ebced74c7ed9e30dfa6f` |
| SignedUntrustedCert | `e93dc46a715c6d71a922418075f61ed9f828c1d0c74a826aa17feb8589385ca3` |
| ManifestPackageHasIncorrectArchitecture | `fa832c96b3d6f573b7b647544b511ea14f10b46c79124e423850f0bc21b5716a` |
| ManifestPackageHasIncorrectSize | `7494e35e1c9b56da406ddb8a78f77793a9f413bbc2fa8317a9f1d7a9b3271883` |
| ManifestPackageHasInvalidOffset | `2cc55baa16171d93d457ec8d7cb5083b474a60e815470c2b7dc69ec55bf48d7f` |
| ManifestHasExtraPackage | `8a6f66b3b8d476bf486994c0deec85998d3c6a986400fed1d92b4fc46a7eac33` |
| PayloadPackageNotListedInManifest | `eeccdecd25f8e20ea649915b29244c830e62752bd58d5f1c35db79cc54e214cc` |
| PayloadPackageIsCompressed | `9a0b2df723bd58ea8b9909afe50aad0c887ddb979630b988559ef7eb46d5560d` |

`windows-msix-bundle-check.py` compares three originals with read-only native bundle
manifest/package/resource APIs, raw ZIP positions and CryptoAPI signature mathematics.
Portable pipeline tests compare the three committed native references, including
internationalized OPC names and separate bundle/package versions. Six independent
negative bundles distinguish field differences, absent declarations/targets and
compressed packages. Two controlled mutations distinguish changed inner ZIP bytes
(CMS passes; AXPC and AXCD differ) from a changed outer signature value (CMS fails;
package digests still agree). Package correspondence remains known in both mutations,
while signed-byte coverage is unestablished. Every case repeats JSON and preserves
inputs, with English Markdown/HTML and a separate Chinese mismatch report. The local
native record is `out/windows-baseline/msix-bundle-complete/checks.json`.

Constructed tests cover namespaces, identity/package cardinality, UTF-16/declaration
conflicts, DTD refusal, redaction, count/text/node limits, numeric overflow and OPC
aliases/traversal.
The first revision's native resource references covered language declarations. The
follow-up below expands reference coverage to scale, DirectX and escaped-space names.

The full workspace run passed in `out/windows-baseline/workspace-msix-bundles.log`,
including the complete damaged-fixture corpus, 48 engine integration tests, 114 Windows
unit tests (one fixture-generation helper intentionally ignored) and 55 Windows pipeline
tests. The final regression retaining known physical differences with an unreadable inner
package then passed among all 49 engine integration tests in
`out/windows-baseline/msix-bundle-engine-final.log`. Windows unit/pipeline tests were
also rerun in `out/windows-baseline/msix-bundle-windows-final.log`. Final workspace
Clippy, format and no-default-feature CLI build passed, followed by the eleven-case
native comparison and bilingual report checks. All five CI jobs passed for
`2ba07b3e75fef8148d9721633139258ad8e27061` in
[run 44888484018](https://github.com/atomsprout/analyze-anything/actions/runs/44888484018).

## Resource and device declarations

The follow-up compares independently bound bundle and inner XML declarations. It
reads unqualified bundle qualifiers and the qualified `Scale` and `DXFeatureLevel`
attributes in the inner Windows 10 or 2010 manifest. Resource comparison uses sets
of ASCII case-folded language tags, SDK scale values and DirectX levels. Default
language order, alias resolution and fallback are outside this profile. Repeated,
redacted, foreign, incomplete and build-placeholder rows remain unresolved.

Direct `Dependencies/TargetDeviceFamily` in the 2018 bundle namespace supplies
literal device-family names, minimum versions and maximum tested versions. Numeric
version quads compare independently of spelling and declaration order. The
`not-declared` result preserves the distinction between an older bundle with no
such declarations and an unqualified or unread section. Maximum tested versions
are reported as declared test targets. Package identity, resource declarations,
target-device declarations and signed-byte coverage have their own results.

MakeAppx 10.0.26100.0 built `native-msix-qualifiers.appxbundle` with an x86 app,
language, scale and DirectX resource packs, two device families and escaped-space
package names. SHA-256 is
`164d149b93b35a822be3544696c019607418b376108d98db0eee60c151b61f95`.
`windows-msix-declarations-check.py` compared four originals with the native
bundle and inner manifest readers and checked fourteen controlled variants.
Windows rejected duplicate resources, foreign resource/family elements and a
missing tested version with HRESULT `0x80080204`. The manifest reader enumerated
the duplicate device-family case, while the analyzer leaves that comparison
unresolved. Resource sets and target-device versions have portable regression
tests against the checked-in native snapshots. The native run is recorded in
`out/windows-baseline/msix-declarations-native/checks.json`.
The final workspace test log is
`out/windows-baseline/workspace-msix-declarations.log`. It includes 51 engine
integration tests, 118 Windows unit tests, 55 Windows pipeline tests and the
damaged-fixture corpus. Workspace Clippy, formatting and the no-default-feature
CLI build also passed.

References: Microsoft [package resource qualifiers](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-resource)
and [bundle target-device declarations](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-targetdevicefamily).

## Sources

- Microsoft [Bundle](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-bundle),
  [Identity](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-identity),
  [Package](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-package)
  and [Resource](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-resource).
- [IAppxBundleManifestPackageInfo](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nn-appxpackaging-iappxbundlemanifestpackageinfo)
  and [CryptSIPRetrieveSubjectGuid](https://learn.microsoft.com/en-us/windows/win32/api/mssip/nf-mssip-cryptsipretrievesubjectguid).
- Pinned SDK [base schema](https://github.com/microsoft/msix-packaging/blob/25a65f5c1690930813bcc10cdf1d59fa865f2bb1/resources/AppxPackaging/Manifest/Schema/2015/BundleManifestSchema2013.xsd)
  and [bundle reader](https://github.com/microsoft/msix-packaging/blob/25a65f5c1690930813bcc10cdf1d59fa865f2bb1/src/msix/unpack/AppxBundleManifest.cpp).
