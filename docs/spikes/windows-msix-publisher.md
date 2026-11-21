# MSIX publisher correspondence

This W6 increment compares the unique qualified manifest identity's literal Publisher
with the subject spelling of a uniquely verified embedded CMS signer. The source P7X,
manifest and block-map declarations are bound to captured original bytes. It adds no
OS calls, network calls, certificate-store access or trust provider to analysis.

## Comparison profile

The pinned Microsoft MSIX SDK derives the signing subject with
`CertNameToStrW(X509_ASN_ENCODING, Subject, CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG)`
and passes it to `IAppxManifestPackageId::ComparePublisher`. Native probes on this Windows
host distinguish case, spacing, unnecessary quotes and `S` versus `ST`. Generic DN
normalization would erase differences observed in that API; it is not used.

The portable `windows-x500-reverse-qualified-v1` profile reverses RDN groups while
preserving ordered multi-valued sets. It uses fourteen fixed standard aliases,
UTF8String, ASCII PrintableString/T61String/IA5String and bounded UTF-16BE BMPString.
Required punctuation/edge-space quoting and doubled embedded quotes follow checked
native output. Unknown OIDs, non-ASCII legacy strings, controls, non-ASCII edge
whitespace, invalid DER, excessive sizes/counts and subjects requiring redaction remain
unresolved. This deliberately does not depend on the host's OID registry or locale.

The limits are 16 KiB subject DER, 32 RDN groups, eight attributes per group and 8 KiB
spelling. Missing/ambiguous signers or identities, unsupported subject formats, stale
captures and exhausted original-footprint budgets select no first candidate.

## Separate claims

`windows.msix-publisher` records the literal comparison, certificate/subject and source
digests, and independently whether manifest content is covered by the verified CMS
capsule's AXBM digest and signed block-map content hashes. A changed manifest can yield
a known literal difference while signed coverage remains unestablished. Matching
strings alone cannot establish signed manifest coverage. Other package-region digest
failures do not erase a separately established manifest-content relationship.

Info correspondence and High mismatch findings carry both literal values and certificate
evidence. Unperformed comparisons and missing signed coverage have explicit limitations.
The package binding fact summarizes these results; standalone P7X still has no manifest
comparison. No result establishes full schema validation, certificate validity/EKU or
other policy, timestamp policy, revocation, Windows trust or installation eligibility.

## Evidence

`windows-msix-publisher-check.py` reproduces 38 committed constructed subject references
with read-only Crypt32 calls, checks six literal `ComparePublisher` probes, obtains the
real fixture subject from CryptoAPI and compares its spelling/digest with the analyzer.
Four controlled package cases exercise repackaging, altered Publisher, duplicate identity
and changed CMS signature. JSON is checked twice and every input is checked unchanged.
The existing five-case signature comparison also passes with the new publisher results.
Local records: `out/windows-baseline/msix-publisher-reference/checks.json` and
`out/windows-baseline/msix-signature-publisher/checks.json`.

Portable tests cover all subject references (including explicit exclusions), truncation,
invalid/empty/oversized names, redaction, RDN/attribute/output budgets and BMP decoding.
Source-binding tests reject stale captures, ambiguous signers and identities, unsupported
subject projections and cross-container inputs, while keeping missing signed-map coverage
separate. Engine cases also cover `S`/`ST`, changed
manifest content with unchanged Publisher, ambiguity and invalid CMS. One licensed
Microsoft RSA-2048/SHA-256 APPX supplies the real certificate; broader real-world
certificate encodings and signature profiles remain open. W6 is not complete.

Local format, workspace Clippy and the no-default-feature CLI build passed. The full
workspace run is `out/windows-baseline/workspace-msix-publisher.log`, including the
complete damaged-fixture corpus, 46 engine integration tests, 109 Windows unit tests
(one fixture-generation helper intentionally ignored) and 54 Windows pipeline tests.
After adding the final redaction/budget/source-binding cases and four encoding
references, all 27 selected MSIX unit tests and both selected MSIX pipeline tests passed;
workspace Clippy and format checks passed again. Cross-platform CI remains the next gate.

All five CI jobs subsequently passed for commit `2dba89f8a24f0d99203e4f4b4e88cbd37666e9d8`
in [run 44885732035](https://github.com/atomsprout/analyze-anything/actions/runs/44885732035).
The [bundle increment](windows-msix-bundles.md) extends the same comparison to a unique
canonical bundle manifest and its signed block-map content, while refusing ambiguous
package/bundle manifest alternatives.

## Sources

- Microsoft [CertNameToStrW](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certnametostrw)
  and [ComparePublisher](https://learn.microsoft.com/en-us/windows/win32/api/appxpackaging/nf-appxpackaging-iappxmanifestpackageid-comparepublisher).
- Pinned SDK [signature subject formatting](https://github.com/microsoft/msix-packaging/blob/25a65f5c1690930813bcc10cdf1d59fa865f2bb1/src/msix/PAL/Signature/Win32/SignatureValidator.cpp)
  and [package publisher comparison](https://github.com/microsoft/msix-packaging/blob/25a65f5c1690930813bcc10cdf1d59fa865f2bb1/src/msix/unpack/AppxPackageObject.cpp).
