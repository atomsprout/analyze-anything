# MSIX manifest namespace and declaration projections

This is initial W6 manifest work, not full XSD validation, package authentication,
dependency resolution or Windows installation qualification. The source is read only.
The integrity layers retain their separate [scope](windows-msix-integrity.md).

## What is projected

`AppxManifest.xml` must use the Windows 10 foundation namespace or the supported
2010 manifest namespace. Identity comes only from a direct `Package/Identity` in that
namespace. Only supported unqualified attributes participate in the identity
projection; unknown or namespaced attributes leave the declaration unsupported.
Foreign or nested identity-like elements remain unread issues. Both prefix spelling
and document order are irrelevant to selecting the qualified direct declarations.

`windows.msix` now records the original source SHA-256, namespace and an explicit
identity status. One supported direct declaration establishes `identity`; missing,
unsupported or repeated declarations leave it null. Repeated identical declarations
are still ambiguous. `identity_declarations` preserves bounded separate records and
omission counts. Required nonempty fields, quad versions with unsigned-16-bit parts,
supported architecture spellings, simple structure and known attribute namespaces
are checked before establishing that projection. Windows name/publisher policy and
the full schema are not inferred from it.

Properties, capabilities, applications and extensions are read at known namespace/
hierarchy paths. Capability names retain namespace-qualified declaration records;
unknown capability namespaces do not produce known broad-capability observations.
Duplicate scalar properties do not choose a first display name. Application IDs,
dependency names, device-family names and repeated sections retain their declarations
and mark affected projections incomplete. Multiple extension details do not select a
first protocol/alias/service name. The older summary arrays remain literal display
data; richer declaration records carry projection support and source positions.

The reader additionally preserves package dependency Name/Publisher/MinVersion and
MaxMajorVersionTested declarations, target-device-family Name/MinVersion/
MaxVersionTested declarations, resource language/scale/feature-level metadata and
selected properties. No target, executable, icon, PRI resource, external package or
installed-package store is opened. No host version comparison or package-default
resolution is performed. Namespaced optional/newer dependency fields and unqualified
profiles remain unread with an explicit issue rather than becoming required edges.

Unknown sections, attributes, nested behavior and extension namespaces remain explicit
`projection_issues`; for example the real corpus's build/phone metadata and visual
elements are not interpreted by this increment. `schema_validated` and
`references_resolved` remain false. A unique identity projection is an observation
about a particular declaration, not proof that Windows accepts the whole manifest.
Publisher/certificate comparison and bundle/resource coverage remain W6 work.

## Bounds and evidence

Text decoding is shared with block maps: strict UTF-8 (optional BOM) or BOM-marked
UTF-16, consistent XML encoding declarations, no host code page or replacement text.
Both XML parsers disable DTDs. Harmless comment/CDATA text resembling a DTD is data,
not an instruction or a reason to select a different parser.

Raw manifest input is at most 16 MiB, XML nodes 100,000, each captured text field
8 KiB, aggregate selected text 1 MiB and a published fact 8 MiB. Up to 16 identity,
64 scalar-property, 50 application, 200 capability/extension/resource and 128 combined
dependency/device-family candidates are retained. At most 64 detailed issues are
published, with omission counts. Candidate budgets include unsupported elements at
those paths so hostile names cannot bypass the work limit. Exhaustion and unknown
fields are visible; strings use the existing credential redaction. A redacted identity
cannot establish the reusable identity projection.

Positions explicitly use `decoded-UTF8-XML` offsets, including for BOM/UTF-16 inputs.
They are diagnostic XML positions, not asserted physical byte ranges in the original
file. Findings cite fields and captured source values. A re-read manifest differing
from its captured digest publishes no projection. No clock, host path, random value
or system state is added to reports.

## Native and portable evidence

The three existing SDK-built MSIX profiles and the pinned Microsoft test APPX were
read through AppxPackaging `IAppxManifestReader`, `IAppxManifestPackageId` and
`IAppxManifestReader3`, using read-only streams. Identity values, package dependencies
and target-device-family versions match. Optional native ResourceId null/empty values
are normalized only by the comparison helper; the analyzer retains absence. Reference
snapshots are `<package>.manifest.ref.json` beside the licensed package fixtures and
are checked by portable pipeline tests. Sources/licences are the existing entries in
[NOTICE](../../NOTICE); no new binary sample was introduced.

Five controlled variants add a foreign identity, a nested identity, repeated identities,
an unsupported root namespace or an out-of-range identity version. The native reader
rejected all five with HRESULT `0x80080204`. The analyzer deliberately preserves the
qualified declaration in the first two, with opaque-content limitations and no schema
validation claim. Repeated identities select none; unsupported roots publish no fact;
an unsupported version preserves its declaration without a reusable identity. This
distinction is recorded rather than described as native acceptance.

`windows-msix-manifest-check.py` checks the four originals and five variants, repeated
JSON, unchanged sources, English Markdown/HTML and Chinese conflict text. Local records
are `out/windows-baseline/msix-manifest-final/checks.json`. Constructed tests cover
namespace/path injection, duplicates, dependency constraints, literal resources,
UTF-8/16 and declaration conflicts, DTD refusal, CDATA, redaction, stale bytes, node/
field/aggregate/count/output limits and ambiguity. The 2010 namespace is constructed
coverage only; the four native samples use the Windows 10 foundation namespace.

Local format, workspace Clippy, locked dependency resolution and the no-default-feature
CLI build passed. The full workspace log is
`out/windows-baseline/workspace-msix-manifest.log`, including 107 Windows unit tests
passed (one fixture-generation helper intentionally ignored), 54 Windows pipeline
tests, 45 engine integration tests and the complete damaged-fixture run. Cross-platform
CI for this increment passed all five jobs in [run 44883557724](https://github.com/atomsprout/analyze-anything/actions/runs/44883557724)
at commit `398641c599384380ef9d184e619705d46a613322`. W6 remains open.

References: Microsoft [Package](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-package),
[Identity](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-identity),
[PackageDependency](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-packagedependency)
and [TargetDeviceFamily](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-f-targetdevicefamily).
