Checks this program's results against the tools that ship with macOS and Windows: `codesign`,
`hdiutil`, `pkgbuild` on macOS; `Get-AuthenticodeSignature` and `makecab` on Windows.

They run in the "Native comparison" GitHub Actions workflow (started by hand), on machines that
have those tools. Each script prints one line per check and exits non-zero if any check failed.

    python3 tools/native-compare/macos.py   path/to/aa
    python   tools/native-compare/windows.py path\to\analyze-anything.exe

The Windows harness discovers the newest x64 SDK SignTool when it is not on PATH. Use
`--signtool <exe>` to select a particular SDK. `--sample <file>` can be repeated to replace
automatic discovery with explicit PE or MSI samples. For example:

    python tools/native-compare/windows.py target/debug/analyze-anything.exe --sample crates/aa-windows/tests/data/msi-signed.msi --record out/windows-baseline.json

`--record` writes a development JSON record with sample SHA-256 digests, analyzer version and
digest, native signature metadata, analyzer checks and limitations, and SignTool output.
It contains local paths and machine information: keep it outside the analyzed input and do
not treat it as a deterministic product report. Native trust failures are recorded separately
from cryptographic agreement; these checks do not establish offline behavior or verify catalog
membership. The default run still checks tampering and both generated CAB compression methods.

Run the reference-tool helper tests without an SDK:

    python -m unittest discover -s tools/native-compare -p test_windows_tools.py

Check supplied Windows shortcut relationships through the CLI, without activating shortcuts
or invoking a native resolver (also usable on other systems):

    python tools/native-compare/windows-reference-check.py --cli target/debug/analyze-anything.exe --output out/windows-baseline/references

This uses the pinned MIT LNK fixture and an explicitly supplied text sibling. It verifies
target/digest evidence, repeated reports, renamed-input comparison and English/Chinese/HTML
output. Optional AI interpretation is explicitly disabled when supported by the binary.

Compare a controlled INF fixture with read-only Windows SetupAPI and the CLI:

    python tools/native-compare/windows-inf-check.py --sample crates/aa-windows/tests/data/upstream-nullFilter.inf --reference out/windows-baseline/inf/checks.json --cli target/debug/analyze-anything.exe --output out/windows-baseline/inf/report

Omit `--cli` and `--output` to capture only the native reference. The helper opens the
explicit full path with SetupOpenInfFileW and reads sections/fields, without installing,
loading a driver or following Include/Needs. Native expanded fields are compared only
where the analyzer's conservative neutral projection is present. It checks repeated JSON
and unchanged input too. Source section names must be unique for this comparison; the
analyzer preserves repeated occurrences while SetupAPI merges them. See
[the scope and provenance record](../../docs/spikes/windows-inf.md).

The same helper checks available `windows.inf-declarations` graph records against their
source occurrence, line span and literal/neutral projection. Typed device IDs, service
fields, copy source/destination names and registry rows are checked separately; native
directory-ID expansion is never copied into the graph. `upstream-echo.inf` and
`native-inf-relationships.inf` add Models and shared-list cases. This is read-only field
evidence, not installation or host-platform selection. See [the graph profile](../../docs/spikes/windows-inf-relationships.md).

Strict comparison requires the native section set to equal the parsed source set. If
an explicitly selected installed INF has native-only sections, use
`--allow-native-added-sections` with --cli/--output to record the difference and compare
all source sections. Native additions are never copied into the product report. The
BasicDisplay observation adds `Strings.0409` natively; its cause remains unestablished.
This optional development scope does not change analysis or native-policy claims.

Generate controlled v1/v2 catalogs with SDK MakeCat/SignTool (PowerShell 7):

    pwsh -NoProfile -File tools/native-compare/windows-catalog-fixture.ps1 -OutputDirectory D:\github\analyze-anything\out\windows-baseline\catalogs

The output must be below this checkout's out folder. A temporary test PFX is removed in
finally; its certificate is created in memory and is never added to a Windows store.
Catalogs have changing producer identifiers/signatures when regenerated; analysis of
the same resulting bytes must still be deterministic. Source payloads are never run.

Read native catalog records and compare the controlled fixture with the CLI:

    python tools/native-compare/windows-catalog-check.py --sample crates/aa-windows/tests/data/native-catalog-v2.cat --version 2 --reference out/windows-baseline/catalogs/v2-checks.json --cli target/debug/analyze-anything.exe --output out/windows-baseline/catalogs/v2-checks

Use version 1 and the v1 sample for the other profile. Without --cli/--output the helper
only captures the native snapshot. CryptCATOpen opens the explicit catalog without
adding it to the host catalog database; SignedCms checks content/signatures with trust
verification disabled. The controlled CLI comparison also checks changed-content and
changed-signature copies, repeated reports, unchanged source bytes and bilingual output.
These checks do not establish supplied payload membership or Windows trust. See
[the catalog record](../../docs/spikes/windows-catalogs.md) for the native v2 alias caveat.

Record native SHA-1/SHA-256 SIP hashes for explicit controlled files, without executing them:

    python tools/native-compare/windows-sip-hash.py crates/aa-windows/tests/data/hello.exe --output out/windows-baseline/sip.json

Regenerate the 17 controlled SIP layout observations (Windows only):

    python tools/native-compare/windows-sip-fixtures.py --output out/windows-baseline/sip-fixtures --reference out/windows-baseline/native-sip-hashes.ref.json

The golden reference in crates/aa-windows/tests/data records input hashes and native
results/errors for portable Rust comparison. Review regenerated observations before
replacing it. These tests use existing project fixtures, not vendor packages.

Compare six supplied-package layouts with native SIP hashing and explicit-catalog
SignTool, then check CLI associations, unchanged input, determinism and rendered output:

    python tools/native-compare/windows-catalog-package-check.py --cli target/debug/analyze-anything.exe --output out/windows-baseline/catalog-package-checks

The layouts are catalog-only, dual signatures, modified, missing, embedded-only and ZIP.
The generated INF includes source/media declarations. The helper explicitly binds its
logical distribution root through --windows-source-root, checks source-path association
and declared sizes, and distinguishes a missing supplied candidate from a present file
whose SIP comparison is separate. ZIP roots remain inside the named container. These
are controlled layouts, not Windows installation or WHQL qualification.
Native SignTool policy failures are retained separately: the controlled certificate is
self-issued, and mathematical digest agreement does not establish Windows trust.
Nothing is installed or added to the catalog/certificate stores. Generated copies and
native policy logs remain under out; see [the scope record](../../docs/spikes/windows-catalog-membership.md).

Create unsigned project MSIX fixtures with SDK MakeAppx, then compare declared hashes
and captured content with read-only AppxPackaging APIs (Windows only):

    python tools/native-compare/windows-msix-fixtures.py --output out/windows-baseline/msix-fixtures
    python tools/native-compare/windows-msix-blockmap.py --blockmap <AppxBlockMap.xml> --content <extracted content directory> --output out/windows-baseline/msix-native.json
    python tools/native-compare/windows-msix-content-check.py --sample crates/aa-windows/tests/data/native-msix-sha256.msix --cli target/debug/analyze-anything.exe --output out/windows-baseline/msix-check

The last helper records original, changed-content, changed-block-hash, missing and
duplicate-name cases, plus changed FileHash when present. It preserves the native
ValidateFileHash result separately from a check of every native block declaration:
on the checked modern SDK inputs, a matching whole-file hash can make that API accept
an altered block declaration. The analyzer reports both block and file-hash checks.
These are content checks, not package deployment, signature authentication or ZIP-layout
validation. Repacked negative cases are not claimed to be valid MSIX packages.

Compare original ZIP record/header results with SDK MakeAppx unpacking (without `/nv`)
and independent Python ZIP metadata, using the four redistributable MSIX/APPX fixtures:

    python tools/native-compare/windows-msix-layout-check.py --cli target/debug/analyze-anything.exe --output out/windows-baseline/msix-zip-layout-check

Use a fresh output directory. It checks each original plus a changed LfhSize declaration,
including repeated report bytes and source preservation. SDK validation applies to the
four original packages only; repacked negatives are declaration cases. No input is installed
or executed. This helper checks record/header correspondence; physical block checks
and package signatures remain separate from those results.

Compare physical stored/DEFLATE block checks, preserving original payload streams in
declaration/profile cases, against independent zlib/hashlib calculations and live
AppxPackaging declarations:

    python tools/native-compare/windows-msix-blocks-check.py --cli target/debug/analyze-anything.exe --output out/windows-baseline/msix-raw-blocks-check

Use a fresh output directory. The four fixtures produce 27 original, block-hash,
extent-overshoot, missing-size, shifted-boundary and final-stream variant cases. The
helper keeps GetHash/GetCompressedSize and ValidateFileHash observations distinct,
checks repeated JSON, input preservation, English Markdown/HTML and Chinese Markdown.
Only input bytes are analyzed; no package is installed or executed. Constructed ZIP32
wrappers do not qualify package signatures or native installation behavior. Independent
block decoding remains a bounded profile; unknown stream forms stay unresolved.

Compare the pinned Microsoft APPX's P7X signature with CryptoAPI message mathematics
and independently reconstructed package regions/footprints:

    python tools/native-compare/windows-msix-signature-check.py --cli target/debug/analyze-anything.exe --output out/windows-baseline/msix-signature-check

Use a fresh output directory. Five original/metadata/signature/capsule cases keep
CMS signature results separate from package digest agreement. It also checks a Chinese
standalone P7X report, repeated JSON and source preservation. Certificates are only
decoded into memory for public-key verification; no certificate is installed, no
trust/chain/revocation lookup is requested, and no package is installed or run.
Other SIP versions, signature algorithms, publisher policies and bundles retain their
separate qualification gates.
