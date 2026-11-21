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
Native SignTool policy failures are retained separately: the controlled certificate is
self-issued, and mathematical digest agreement does not establish Windows trust.
Nothing is installed or added to the catalog/certificate stores. Generated copies and
native policy logs remain under out; see [the scope record](../../docs/spikes/windows-catalog-membership.md).
