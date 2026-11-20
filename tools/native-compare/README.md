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
