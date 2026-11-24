Small archives used by the engine's damaged-input test. Each holds `a.txt` (one line of text)
and `sub/b.bin` (3000 random bytes), packed with the system `zip`, `tar` (plain, gzip, bzip2,
xz, zstd) and `7z` tools. An engine test checks each unpacks to the same SHA-256 digests.

`sdk-dotnet-bundle.exe` is a framework-dependent Windows x64 bundle built with
Microsoft .NET SDK 10.0.401 from `tools/fixtures/executable-bundles`. Its original
apphost is MIT; see `LICENSE-dotnet-runtime.txt` and the root `NOTICE`. The embedded
program is Apache-2.0 and is never run. `sdk-dotnet-bundle.ref.json` records the
independent .NET BinaryReader/DeflateStream comparison.

`native-carchive.pkg` contains only the Apache-2.0 `data.txt` in that same source
directory, written by the external PyInstaller 6.22.3 CArchive writer. It includes
no bootloader or Python module. `native-carchive.ref.json` records archive-viewer
declarations and content digests. The producer is `tools/native-compare/pyinstaller-fixture.py`.

Reproduction and larger real-sample comparisons are described in
`docs/spikes/executable-bundles.md`. The SDK and Python reference tool are development
tools, not analysis dependencies.
