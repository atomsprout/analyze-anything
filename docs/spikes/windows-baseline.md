# Windows baseline checks

2026-11-20, Windows x64 version 10.0.26200.0, Rust 1.100.0. Initial W0 results for
[the Windows plan](../PLAN-WINDOWS.md). The milestone remains open: these checks do not cover
a real signed installer distribution, an application folder or the Windows desktop app.

## Build and native comparison

The CLI built successfully with `cargo build -p aa-cli --no-default-features`.
`cargo fmt --all --check` passed. Two helper tests passed for SDK discovery and passing
quoted/non-ASCII paths to the native signature reader as data.
`cargo clippy --workspace --all-targets -- -D warnings` also passed on this host.
The initial `cargo test --workspace` run completed successfully, including the whole-engine
damaged-fixture test (205 seconds). After the comparison normalization change, all 14 export
tests, export Clippy and the no-AI CLI rebuild passed. An end-to-end comparison of two ZIPs with
the same generated contents and different input names produced four unchanged findings and no
added, removed or changed findings.

The development harness discovered x64 SignTool in Windows SDK 10.0.26100.0 without a PATH
entry. The following explicit sample run passed 12 checks, including signer thumbprints,
the valid embedded signature's cryptographic checks, changed-byte detection and byte-identical
extraction from makecab-produced MSZIP and LZX cabinets:

    python tools/native-compare/windows.py target/debug/analyze-anything.exe --sample "C:\Program Files\dotnet\dotnet.exe" --sample crates/aa-windows/tests/data/hello-signed.exe --sample crates/aa-windows/tests/data/msi-signed.msi --record out/windows-baseline/native.json

| Sample | SHA-256 | Windows signature status | SignTool exit |
|---|---|---|---|
| Installed dotnet.exe | 21a46f1e5235cf4e844b9de5429f0e198b9c97a41f0503a66442f1d639ca3ee6 | Valid | 0 |
| hello-signed.exe fixture | 874dd045e7a59b0d07e3bd1a0c9a2513135a0258c4986ad4d2b9842220110844 | UnknownError | 1 |
| msi-signed.msi fixture | ef1e6832d44740b25241643e5e0ffb7c638c3a7666f073215e0350edc502f282 | UnknownError | 1 |

The analyzer reported passed content digest, file digest, signature value and chain checks
for all three inputs. The fixture signer thumbprints matched the Windows reader. Native
UnknownError and nonzero SignTool results are recorded observations, not evidence that
Windows accepts these fixture certificates. This run does not establish the cause of those
policy outcomes, offline behavior, catalog membership or equivalence with Windows trust.
The installed binary was read, never executed as an analyzed input.

The raw record is under ignored out/ because it includes machine paths and native diagnostics.
The fixtures' existing source and licensing records remain in the Windows test data directory.

A second run using automatic discovery inspected 23 installed executables, DLLs and a driver
from .NET, Git, 7-Zip, Edge and Windows. It passed 50 checks, including the generated tampering
and CAB cases. Catalog-only system files were distinguished from embedded signatures; catalog
membership itself was not verified. [The sanitized sample record](windows-baseline-samples.json)
preserves each sample's name, digest, native status, signer thumbprint, analyzer cryptographic
checks and limitation counts without absolute paths or raw native diagnostics. These are individual
file comparisons, not analysis of an entire installed application folder.

## Real signed MSI and installed directory (2026-11-24)

The extended `windows.py` harness accepts repeatable `--folder` inputs. It analyzes each
directory once, compares every loose regular file against independent Python SHA-256,
and compares EXE/DLL/SYS/MSI signature facts from that same directory report with
Get-AuthenticodeSignature and SDK SignTool. It does not execute any program in the input.
Native policy outcomes remain separate from offline cryptographic facts.

A run on this Windows x64 host compared installed `dotnet.exe`, the locally supplied
`OpenJDK25U-jdk_x64_windows_hotspot_25.0.3_9.msi`, and the installed 7-Zip directory.
All 127 checks passed, including the existing modified-byte and generated CAB checks.
Windows reported Valid and SignTool returned zero for both signed standalone samples;
all four recorded analyzer signature checks passed. The directory's EXE/DLL signatures
were absent in both readers. Full directory inventory agreement does not establish
dynamic loader resolution or runtime behavior.

[The sanitized record](milestone-02-native.json) includes sample digests, signer identities,
cryptographic checks, directory file digests, limitation counts and the analyzer/SignTool
binary hashes. Raw native diagnostics remain under ignored `out/windows-baseline/`.
The external installed files and installer are not redistributed with the repository.
This adds representative evidence to W0; it does not establish every PE/MSI signature
profile, Windows trust equivalence or ARM64 behavior.
