# Executable bundle readers

The engine now offers bounded .NET and PyInstaller readers before generic executable
overlays. Members pass through the ordinary sink, name provenance, extraction budgets,
recursive unpacking and analyzers. No host, assembly, Python object or package is loaded
or executed. Metadata findings cite byte ranges in the original container. Facts retain
the declared member names, sizes, offsets and types separately from captured child artifacts.

## .NET single-file profile

The reader supports manifest versions 1.0, 2.0 and 6.0, a unique nonzero apphost marker
in the first 16 MiB, at most 10,000 entries and 16 MiB of metadata. Strings are bounded
to 4,096 UTF-8 bytes. Header/configuration ranges, entry ranges and overlaps are checked
before extraction. Unbundled apphosts with a zero header pointer are left alone.

Stored entries and version-6 raw DEFLATE streams are supported. The streaming decoder
requires a real stream end, the exact declared compressed extent and exact output size;
it does not allocate from a declared size. Engine limits apply independently. Unknown
file types have an explicit limitation; unsupported versions, flags, ambiguous markers,
bad pointers, malformed strings and overlapping ranges produce unpacking limitations.
The report retains the header ID, flags, configuration ranges and file-entry metadata.
Version-1/2 profiles have constructed tests only; native samples below cover version 6.
Other host layouts, runtime eligibility, extraction behavior and IL execution flow remain
outside this reader's claims.

The layout references are the .NET project's
[bundler design](https://github.com/dotnet/designs/blob/main/accepted/2020/single-file/bundler.md),
[Manifest](https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/Manifest.cs)
and [FileEntry](https://github.com/dotnet/runtime/blob/main/src/installer/managed/Microsoft.NET.HostModel/Bundle/FileEntry.cs).
The implementation is repository-authored; it does not use the SDK at analysis time.

## PyInstaller profile

The reader supports the 88-byte CArchive cookie and bounded UTF-8 TOC records, at most
10,000 entries, 4,096 bytes per name and a 16 MiB directory/cookie search window at the
end of the supplied bytes. The TOC must immediately precede its cookie. Member ranges
cannot overlap the directory/cookie or one another. Duplicate declarations remain separate
and go through the engine's name-collision handling.

Stored and zlib-compressed members are supported, with exact stream/size checks. Runtime
options remain metadata. Symbolic-link and external-dependency declarations are retained
in the directory and reported unresolved, without creating links or following paths.
Unknown item types/compression flags and unread members are explicit limitations.
Python marshal bytecode and PYZ contents remain opaque: their bytes can be analyzed by
generic readers, but no Python objects are deserialized and no source/import/control-flow
claims are made. This semantic limitation is separate from CArchive enumeration completeness.
Legacy 24-byte cookies are not unpacked. Protected/encrypted Python objects are never
decrypted; raw members may still be retained as data. Post-cookie trailing bytes have
constructed coverage; a real signed-trailer profile is not established.

Native-host prefixes and standalone package extents distinguish these readers from a
marker embedded inside an unrelated archive or disk image. Apple container readers keep
their earlier priority. Nested-marker regressions cover both readers.

Reference: [PyInstaller archive documentation](https://pyinstaller.org/en/stable/advanced-topics.html)
and its external archive-viewer reader. No PyInstaller code is copied into the Rust reader
or shipped as an analysis dependency.

## Recorded comparisons on Windows x64

| Sample | Source | Members / compressed | Result |
|---|---|---|---|
| WinSW-x64.exe | [v3.0.0-alpha.11](https://github.com/winsw/winsw/releases/tag/v3.0.0-alpha.11), source project MIT | 80 / 0 | Entry fields and every member digest agree with BinaryReader/DeflateStream |
| SDK framework-dependent fixture | .NET SDK 10.0.401, repository fixture project | 3 / 0 | Same comparison; small fixture and reference snapshot committed |
| SDK self-contained compressed fixture | Same project and SDK, compression enabled | 175 / 173 | Same comparison, including raw DEFLATE content |
| yt-dlp.exe | [2026.11.23](https://github.com/yt-dlp/yt-dlp/releases/tag/2026.11.23), source project Unlicense | 153 / 152 | 160 archive-viewer declaration, size and digest checks passed; Python-code limitation present |
| Data-only CArchive | PyInstaller 6.22.3 writer; project-authored data | 1 / 1 | Seven native-reader checks passed; fixture and snapshot committed |

The larger executables remain under ignored `out/milestone-04/`. The small native fixtures
have source/licence notices in `NOTICE`. Native generation is distinguished from independent
published samples. Only Windows x64 executable distributions were compared; real ELF/macOS
bundle profiles remain unqualified. This establishes static contents agreement, not trust or
runtime behavior.

[The native comparison record](executable-bundles-native.json) preserves the exact source
digests, entry fields and independent member digests for the larger samples. The small
fixture snapshots are in `crates/aa-unpack/tests/data/`.

Eleven unpacker tests cover native fixtures, nested-container markers, all supported .NET versions, compressed-size and
stream-boundary failures, malformed lengths/pointers/counts, truncated inputs, runtime options,
external references and opaque Python-code scope. Two engine tests verify that actual .NET
members reach the existing assembly reader, that CArchive member provenance is retained,
that repeated reports agree and that extraction budgets remain effective.

Reproduce with a no-AI CLI build and development reference tools:

```powershell
cargo build -p aa-cli --no-default-features
pwsh -File tools/native-compare/dotnet-bundle-fixture.ps1 -Output out/bundle-fixtures
python tools/native-compare/dotnet-bundle.py target/debug/analyze-anything.exe out/bundle-fixtures/compressed/BundleFixture.exe --record out/bundle-fixtures/comparison.json
# Use a development Python environment containing PyInstaller 6.22.3 for these two commands.
python tools/native-compare/pyinstaller-fixture.py out/bundle-fixtures/data.pkg
python tools/native-compare/pyinstaller-archive.py target/debug/analyze-anything.exe out/bundle-fixtures/data.pkg --record out/bundle-fixtures/carchive.json
```

## Windows checkout follow-up

Hosted CI 45369702842 at a4bb836 passed the Linux/macOS core jobs, all three
platform desktop jobs and the advisory/license gate. The Windows core job exposed
a fixture line-ending mismatch: Git converted data.txt to CRLF while the pinned
native CArchive embeds its original LF bytes. The source fixture now explicitly
uses LF through .gitattributes. The byte-for-byte digest assertion is retained;
a fresh hosted Windows checkout must verify this fix before final acceptance.
