# Test fixtures

Everything here is built by `make-fixtures.sh` from the sources in `src/`. Nothing was downloaded.
Keys and certificates are generated on the spot and thrown away, so the signed files differ on
every run; the reference tools' output is regenerated with them and stored next to each fixture.
The tests in `../pipeline.rs` compare the analyzer's results with those reference files.

| File | Made with | Reference file (tool) |
|---|---|---|
| `hello.exe` | mingw-w64 gcc + windres from `src/hello.c`, `hello.rc`, `hello.manifest` | `hello.version.ref.txt` (exiftool) |
| `hello-signed.exe` | osslsigncode: RSA-2048 leaf under a test root, SHA-256, RFC 3161 timestamp from osslsigncode's built-in TSA | `hello-signed.ref.txt` (`osslsigncode verify`) |
| `hello-sha1.exe` | same leaf, SHA-1, no timestamp | `hello-sha1.ref.txt` |
| `hello-dual.exe` | `hello-sha1.exe` plus a nested SHA-256 signature (`-nest`) with a timestamp | `hello-dual.ref.txt` |
| `hello-ecdsa.exe` | ECDSA P-256 leaf, SHA-384 | `hello-ecdsa.ref.txt` |
| `hello-selfsigned.exe` | a self-signed certificate | `hello-selfsigned.ref.txt` |
| `dotnet.exe` | Mono `mcs` from `src/dotnet.cs` | `dotnet.ref.txt` (`monodis`) |
| `nsis-zlib.exe` | makensis 3.09 from `src/installer.nsi`: Unicode, deflate, non-solid | `nsis-zlib.ref.txt` (`7z l -slt`, then SHA-256 of `7z x`) |
| `nsis-lzma-solid.exe` | same script: Unicode, LZMA, solid | `nsis-lzma-solid.ref.txt` |
| `nsis-bzip2-ansi.exe` | same script: ANSI, bzip2, solid | `nsis-bzip2-ansi.ref.txt` |
| `fixture.msi` | wixl (msitools) from `src/product.wxs` | `fixture.msi.ref.txt` (`msiinfo export`, then SHA-256 of `msiextract`) |
| `msi-signed.msi` | wixl from `src/tiny.wxs`, signed with osslsigncode: RSA-2048 leaf under a test root, SHA-256, RFC 3161 timestamp | `msi-signed.ref.txt` (`osslsigncode verify`) |
| `msi-signed-dse.msi` | the same package, self-signed certificate, with the `MsiDigitalSignatureEx` metadata hash (`-add-msi-dse`) | `msi-signed-dse.ref.txt` |
| `msi-nested-dse.msi` | a compound file with nested storages written by the ignored test `msisig::tests::write_nested_sample`, signed like the above with SHA-384 | `msi-nested-dse.ref.txt` |
| `fixture.cab` | gcab, MSZIP | `fixture.cab.ref.txt` (SHA-256 of `cabextract`) |
| `fixture.asar` | `src/make-asar.py`, which writes the asar format directly | — (contents are in the script) |
| `sfx-7z.exe` | `hello.exe` with a 7z archive appended | `sfx-7z.ref.txt` (SHA-256 of the files that were packed) |

Variants the tests need but that are not stored (a modified signed file or package, data hidden
in the certificate table or the signature stream, an Electron folder, truncated and corrupted files) are derived from these
files by the tests themselves.

There is no Inno Setup fixture: the Inno Setup compiler runs only on Windows, and real installers
are far larger than the 200 KB limit. Inno Setup support was checked by hand against
`innoextract` on real installers; see the crate's module documentation.
