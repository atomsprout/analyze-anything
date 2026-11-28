# Arch ALPM fixture

`libutf8proc-2.12.0-1-x86_64.pkg.tar.zst` is an unmodified official Arch Linux
package from
<https://archive.archlinux.org/packages/l/libutf8proc/libutf8proc-2.12.0-1-x86_64.pkg.tar.zst>.
It is 80,236 bytes, SHA-256
`297205aba0d093921dbfbc70b9ecf7359838f0c3418b6265af960aed12bfd072`.

Upstream is <https://github.com/JuliaStrings/utf8proc>. The package contains its
MIT and Unicode data notices in `usr/share/licenses/libutf8proc/LICENSE.md`;
the same unmodified text is preserved in `LICENSE-libutf8proc.md`. See `NOTICE`.

The package was read using Windows' libarchive `tar.exe`; its root `.PKGINFO`,
`.BUILDINFO`, `.MTREE`, regular payloads and two symlink declarations were inspected
without extraction to the host filesystem, installation, loading or execution.
The reproducible comparison uses libarchive bsdtar, system zstd and Python tarfile;
when pacman is installed it additionally performs the read-only `pacman -Qip`
package-file query:

```
python3 tools/native-compare/arch-packages.py target/debug/analyze-anything \
  crates/aa-linux/tests/data/libutf8proc-2.12.0-1-x86_64.pkg.tar.zst \
  --record out/arch-reference.json
```

The first reader profile recognizes an exact regular root `.PKGINFO` from
the original captured TAR, independent of the filename. Shared gzip, bzip2,
xz and zstd layers retain their own provenance. Root control aliases, repeated
scalar identity fields, incomplete TAR indexes and unsupported text are explicit
limitations. The TAR index retains original offsets, entry types, modes and link
targets; links are declarations, never followed or materialized. `.BUILDINFO`
format 2 has selected build-tool/environment declarations. `.MTREE` is retained
only as member size and digest, without parsing or checksum verification.

Constructed Rust tests cover literal dependencies, a bounded/redacted `.INSTALL`,
duplicate controls, malformed fields, missing identity, link declarations,
truncated/concatenated TARs and text budgets. This real package does not contain
an installation script. Neither fixture qualification nor static declarations
establish installation behavior, dependency resolution, package authenticity or
reproducible builds.

Format references: [PKGINFO](https://man.archlinux.org/man/PKGINFO.5.en),
[BUILDINFO](https://man.archlinux.org/man/BUILDINFO.5.en).
