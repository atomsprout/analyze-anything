# Linux package readers

The 0.4 package work reads declarations and payload bytes; no input is installed,
loaded, executed or decrypted. Initial native qualification passed; final combined-head
checks remain required.

## Supported scope

- Debian: common ar headers, first `debian-binary` major 2 version, ordered unique
  control and data archives; bounded underscore extension members and trailing
  members. Up to 512 ar members. Shared streams and TAR readers expose regular
  members. Literal single-stanza Deb822 fields retain source lines and spelling;
  duplicate fields, ambiguous control files and malformed continuations are gaps.
  Identity, relationships and maintainer-script findings cite captured control
  contents, never a similarly named file in the payload. Both TAR indexes retain
  paths, original offsets, permissions, sizes, entry types and link targets.
  Captured scripts and triggers retain redacted UTF-8 source text up to 256 KiB;
  ambiguous names, larger declarations and undecodable text are explicit gaps.
- RPM: 96-byte 3.0 lead with header-style signature records; checked and ordered
  signature/header index structures. Header stores are at most 16 MiB, indexes and
  decoded values at most 100,000; a shared string-scan budget prevents overlapping
  declarations from multiplying work. Selected identity, dependency, script,
  interpreter, trigger and payload tags retain original index and value offsets.
  Other tags retain descriptors. Explicit CPIO and gzip/bzip2/xz/zstd/none payload
  declarations are checked against magic bytes before extraction. RPM v6 and
  missing/unsupported declarations remain gaps.
- CPIO: newc/crc, at most 100,000 entries, 4096-byte names and 16 MiB of names.
  Checked extents, trailer and byte sums. Complete hardlink groups with identical
  or single late data bodies yield independent logical byte artifacts, never host
  links. Incomplete/conflicting groups remain gaps. Symlink targets and special
  files remain metadata and explicit limitations. Concatenated archives and the
  RPM `07070X` extension are outside this profile.

Package identity feeds the shared component inventory. Dependency declarations
are not resolved against repositories or the host. Package signatures, checksum
declarations, installation eligibility and script behavior are not verified.
Raw LZMA, old Debian containers and additional RPM metadata semantics remain open.

The engine registers specific Apple containers first, then executable/platform
containers, Linux packages/newc, shared archives/streams and legacy Apple payload
fallbacks. Compressed CPIO now retains its compression layer in the artifact tree;
the Apple odc and pbzx readers remain available.

## Evidence so far

Seven constructed unpacker tests and ten engine tests passed on Windows, including
malformed lengths, all short prefixes, unsupported payloads, CPIO checksums and
hardlinks, ambiguous control metadata, source attribution, repeated-report equality
and engine budgets. Published and native-built fixtures exercise real compression,
link declarations, scalar/array interpreters and bounded script text. Targeted
Clippy passed with warnings denied. The engine/correlation/Apple/Linux regression
suites passed, including the damaged-fixture corpus in 274.69 seconds.

Local no-AI CLI runs read Debian node-isarray 2.0.5-1 (xz control and data TAR)
and Fedora xxhash-libs 0.8.4-2.fc43 (zstd CPIO). They are redistributable fixtures
with source and license notices.

The Linux Native comparison job uses dpkg-deb, librpm, rpm2cpio and bsdtar to check
identity, selected header values, regular-file SHA-256, TAR metadata, CPIO paths,
symlink targets and maintainer-script declarations. Separate native-built fixtures
exercise Debian postinst and RPM post/preun declarations; those scripts are never run.

The first Linux run (45372596833 at be39b11) found a real profile gap: rpmbuild
stored a single script interpreter as STRING rather than STRING_ARRAY. The reader
now accepts both representations for interpreter tags, preserving the original
type, count and value. The generated script packages are pinned regression inputs.
Run [45373345565](https://github.com/atomsprout/analyze-anything/actions/runs/45373345565)
at 425b6b6 then passed all 112 checks with dpkg-deb 1.22.6 and RPM 4.18.2.
[The native record](linux-packages-native.json) binds every result to its input hash.
It covers the four pinned packages plus two freshly built script packages. A
cross-platform engine test checks these native identities, tag values and regular
member digests. Bounded script-text display was added after that run; its explicit
native text check and the final combined-head qualification remain pending.

```
python3 tools/native-compare/linux-package-fixtures.py out/native-linux
python3 tools/native-compare/linux-packages.py target/debug/analyze-anything \
  crates/aa-linux/tests/data/*.deb crates/aa-linux/tests/data/*.rpm \
  out/native-linux/*.deb out/native-linux/*.rpm --record out/native-linux/reference.json
```

Format references: [Debian deb(5)](https://manpages.debian.org/trixie/dpkg-dev/deb.5.en.html),
[Debian control fields](https://www.debian.org/doc/debian-policy/ch-controlfields.html),
[RPM v4](https://rpm.org/docs/latest/manual/format_v4.html),
[RPM headers](https://rpm.org/docs/latest/manual/format_header.html),
[RPM tag definitions](https://github.com/rpm-software-management/rpm/blob/master/include/rpm/rpmtag.h),
and [SVR4 CPIO fields](https://www.kernel.org/doc/html/next/driver-api/early-userspace/buffer-format.html).
