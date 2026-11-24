# Linux package readers

The 0.4 package work reads declarations and payload bytes; no input is installed,
loaded, executed or decrypted. This profile is still undergoing native qualification.

## Supported scope

- Debian: common ar headers, first `debian-binary` major 2 version, ordered unique
  control and data archives; bounded underscore extension members and trailing
  members. Up to 512 ar members. Shared streams and TAR readers expose regular
  members. Literal single-stanza Deb822 fields retain source lines and spelling;
  duplicate fields, ambiguous control files and malformed continuations are gaps.
  Identity, relationships and maintainer-script findings cite captured control
  contents, never a similarly named file in the payload. Both TAR indexes retain
  paths, original offsets, permissions, sizes, entry types and link targets.
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

Seven constructed unpacker tests and six engine tests passed on Windows, including
malformed lengths, all short prefixes, unsupported payloads, CPIO checksums and
hardlinks, ambiguous control metadata, source attribution, repeated-report equality
and engine budgets. Two published package fixtures exercise real compression and
link declarations. Targeted Clippy passed with warnings denied.

Local no-AI CLI runs read Debian node-isarray 2.0.5-1 (xz control and data TAR)
and Fedora xxhash-libs 0.8.4-2.fc43 (zstd CPIO). They are redistributable fixtures
with source and license notices. **Native tool agreement is not yet established.**

The Linux Native comparison job uses dpkg-deb, librpm, rpm2cpio and bsdtar to check
identity, selected header values, regular-file SHA-256, TAR metadata, CPIO paths,
symlink targets and maintainer-script declarations. Separate native-built fixtures
exercise Debian postinst and RPM post/preun declarations; those scripts are never run.

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
