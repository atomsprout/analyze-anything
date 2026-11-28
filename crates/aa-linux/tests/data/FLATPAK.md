# Flatpak single-file fixtures

`native-inert.flatpak` is an unmodified native Flatpak-writer output containing
project-authored Apache-2.0 inert text, an empty file, a Unicode filename and a
symlink declaration. It is 1,884 bytes, SHA-256
`ee9b1c1db1ae500654036a418946548ed48d65ea6bd7e189bdbb0536022cff3d`.
The original source paths and regular-file digests are in
`native-inert.flatpak.source.json`.

The writer recipe is `tools/native-compare/flatpak-bundle-fixture.py`. It creates
a private OSTree repository with a fixed source commit time and calls native
`flatpak build-bundle`. It never installs, imports, launches or applies the bundle.
The delta generation timestamp is writer data and reproduction does not promise
identical bundle bytes. The fixture was generated on Ubuntu 24.04 by the
Flatpak native reader comparison workflow, run 46105635373 at ce29c9f.

`tools/native-compare/flatpak-bundles.py` reads the bundle through native
`Flatpak.BundleRef`, validates GVariant through native GLib, decodes XZ through
Python's liblzma and independently reconstructs literal object associations.
GLib serializes canonical OSTree checksum headers. Every object label, file path,
mode, symlink target and regular payload digest is compared to the report; the
bundle is never installed or imported into a repository.

```
/usr/bin/python3 tools/native-compare/flatpak-bundle-fixture.py out/flatpak-native
/usr/bin/python3 tools/native-compare/flatpak-bundles.py target/debug/analyze-anything \
  out/flatpak-native/native-inert.flatpak --record out/flatpak-native/reference.json
```

The separate, external RustDesk 1.5.3 x86_64 Flutter bundle was read locally as
bytes, not launched or installed. Its published source is
<https://github.com/rustdesk/rustdesk/releases/download/1.5.3/rustdesk-1.5.3-x86_64.flatpak>,
size 25,187,184, SHA-256
`947239551c8758479a55aa8d03e863655e5c8e4e52c4f79a39d9bb51cc4184f8`.
It is not redistributed here. Upstream source and AGPL-3.0 licence are at
<https://github.com/rustdesk/rustdesk/tree/1.5.3>. The parser read four XZ inline
parts, 150 checksum-verified objects, 120 file/link paths and 44 directories.
This local reading alone is not an independent native comparison.

The supported profile is empty-base OSTree static-delta single-file bundles with
an explicit little/big endianness marker, inline version-0 parts, stored/XZ
compression and complete literal `S` object records. Root/part framing offsets,
padding, strings, checksums and ranges are checked; node, string, object, path,
depth, compression-memory and output budgets are bounded. Links and extended
attributes remain declarations. Original inline parts are retained as artifacts,
with decoded-part layers and payload byte provenance.

Object hashing has a cumulative 256 MiB work budget, including repeated ranges
and attribute data; duplicate object identities are rejected before repeated hashing.
Graph queues have a 16 MiB metadata budget. Declared and verified object counts,
reconstructed and actually retained regular-file counts are separate. Evidence for
captured contents names both the decoded payload range and the original directory
filename declaration. Missing captured layers remain explicit.

Nonempty bases, recursive/fallback/external objects, other delta operations,
compression profiles, signed-superblock envelopes and unsupported metadata remain
explicit gaps. AppStream/icon data, signatures, runtime availability, remote
resolution and effective sandbox policy are not authenticated or evaluated.
The parser does not execute target code or load it into a runtime.

Primary format references:
[OSTree formats](https://ostreedev.github.io/ostree/formats/),
[static-delta definitions](https://github.com/ostreedev/ostree/blob/main/src/libostree/ostree-repo-static-delta-private.h),
[Flatpak writer](https://github.com/flatpak/flatpak/blob/main/app/flatpak-builtins-build-bundle.c),
[GVariant serialization specification](https://people.gnome.org/~desrt/gvariant-serialisation.pdf).
