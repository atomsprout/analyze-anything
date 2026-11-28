# AppImage and snap reader qualification

Analysis never invokes an AppImage runtime, mounts a filesystem, runs a hook,
installs a snap or contacts a store. Native comparisons are separate developer
tools which read the same captured bytes.

## AppImage Type 2

The initial profile requires `AI\x02` at ELF identification bytes 8–10, ordinary
ELF32/ELF64 section tables and a little-endian SquashFS v4 filesystem immediately
after the proven runtime extent. The reader uses the upstream runtime's maximum
of the section-table end and last file-backed section end. It checks every other
file-backed section and segment against that boundary; it never searches for a
filesystem magic string to guess an offset. Extended or absent section counts,
nonstandard entry sizes and unsupported layouts are explicit limitations.
Limits are 8192 sections and 1024 program headers. Only the checked `bytes_used`
extent becomes `[filesystem].squashfs`; additional nonpadding bytes are reported.

The captured filesystem can supply one root Desktop Entry identity and AppRun
evidence. A regular AppRun or a supported literal package-relative link can match
an original captured regular file. Absolute links, parent traversal, substitutions,
multiple hops, missing/changed entries and incomplete namespaces remain unresolved.
The target's digest is evidence of bytes, never execution or publisher trust.

`appimage-external.ref.json` records AppImageKit 12's public
`appimagetool-x86_64.AppImage`, SHA-256
`d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13`.
Its 64-bit little-endian ELF proves offset 188392, and its gzip SquashFS has 40
inodes. The external sample yielded the captured name `appimagetool` and a regular
AppRun file. Windows 7-Zip 25.00 independently qualified all directory paths/types,
modes/owners, ordinary-file hashes and link targets in 135 checks. The AppImage
executable is **not redistributed**: AppImageKit's source is MIT, and its bundled
dependencies keep their own licences. Other ELF classes/byte orders and hostile
header profiles currently have constructed tests only. Linux `unsquashfs`
qualification remains a separate gate until its result is recorded.

## Snap metadata

The package is qualified from one original direct `meta/snap.yaml` inside a complete
captured SquashFS namespace. A filename alone or `snapcraft.yaml` does not qualify
it. YAML scalar text, mappings and sequences retain source lines; recognized
credentials are redacted. Duplicate keys, tags, anchors, aliases, merge keys,
multiple documents and unsupported encodings are rejected explicitly.

Limits are 256 KiB per metadata file, 16 MiB of aggregate metadata, 12000 YAML
events, depth 24, 16 KiB per scalar, 256 bytes per key, 256 application/hook records
and 1024 supplied target records per package. Namespace traversal is capped at
100000 artifacts and 1024 filesystem candidates. Identity requires literal name
and version fields; the reader does not claim full snap schema validation.

Applications, daemon/interface/environment settings, root plugs/slots and hook
metadata remain declarations. Literal package-relative command tokens, command
chains and `meta/hooks` paths can match captured original regular files, without
following symlinks or querying the host. Confinement, dependency satisfaction,
store assertions, signatures, command evaluation and hook activation are unchecked.

The unchanged MIT-declared Canonical hello-world 6.4 revision 29 fixture is described
in [SQUASHFS.md](SQUASHFS.md). Its captured metadata and all four application targets
are exercised together by the snap reader's unit test. No fixture script is run.

## Reproduction

Fetch the pinned external AppImage only into an ignored scratch directory:

```
python3 tools/native-compare/linux-image-fixtures.py out/native-linux-images
```

On Linux with `squashfs-tools` and PyYAML installed, compare the image and snap using
only `unsquashfs` listing and member-to-stdout operations:

```
python3 tools/native-compare/linux-images.py target/debug/analyze-anything \
  crates/aa-linux/tests/data/upstream-hello-world-29.snap \
  out/native-linux-images/appimagetool-12-x86_64.AppImage \
  --record out/native-linux-images/unsquashfs-reference.json
```

The native helper detects whether the CLI exposes `--no-ai`, so no-AI builds work.
Its AppImage offset calculation is a separate Python snapshot; `unsquashfs -o`
checks that exact extent. No `--appimage-offset` or `--appimage-extract` input option
is used.
