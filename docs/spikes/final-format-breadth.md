# Final format breadth increment

The fourth increment adds three primary families and one compression family:
Alpine APK, full Flatpak single-file bundles, OCI/Docker-save images as one
family, and LZ4 frames. With B merged, the combined A/B/C/D source catalogue
contains 35 primary plus five compression families: 40 in total. Eleven
declaration families remain separately counted. These are
implemented source profiles for the pending 0.2.6 delivery; no 0.2.6 release is
claimed here. Release notes identify immutable source and packaged runtime checks.

## Qualified inputs and references

| Family | Default real/native-writer input | Independent reference |
|---|---|---|
| Alpine APK | Alpine 3.22 `libxxhash-0.8.3-r0.apk`, BSD-2-Clause | gzip/zlib, TAR/libarchive and read-only Alpine `apk manifest`; [source and scope](../../crates/aa-linux/tests/data/ALPINE.md) |
| Flatpak | Native `flatpak build-bundle` output containing project-authored Apache-2.0 inert data | Flatpak BundleRef, GLib GVariant and independently reconstructed object bytes; an external RustDesk 1.5.3 bundle is fetched by hash in CI and is not redistributed; [source and scope](../../crates/aa-linux/tests/data/FLATPAK.md) |
| OCI/Docker | Native umoci/skopeo archives containing project-authored Apache-2.0 inert data | Skopeo inspection, independent JSON/TAR/digest readers and raw PAX provenance checks; [source and scope](../../crates/aa-linux/tests/data/OCI.md) |
| LZ4 | Four native LZ4 1.9.4 writer frames containing project-authored Apache-2.0 text | Native `lz4 -dc`, original text and SHA-256 comparison; [source and scope](../../crates/aa-unpack/tests/data/LZ4.md) |

The fixtures are data. Native development helpers never install a package,
import a bundle, load an image or execute an analyzed file or declared hook.
The source reader uses no external program or network.

## Supported boundaries

Alpine reads exact gzip members with integrity checks and separates signature,
control and payload captures. Effective names determine authority; aliases and
duplicate controls cannot establish an identity. APK v3/ADB is outside the
profile. Signatures remain unverified declarations.

Flatpak supports the empty-base inline V0 literal operation profile with stored
or bounded XZ parts. It checks canonical object labels and retains part and byte
provenance for file contents and filename declarations. Missing or unsupported
objects preserve independently readable siblings. Other base/fallback/opcode
profiles and trust are explicit unknowns. A branch is never reported as a
software version. Serialized inventory is limited to 16 MiB and paths offered
to extraction to 32 MiB, including repeated outer-container prefixes. Native
[run 46109882704](https://github.com/atomsprout/analyze-anything/actions/runs/46109882704)
passed at `56fce92` with those guards, comparing the checked-in and fresh inert
writer fixtures and the pinned external RustDesk bundle.

OCI and Docker-save are one family. Captured descriptors, configuration and
ordered layers remain separate; whiteouts and links are declarations. There is
no merged filesystem, registry resolution or runtime claim. Local PAX/GNU
extension evidence spans include the bytes used to derive effective names.
Global PAX, sparse and unfinished TAR layers are outside the supported profile.

LZ4 supports one modern independent-block frame, at most 4 MiB per block,
65,536 blocks and 256 MiB of decoded data. Header, block and content checksums
are checked where declared. Dictionaries, linked blocks, raw/legacy/skippable
streams and concatenated frames remain unread.

Every reader checks input-driven sizes and offsets. Path, decoding, JSON/variant
structure and serialized output budgets have hostile-input regression coverage.
Complete capture, complete inventory, digest agreement and authenticity are
distinct properties. The engine integration checks identities, real payload
digests, component sources, explicit unknowns and repeated-report equality.
