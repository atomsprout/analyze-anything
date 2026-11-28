# OCI and Docker-save native fixtures

The positive `native-image.oci.tar` and `native-image.docker.tar` fixtures are
unchanged copies of `native-inert.oci.tar` and `native-inert.docker.tar` from the
Ubuntu 24.04 native comparison
[run 46108449511](https://github.com/atomsprout/analyze-anything/actions/runs/46108449511)
at `79635c7`. Native umoci `0.4.7+ds-4ubuntu0.24.04.3` wrote the image layout and
gzip layers; skopeo `1.13.3` wrote the archive exports and independently inspected
their manifests/configuration. All contents are project-authored Apache-2.0 inert
data. No third-party base image or executable payload is included.

| Fixture | Bytes | SHA-256 |
|---|---:|---|
| `native-image.oci.tar` | 10,240 | `2f2df7cea6652176d4dd23de2e143510ab423a9ec45ad89daeb1c46c16a686c5` |
| `native-image.docker.tar` | 45,056 | `7f212f0198616f6618b5d0dc1b2a66de9f25b2fa2e1ab8a1bc80c1070626d2fd` |
| `native-image.ref.json` | 51,407 | `3e7744b88628e0624c93e38185515599ad71f913cc9ad83142da9a9cb553d1b7` |
| `native-image.source.json` | 6,083 | `229d489b9430f99ce5c092d83673bbfa7ec17ec8608c59d7906661115af6c977` |

The unmodified native comparison record is `native-image.ref.json`; its sample
labels retain the original `native-inert` names. It records **326 passing checks**:
164 for OCI and 162 for Docker-save. The source record, `native-image.source.json`,
retains the exact source file/layer digests, tool versions, native umoci status and
skopeo observations. Each profile has three ordered layers with 7, 1 and 3 logical
TAR entries. The compared declarations include a Unicode name, empty file, symlink,
hardlink, named whiteout and opaque-directory marker. This qualifies those two
native writer profiles; it does not establish every image index, compression,
platform, registry export or historical Docker layout.

`native-unfinalized.oci.tar` is project-authored Apache-2.0 inert source data
packaged by Ubuntu's native umoci/skopeo tools in comparison run
[46107713227](https://github.com/atomsprout/analyze-anything/actions/runs/46107713227)
at `69e9821`. It is 10,240 bytes, SHA-256
`1666785aa68325bdb9cbeb129bbbd50a97d5f68e5f37ef0ea0b00987a67b652d`.
It is a negative fixture: declared blob hashes and DiffIDs agree, while the
`umoci insert` layer streams lack final TAR padding/trailers. The reader retains
the available declarations and reports incomplete layer coverage. No image was
loaded, installed, merged, unpacked to a host root or executed.

The native writer recipe is `tools/native-compare/oci-image-fixtures.py`. It
creates a new empty OCI image with `umoci`, writes finalized PAX TARs containing
only project-authored Apache-2.0 inert data, adds them verbatim with native
`umoci raw add-layer`, and exports local OCI and Docker-save archives with
`skopeo`. This is the writer equivalent of an image built from `FROM scratch`
with `COPY` and configuration declarations; no image command or `RUN` step is
executed. No image is loaded into a daemon, installed, imported or unpacked into
a host root filesystem. All skopeo transports are local files or layouts.

The image has three ordered layers: regular/empty/Unicode files, a symlink and
hardlink declaration; a named whiteout; and a directory with an opaque marker.
Its configuration declares literal argv, an environment variable and a synthetic
password redaction probe, a port, a volume and a title annotation. These are
declarations and do not establish effective runtime or network behavior.

The current recipe also creates two local PAX provenance probes in future writer
outputs: a symlink whose base header says `benign` while the local `linkpath`
record says `../outside`, and a regular file whose local `path` record overrides
its base-header filename. The symlink is written only as TAR metadata and never
created or followed on the host. The reference distinguishes actual base-header
fields from the original local extension/header span that establishes effective
metadata. These probes do not change the positive fixture bytes or the recorded
326-check qualification above; later writer runs have separate hashes and records.

The generator records the source-file digests, native `umoci stat --json`, raw
`skopeo inspect --raw` manifests and `skopeo inspect --config --raw` configuration
for both exports. `tools/native-compare/oci-images.py` independently reads original
archive members and every ordered TAR layer through Python's TAR/gzip readers.
It compares descriptor sizes and SHA-256, config identity, original blob sources,
`rootfs.diff_ids`, entry metadata, link/whiteout declarations and every regular
payload digest with the report. Original data offsets and actual file-header
offsets are checked; a Python `TarInfo.offset` preceding PAX metadata is not
mistaken for the actual file header.

```
/usr/bin/python3 tools/native-compare/oci-image-fixtures.py out/oci-native
/usr/bin/python3 tools/native-compare/oci-images.py target/debug/analyze-anything \
  out/oci-native/native-inert.oci.tar out/oci-native/native-inert.docker.tar \
  --record out/oci-native/reference.json
```

For Docker-save, `manifest.json` declares paths to config and layer members; it
does not contain OCI size/digest descriptors. Skopeo's registry-style raw manifest
for that archive is a native synthesized view, not an original archive record.
The reader's measured Docker layer digest remains distinct from declared digests;
the config's `rootfs.diff_ids` bind the captured uncompressed layer bytes.

Layers are retained separately. Whiteouts, links, permissions, entrypoint, command,
environment, exposed ports and volumes are read as data; no merged filesystem,
effective configuration, installation eligibility, signature trust or registry
resolution is established.

The initial Ubuntu 24.04 comparison at run 46107713227 found an independent writer
boundary: `umoci insert` emitted decoded layers of 5,651, 512 and 1,573 bytes whose
last entries were present, but final TAR padding and zero trailers were absent.
Python's TAR reader stopped with an unexpected-end error. Those initial archives
do not qualify the strict complete-TAR profile. The recipe now finalizes the TAR
layers before handing them to native `raw add-layer`; neither parser nor reference
silently pads or reinterprets the old bytes.

Primary format references:
[OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md),
[descriptors](https://github.com/opencontainers/image-spec/blob/main/descriptor.md),
[manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md),
[configuration](https://github.com/opencontainers/image-spec/blob/main/config.md),
[filesystem layers](https://github.com/opencontainers/image-spec/blob/main/layer.md),
[native umoci insertion](https://umo.ci/),
[skopeo local image inspection](https://github.com/containers/skopeo/blob/main/docs/skopeo-inspect.1.md).
