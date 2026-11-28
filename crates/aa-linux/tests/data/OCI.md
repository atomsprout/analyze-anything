# OCI and Docker-save native fixtures

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
