# Alpine APK v2 qualification

Alpine APK and Android APK are distinct format families. This reader handles
Alpine v2's concatenated gzip/TAR layout, not Android ZIP packages. The primary
format reference is [apk-tools' apk-v2 specification](https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-v2.5.scd).
Alpine ADB/v3 containers are explicitly unsupported.

## Supported profile

- Up to eight independently decoded gzip members: zero or more signature members,
  exactly one control member beginning with one root `.PKGINFO`, then one payload
  member. Each gzip member has exact source extents and checked CRC/ISIZE. Optional
  gzip name/comment/extra fields are bounded before decoder allocation.
- Signature and control TAR layers omit zero terminators; the payload requires a
  complete zero trailer with no hidden archive or nonzero bytes after it.
- Checked USTAR/GNU numeric and header checksums; local PAX metadata, including
  literal path/link overrides and `APK-TOOLS.checksum.*` declarations. Global PAX,
  GNU long-name/sparse profiles, PAX size overrides and base-256 numeric fields
  remain explicit gaps.
- Ordinary files are captured under `[signature-N]/`, `[control]/` and `[payload]/`.
  Layer facts retain physical compressed ranges, decoded hashes and TAR record
  offsets. An offset inside a decoded `.PKGINFO` or script is evidence on that
  captured logical file, never mislabelled as an offset in compressed input bytes.
- Original path/link/mode/owner/type and PAX declarations are retained. Links and
  special files remain metadata; no host links/devices are created or followed.
- Identity, literal dependencies/providers/replacements/install-if/triggers and
  script source come only from the control namespace. A payload `.PKGINFO` or
  `.post-install` cannot provide control identity or installation declarations.
  Recognizable credentials are redacted from retained text.

Limits are 256 MiB compressed input, 1 MiB per signature/control member, 128 MiB
payload, 136 MiB total decoded data, 100000 entries per TAR, 16 MiB of names per
TAR, 1 MiB of PAX metadata per TAR, 4096-byte paths/link targets, 4096 `.PKGINFO`
fields and 16 KiB per metadata line. Script text retention is capped at 256 KiB.
Unsupported lengths, malformed trailers and exhausted bounds have explicit limits.

Signatures, declared datahash and per-member hashes are **not verified**. Gzip CRC
and TAR header checks are structural transport checks; they do not authenticate
the package. Keys are not loaded. No script, dependency, trigger, installation
eligibility or host/repository state is evaluated.

## Redistributable sample

`libxxhash-0.8.3-r0.apk` is an unchanged Alpine Linux v3.22 main/x86_64 package:

- Source: https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/libxxhash-0.8.3-r0.apk
- SHA-256: `e3140cf609508b32db2aec81c8736e7db5d96c351857c99b364a6d1a913bb850`
- Size: 23642 bytes. Exact gzip members: 719, 575 and 22348 bytes.
- Metadata declares `libxxhash`, `0.8.3-r0`, `x86_64`, `BSD-2-Clause`; packaging
  commit `6e7967375f3dc136a45daa394d61ff677d9485f3`.
- Upstream source: https://github.com/Cyan4973/xxHash/tree/v0.8.3 ; copyright Yann
  Collet. `LICENSE-alpine-xxhash.txt` preserves its BSD-2-Clause notice.
- The `.SIGN.RSA.*.rsa.pub` member contains signature bytes, **not a public key or
  certificate**. Its filename is retained; it is never loaded as a key.

The real sample covers local PAX headers in all three layers, a cut control TAR,
one shared-library payload and a symlink declaration. Unsigned streams, scripts,
trigger declarations, duplicate controls, path escapes, malformed lengths/CRCs,
truncations and resource bounds also have constructed tests. APK v3, unusual TAR
variants and broader real installation-script packages have not been qualified.

## Independent inspection

`tools/native-compare/alpine-fixtures.py` builds project-authored inert unsigned
and signature-declaration packages; their scripts and synthetic signatures are
never run or called verified. `alpine-packages.py` uses independent Python zlib and
tarfile readers to compare exact stream boundaries, decoded hashes, every TAR
entry, authoritative identity/relationships and ordinary-file digests.

`alpine-native.ref.json` records 171 passing checks across the real package and
the two constructed packages on Windows x64, with GNU gzip 1.13 and Windows'
bsdtar/libarchive 3.8.9. The no-default-features CLI was used. This record qualifies
those bytes and tools; it does not substitute for integrated-head Linux checks.

With `--native`, it also requires `gzip -t` and `bsdtar -tf`; optional `apk manifest`
output checks actual payload digests. `.github/workflows/alpine-native.yml` obtains
that manifest using a network-disabled, read-only Alpine container. No `apk add`,
package installation, mounting or script invocation occurs. Native Linux results
remain pending until the workflow record for the integrated source is available.

```
python3 tools/native-compare/alpine-fixtures.py out/native-alpine
python3 tools/native-compare/alpine-packages.py target/debug/analyze-anything \
  crates/aa-linux/tests/data/libxxhash-0.8.3-r0.apk \
  out/native-alpine/native-unsigned.apk out/native-alpine/native-signature-declaration.apk \
  --native --record out/native-alpine/reference.json
```
