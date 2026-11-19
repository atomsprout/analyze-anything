# Spike 4: verifying APK signatures in pure Rust

Date: 2026-11-18. Code: `crates/aa-android/src/` — `zipraw.rs` (ZIP structures), `sigblock.rs`
(APK Signing Block, v2/v3/v3.1), `jarsign.rs` (v1), `der.rs` + `x509.rs` (certificates and
PKCS #7), `crypto.rs` (signature checks), `emit_signing.rs` (findings). Question of the spike:
can the tool say "this signature verifies" with the same authority as `apksigner verify`, using
only permissively licensed Rust code, and where does it stop?

**Answer: yes for v1, v2, v3 and v3.1.** On 21 purpose-built files (valid, tampered, stripped,
rotated; RSA, EC and DSA keys) and 13 real APKs the verdicts equal those of `apksigner`, with
one explained difference where the reference tool at hand is older than the format (Signal's
v3.1). v4 and source stamps are detected, not verified.

## What is checked

| Scheme | Checked | Not checked |
|---|---|---|
| v1 (JAR) | (1) SHA-1/256/384/512 digest of **every** entry of the central directory against `META-INF/MANIFEST.MF`; an entry the manifest does not list, or a manifest entry with no file, fails the scheme. (2) `.SF` → manifest: the whole-file digest, or else the main-attributes digest and every per-entry section digest. (3) the PKCS #7 `SignedData` in `.RSA`/`.DSA`/`.EC`: signer certificate found by issuer and serial, `messageDigest` attribute equals the digest of the `.SF`, signature over the signed attributes (or over the `.SF` when there are none). BER indefinite lengths are accepted. `X-Android-APK-Signed` is read to detect stripped v2/v3. | More than one PKCS #7 signer per block (the first is used). Counter-signatures and timestamps. That all signature files cover the same entries. MD5 digests (rejected, as on Android). |
| v2 | Block located from the end record (magic, both size fields, id-value pairs). Per signer: content digest recomputed — 1 MiB chunks over the entries section, the central directory, and the end record with its central-directory offset set to the block's offset; SHA-256 and SHA-512 — and compared with the signed data; **every** signature of a known algorithm verified over the signed data with the signer's public key; that key equals the key of the first certificate; signature and digest algorithm lists agree. Stripping-protection attribute (`0xbeeff00d`) read. | fs-verity digests (algorithms `0x0421`/`0x0423`/`0x0425`): reported as not checked. |
| v3, v3.1 | As v2, plus: the SDK range in the signed data equals the signer's; proof-of-rotation attribute (`0x3ba06f8c`) parsed and every link verified (each node's signed data against the previous certificate's key); the lineage must end at the signing certificate. Rotation-min-SDK attribute (`0x559f8b02`) read. | Whether the signers' SDK ranges cover every platform version without gaps. Lineage capability flags are reported, not interpreted. |
| v4 | A `<name>.apk.idsig` beside the APK is reported. | Everything else. |
| Other blocks | Listed by id with a name where known: source stamp v1/v2, verity padding, Google Play frosting, dependency info, channel blocks. `META-INF/stamp-cert-sha256` is reported. | Source stamp verification. |

Signature algorithms: RSA PKCS #1 v1.5 and RSASSA-PSS (SHA-256/512; for v1 also MD5, SHA-1,
SHA-224, SHA-384), ECDSA on P-256, P-384 and P-521, DSA. Other curves or key types give "not
checked" with the reason, never "invalid".

A file with bytes after the ZIP end record fails every scheme, because `apksigner` refuses it
("not a ZIP archive") and the v2+ rules require the end record to end the file. ZIP64 archives
are reported as not checked for v2+.

The report gives per scheme: verified, failed (with the first reason), or not checked (as a
limitation, with the reason). The `android.signing` fact holds the detail per signer (content
digest, signature, problems, certificates, lineage) and `install_check`: whether every scheme
present verifies, nothing is stripped, and a v1 signature exists when the manifest's
`minSdkVersion` is below 24. That is the rule `apksigner verify` applies by default, and it is
what the tests compare.

## Getting at the file Android sees

Two of the checks above only make sense on the package as the platform reads it, which is not
always what a ZIP library sees. `crates/aa-android/src/unpack.rs` adds an unpacker that runs
before the generic ZIP one and claims a file only when it has an `AndroidManifest.xml` in its
central directory and one of these traits: it does not start with a ZIP header (the Janus
layout: `v1-janus.apk` is otherwise not opened at all), or an entry has a compression method
other than stored/deflate or the encryption flag. Android reads any method but deflate as
stored, with the uncompressed size, and ignores the flag; `unzip` and the `zip` crate refuse
such entries ("BadPack"). The same reading rules are used for the v1 entry digests. A hand-made
package with a stored manifest marked as method `0x1d2a` is rejected by `unzip` and analyzed in
full here; no real malware sample was tested.

## Differences from apksigner, by design

- **Every signature is verified**, not only the strongest one a given platform would pick, and
  v1 is verified even when `minSdkVersion` ≥ 24 makes `apksigner` skip it. A file can therefore
  fail here on a signature Android would never look at; none of the samples does.
- **No trust decisions.** Certificates are not validated (Android does not either): no chain,
  no expiry. Known-public keys (the eight AOSP test keys, by SHA-256 computed from the
  certificates in AOSP `platform/build`) and `CN=Android Debug` are flagged, as are RSA/DSA keys
  under 2048 bits and MD5/SHA-1 certificate signatures.
- **Anomalies apksigner passes silently** are reported: data before the first entry (as Janus,
  CVE-2017-13156, when it starts with a DEX header), duplicate entry names, local headers that
  disagree with the central directory, encrypted or oddly compressed entries, signers that
  differ between schemes without a lineage to explain it.

## Verification

### Fixtures (`crates/aa-android/tests/data/`, built by `make-fixtures.sh`)

A hand-written package signed with throwaway keys by `apksigner` 0.9; `expected.tsv` records
what `apksigner verify --verbose --print-certs` said. The test `signatures_agree_with_apksigner`
compares accept/reject, the schemes verified and the signer certificate's SHA-256 for all rows.

| File | apksigner | aa | What fails |
|---|---|---|---|
| `v1`, `v1v2`, `v1v2v3`, `full` (RSA 2048) | verifies | verifies | |
| `v2-ec`, `v3-ec` (P-256, no v1; verified for API 24 / 28) | verifies | verifies | (for the manifest's API 21: rejected by both, no v1) |
| `debug`, `weak` (RSA 1024, SHA1withRSA certificate) | verifies | verifies | flagged as debug certificate / weak key |
| `dsa` (DSA 2048), `ec384` (P-384, SHA-512 digests), `rsa4096` (SHA-512 digests) | verifies | verifies | |
| `rotated` (v1+v2 old RSA key, v3 new EC key, lineage) | verifies | verifies | lineage link verified; no signer mismatch reported |
| `v1-entry-modified` | rejects | rejects | v1: digest of `classes.dex` |
| `v1v2-entry-modified`, `v1v2v3-entry-modified`, `v3-ec-entry-modified` | rejects | rejects | chunked SHA-256 mismatch (and v1 where present) |
| `v1v2-block-modified` | rejects | rejects | v2 signature over signed data; v1 still verifies |
| `v1-appended`, `v1v2-appended` | rejects | rejects | bytes after the end record |
| `v1v2-stripped` | rejects | rejects | `.SF` names v2, block is gone |
| `v1-janus` (DEX in front of a v1-signed APK) | verifies | verifies | reported as Janus, High |

21 of 21 agree.

### Real APKs

Downloaded from the projects' GitHub releases; reference: `apksigner` 0.9 (Debian).

| APK | Size | Schemes apksigner verified | aa | Signer SHA-256, SHA-1, DN, key |
|---|---|---|---|---|
| Droid-ify 0.6.3 | 4 MB | v1 v2 v3 | same | equal |
| NewPipe 0.27.7 | 12 MB | v1 v2 v3 | same | equal |
| LibreTube 0.27.0 | 10 MB | v1 v2 | same | equal |
| Thunderbird 8.0 | 11 MB | v1 v2 v3 | same | equal |
| Termux 0.118.1 (GitHub debug build) | 33 MB | v2 | same | equal |
| LocalSend 1.17.0 | 17 MB | v1 v2 | same | equal |
| Joplin 2.14.9 | 44 MB | v1 v2 | same | equal |
| Bitwarden 2024.6.0 (Xamarin) | 71 MB | v1 v2 v3 | same | equal |
| Bitwarden 2025.1.0 | 73 MB | v2 | same | equal |
| Element 1.6.20 | 74 MB | v1 v2 v3 | same | equal |
| Immich (latest) | 187 MB | v2 | same | equal |
| Signal 7.30.2 | 104 MB | v1 v2 | v1 v2 **v3 v3.1** | equal for the v1/v2/v3 signer |
| Mattermost 2.22.0 (unsigned build) | 154 MB | rejects (no signature) | unsigned | — |

Signal is the one difference. The APK carries v3 for API 24–32 with the original key and v3.1
for API 33+ with a rotated key and a two-certificate lineage. `apksigner` 0.9 predates v3.1,
warns about the unknown attribute `0x559f8b02` and reports v3 as not verified; here both blocks
verify, digests and signatures included, and the lineage link checks out. A current apksigner
was not available to confirm this independently. Signal's original key is RSA 1024, which the
report flags.

The app bundle `com.x8bit.bitwarden.aab` (2025.1.0) is JAR-signed; its v1 signature verifies
(751 files). No reference tool was run on it.

### Malformed input

Every reader (`zipraw`, `sigblock`, `jarsign`, `der`, `x509`) has tests with truncations at
every length and single-byte corruption over the whole structure; `damaged_package_file_does_not_panic`
runs the whole analyzer over a signed fixture with bytes of the signing block, central directory
and end record overwritten. No count or length from the file drives an allocation; lists are
capped (16 signers, 64 items per list, 400 000 ZIP entries).

## Cost

Release build, 4 loaded cores, whole `analyze-anything analyze` run including all other analyzers: Signal
(104 MB, 5 020 entries, four signatures) 3.1 s; Immich (187 MB) 2.3 s; Droid-ify 0.2 s. The
signature work is two passes over the file (v1 entry digests, v2+ chunk digests), single-threaded.

## Dependencies

RustCrypto `rsa` 0.9, `p256`/`p384`/`p521` 0.13, `dsa` 0.6, `sha1`, `sha2`, `md-5` (all MIT OR
Apache-2.0), `flate2` for entry data, `base64`. DER, X.509 and PKCS #7 are read by a small reader
of our own (`der.rs`, about 150 lines) rather than `x509-cert`/`cms`: signing certificates in
the wild include encodings strict DER parsers refuse, and the report needs only a handful of
fields plus the exact signed bytes.

## Open ends

- v4 (`.idsig`) and source stamp verification.
- fs-verity content digests.
- Confirming the v3.1 result against a current `apksigner`.
- The v1 check reads every entry once more than the unpacker did; sharing the digests with the
  engine would halve the I/O.
