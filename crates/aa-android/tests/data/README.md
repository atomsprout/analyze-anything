# Fixtures of aa-android

Everything here is written by `make-fixtures.sh` in this folder; run it to rebuild. It needs the
Debian packages `aapt apksigner zipalign dalvik-exchange dexdump android-sdk-platform-23
default-jdk-headless gcc zip python3`. Keys are generated for the run and thrown away, so the
signatures (and the certificate fingerprints in `expected.tsv`) change with every rebuild; the
files are always rebuilt together.

The app is a tiny hand-written package, `com.example.aafixture`: a manifest that exercises the
manifest rules, two Java classes compiled with `javac` and `dx`, three native libraries built with
`gcc`, and a few asset files. No third-party code or data is included.

| File | What it is |
|---|---|
| `unsigned.apk` | The package without native libraries, aligned, not signed. Base of the signed variants. |
| `full.apk` | The package with native libraries, signed v1+v2+v3 (RSA 2048). |
| `v1.apk`, `v1v2.apk`, `v1v2v3.apk` | Signed with the same RSA key, with the schemes the name says. |
| `v2-ec.apk`, `v3-ec.apk` | Signed with an EC P-256 key, v2 only / v3 only (no v1). |
| `debug.apk` | Signed with a certificate named `CN=Android Debug, O=Android, C=US`. |
| `weak.apk` | Signed v1 with an RSA 1024 key and a SHA1withRSA certificate. |
| `dsa.apk`, `ec384.apk`, `rsa4096.apk` | Signed with a DSA 2048, an EC P-384 and an RSA 4096 key. The last two carry SHA-512 content digests. |
| `rotated.apk` | v1+v2 with the RSA key, v3 with the EC key and a rotation lineage RSA → EC (`apksigner rotate`). |
| `*-entry-modified.apk` | One byte of `classes.dex` flipped after signing. |
| `v1-appended.apk`, `v1v2-appended.apk` | Eight bytes appended after the ZIP end record. |
| `v1v2-block-modified.apk` | One byte inside the APK Signing Block flipped. |
| `v1v2-stripped.apk` | The APK Signing Block cut out, leaving a v1 signature that says v2 was applied. |
| `v1-janus.apk` | `classes.dex` placed in front of `v1.apk`, with all ZIP offsets moved (the Janus layout). |
| `set.xapk` | A ZIP holding `manifest.json`, `v1v2.apk` as the base APK and a split APK (`split="config.fixture"`) of the same package and signer. |
| `zip-tricks.apk` | Unsigned; `classes.dex` appears twice, and one local header name differs from the central directory. |
| `expected.tsv` | Per signed file: whether `apksigner verify` accepted it, which schemes it reported as verified, and the signer certificate's SHA-256. `v2-ec` and `v3-ec` were verified with `--min-sdk-version 24` / `28`. |
| `*.apksigner.txt` | The full output of `apksigner verify --verbose --print-certs` for each signed file. |
| `badging.txt`, `xmltree.txt` | `aapt dump badging` and `aapt dump xmltree … AndroidManifest.xml` of `full.apk`. |
| `AndroidManifest.bin`, `resources.arsc`, `network_security_config.bin`, `classes.dex` | Members of the package, extracted. |
| `dexdump-header.txt` | The header section of `dexdump -f classes.dex`. |

One deliberate oddity: the platform-23 `aapt` does not know `android:networkSecurityConfig`
(API 24). The manifest source uses `android:banner` in its place and the script then replaces the
attribute's resource id (0x010103f2 → 0x01010527) in the compiled manifest. Android reads
attributes by resource id, so this is a valid `networkSecurityConfig`; the name string still says
`banner`, which the analyzer reports as a manifest anomaly, and the tests expect that.
