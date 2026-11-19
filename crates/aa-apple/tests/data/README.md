# Test fixtures

Small files the tests in `src/e2e.rs` read with `include_bytes!`. Each is under 200 KB.

| File | What it is | How it was made |
|---|---|---|
| `tiny.dmg` | A UDIF image of a 1 MiB HFS+ volume with four files, a symbolic link, a hard link and a file in two extents. Its chunks use zlib, bzip2, LZMA, ADC, raw and zero. | `python3 make_dmg.py tiny.dmg`. The empty volume comes from `mkfs.hfsplus` (hfsprogs 540.1); the script adds catalog records and wraps the volume. The bare volume (`--raw`) was extracted with 7-Zip 23.01 and with the `hfsplus` 0.4 crate; both give the same file contents as this crate. |
| `apfs-empty.dmg` | A UDIF image of an APFS container with one empty volume named `TinyAPFS`. | `truncate -s 128M a.img; mkapfs -L TinyAPFS a.img` (apfsprogs 0+git20231203), then `python3 make_dmg.py --wrap a.img apfs-empty.dmg "disk image (Apple_APFS : 0)"`. `apfsck` accepts the container. APFS volumes with files were checked on real images only, see `docs/spikes/dmg.md`. |
| `rectangle-arm64.codesig` | The code-signature SuperBlob (`LC_CODE_SIGNATURE` data) of the arm64 slice of `Rectangle.app/Contents/MacOS/Rectangle`, Rectangle 0.93 (MIT licence, github.com/rxhanson/Rectangle). Developer ID signature with a timestamp. | Cut from the release DMG at the offset and length of the load command. Expected values in the test are from `rcodesign print-signature-info` (apple-codesign 0.29). |
| `LaunchAtLogin.macho` | A whole universal Mach-O (x86_64 + arm64, 139 KB) signed with a Developer ID: `Stats.app/Contents/Library/LoginItems/LaunchAtLogin.app/Contents/MacOS/LaunchAtLogin` from Stats (MIT licence, github.com/exelban/stats), release of 2026-11-15. | Copied unchanged from the release DMG. Expected cdhashes, identifier, team and page counts are from `rcodesign print-signature-info`. |
| `node-pkg-head.xar` | The first 14 849 bytes of `node-v22.11.0.pkg`, the Node.js installer (MIT licence, nodejs.org/dist/v22.11.0): xar header, table of contents, checksum and both signatures (RSA and CMS). The files' data is cut off. | `curl -r 0-262143`, then cut at the end of the last signature. The signature covers only the table of contents, so it verifies without the payload. |
| `synthetic.mobileprovision` | A provisioning profile with made-up content (team `TEAM`, two fake device identifiers), CMS-signed by a throwaway self-signed certificate. | `openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 3650 -subj "/CN=Test Profile Signer/O=Analyze Anything Tests"`, then `openssl cms -sign -binary -nodetach -in profile.plist -signer c.pem -inkey k.pem -outform DER -md sha256`. The key was deleted. |

Everything else the tests use (Mach-O files with ad-hoc signatures, property lists, xar and
cpio archives, `CodeResources`) is built by the test code itself.
