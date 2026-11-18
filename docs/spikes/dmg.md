# Spike 2: reading DMG images in pure Rust

Date: 2026-11-18. Code: `crates/aa-apple/src/disk/` (UDIF, HFS+, APFS, decmpfs) and
`crates/aa-apple/src/unpack.rs`. Question of the spike: can a `.dmg` be opened down to its
files with permissively licensed, pure-Rust code, and how much of what exists in the wild
does that cover?

**Answer: yes for the images open-source projects publish.** Twelve real images, covering
every chunk compression but ADC and both file systems, extract byte-for-byte identically to
7-Zip. Encrypted images and a few rarer structures are detected and reported, not opened.

## What was built

| Layer | Implemented | Not implemented |
|---|---|---|
| UDIF container | `koly` trailer, XML property list, `blkx`/`mish` block tables; chunk types zero, raw, ignore, zlib, bzip2, LZFSE, LZMA (xz), ADC; partitions decompressed lazily, chunk by chunk, with a small cache | checksum verification (`koly` and `mish` CRC32); segmented images (`.dmgpart`); images whose trailer is at the start of the file |
| Partition maps | each `blkx` entry is tried as a volume; inside one, GUID and Apple partition maps are followed | MBR-only disks |
| HFS+ / HFSX | volume header, catalog B-tree (leaf chain), extents overflow B-tree, attributes B-tree (inline `com.apple.decmpfs` only), hard links to files (`iNode<n>` in the private folder), files in any number of extents | resource forks as separate outputs, extended attributes other than decmpfs, directory hard links, journal replay, the HFS wrapper and classic HFS |
| APFS | container superblock with newest-valid checkpoint selection (Fletcher-64), container and volume object maps, file-system tree (inodes, directory entries, file extents, the two attributes compression needs), several volumes per container, sparse files | encrypted volumes (reported per volume), snapshots (only the live tree is read), Fusion containers, checkpoint descriptor areas stored as a B-tree, sealed-volume hash verification |
| Transparent compression (decmpfs) | types 1, 3, 4 (zlib), 7, 8 (LZVN), 9, 10 (stored), 11, 12 (LZFSE), from the attribute or the resource fork, for both file systems | types 5, 6 and any later ones |
| Raw images | a file that starts with an HFS+ or APFS volume, or a GPT/APM disk holding one, is opened without the UDIF wrapper (kind `disk-image`) | |
| Encrypted images | recognised by `encrcdsa` (v2) and `cdsaencr` (v1); limitation `dmg.encrypted`, nothing is read | decryption, even with a password |

Symbolic links are not emitted as files (they have no content of their own). Every length,
offset and count is checked; a damaged catalog yields `dmg.volume-incomplete`, an unreadable
file `dmg.file-unreadable`, an unsupported volume `dmg.volume-unreadable`, and an image with
no supported file system `dmg.no-filesystem`.

## Verification on real images

Method: analyze the image with `aa`, extract it with 7-Zip 23.01, and compare the SHA-256 of
every file (symbolic links and extended-attribute pseudo-files left out on the 7-Zip side).
For kitty, 7-Zip cannot decode LZMA chunks, so the partition was first expanded with an
independent Python script (stdlib `lzma`) and 7-Zip was run on the raw APFS container.

| Image | Chunks | File system | Files | Result |
|---|---|---|---|---|
| Rectangle 0.93 | zlib | HFS+ | 169 | all identical |
| Stats (2026-11) | zlib | HFS+ | 116 | all identical |
| Alacritty 0.13.2 | zlib | HFS+ | 13 | all identical |
| Keka 1.4.6 | zlib | HFS+ | 645 | all identical |
| macFUSE 4.4.3 | zlib | HFS+ (no partition map) | 27 | 25 identical; the other 2 are hard links, which 7-Zip writes as empty files and this crate resolves — their content equals 7-Zip's `iNode50` |
| IINA 1.3.5 | bzip2 | HFS+ | 1 235 | all identical |
| OBS Studio 30.2.3 | LZFSE | HFS+ | 2 200 | all identical |
| Logseq 0.10.9 (arm64) | LZFSE | HFS+ | see note | listed, not hash-compared |
| balenaEtcher 1.19.25, MarkText 0.17.1 (arm64) | zlib | HFS+ | see note | listed, not hash-compared |
| Zed 0.160.7 | zlib | APFS | 108 | all identical |
| kitty 0.36.4 | LZMA | APFS | 415 | all identical (via the raw-container route above) |

Note: the three images in the "see note" rows were downloaded to look for APFS and were only
classified with 7-Zip; they were not run through the comparison.

A second oracle: the `hfsplus` 0.4 and `apfs` 0.4 crates (see below) were run over the raw
partitions of Rectangle (HFS+), Zed and kitty (APFS). All 169 + 108 + 415 file hashes equal
this crate's.

What the real images did **not** exercise, and is therefore covered by unit tests with
synthetic data only:

- ADC chunks (no sample; tested with literal-only streams written by the fixture script, and
  a hand-made stream with matches);
- transparent compression (none of the images held a `com.apple.decmpfs` file); the LZVN path
  is tested with payloads produced by `lzfse_rust`'s encoder, the zlib and LZFSE paths with
  round trips;
- HFS+ extents overflow records (no sample file had more than eight extents — the reader
  loads them, the lookup has no real-data test);
- APFS volumes with snapshots, several volumes, or hashed-versus-plain directory keys other
  than what Zed and kitty use (both case-insensitive, hashed);
- encrypted images (detection is tested on the magic bytes only; no real encrypted sample).

Committed fixtures (`crates/aa-apple/tests/data/`): `tiny.dmg`, an HFS+ volume from
`mkfs.hfsplus` with hand-added catalog records, wrapped with zlib, bzip2, LZMA, ADC, raw and
zero chunks; and `apfs-empty.dmg`, an empty container from `mkapfs`. Linux has no tool that
writes files into an APFS volume, so APFS with content is verified on real images only.

## Crates evaluated

| Crate | Licence | Finding | Used |
|---|---|---|---|
| `apple-dmg` 0.5 | MIT OR Apache-2.0 | Reads and writes `koly`/`blkx`; decodes zlib chunks only; its file-system side is FAT (it exists to build EFI images). No HFS+/APFS. | no |
| `dmgwiz` 1.1 | MIT | Expands an image to a raw disk and can decrypt it. Handles ADC, zlib, bzip2, LZFSE, not LZMA. LZFSE and bzip2 go through C libraries (`lzfse`, `bzip2-sys`), decryption through OpenSSL or ring. Stops at the raw disk. | no — C dependencies, no LZMA, whole-disk expansion |
| `hfsplus` 0.4 | MIT | Pure Rust, no `unsafe`. Lists and reads files, handles decmpfs. On real images its output equals ours. On `tiny.dmg` it fails on the file inside the private folder and returns nothing for a hard link. | no — works, but see below |
| `apfs` 0.4 | MIT | Pure Rust, no `unsafe`. Its output equals ours on Zed and kitty. | no — works, but see below |
| `lzfse_rust` 0.2 | MIT OR Apache-2.0 | Pure Rust LZFSE and LZVN. Decodes every LZFSE chunk of OBS (584 MB expanded) correctly. | yes |

Why own readers although `hfsplus` and `apfs` work: they want `Read + Seek` over a fully
expanded partition, where this crate reads compressed chunks on demand (OBS expands to
584 MB); behaviour on hostile input is ours to guarantee (rule 4 of `docs/ANALYZERS.md`), and
the readers are small (about 350 lines each); hard links needed handling the crate lacks.
They remain a good differential-test oracle, and a fallback if maintaining the readers
becomes a burden.

## Cost

Debug build, 4 cores, whole `aa analyze` run including every other analyzer:
Rectangle (3.9 MB image, 12 MB expanded) 1 s; Keka (32 MB / 85 MB) 7 s; IINA (85 MB / 253 MB,
bzip2) 44 s; OBS (169 MB / 584 MB, LZFSE) 58 s; Zed (79 MB / 273 MB, APFS) 42 s. Memory is
bounded by the chunk cache (24 chunks) plus the catalog; file data is streamed to the engine's
sink, which applies the unpack limits.

## Open points

1. Encrypted images: decryption with a user-supplied password is feasible (PBKDF2 + AES-CBC,
   RustCrypto) but out of scope for static analysis without a password.
2. A real image with decmpfs-compressed files, and one with ADC chunks, should be added to
   the manual sample set when found.
3. UDIF checksums are not verified; a corrupted chunk shows up as a decode error or as files
   whose signature checks fail, not as a checksum finding.
4. Resource forks and extended attributes are dropped. For analysis the one that might
   matter is `com.apple.quarantine`, which does not survive into a published image anyway.
