# SquashFS qualification inputs

`upstream-hello-world-29.snap` is the unchanged Canonical hello-world revision 29
from the Snap Store, 20,480 bytes:

https://api.snapcraft.io/api/v1/snaps/download/buPKUD3TKqCOgLEjjHx5kSiCpIs5cMuQ_29.snap

SHA-256: `a14a4c44b085499d45f4182388b941fc9d5d87c5fe04f7405e087f52da61c407`.
The publisher's current Store/API declaration is MIT; the declaration and standard
license text are in `LICENSE-hello-world.txt`. No snap is installed. Shell files,
including the unusually named `bin/evil`, are bytes to read and never instructions
to run.

`squashfs-native.ref.json` is the project-authored 7-Zip 25.00 read-only reference:
all nine paths/types/modes/owners and six regular-file sizes and SHA-256 values.
The Rust tests compare every member against this hash-bound record. References
were generated on Windows with `tools/native-compare/squashfs.py --native-only`;
the script uses `7z l -slt` and `7z x -so` and creates no extracted file tree.
The complementary `linux-images.py` compares supported inputs with Linux
`unsquashfs -lln` and `-cat`, without mounting them or executing their contents.

The qualified real profile is SquashFS v4.0, little endian, with XZ data and
metadata blocks. Constructed Rust inputs additionally exercise zlib-compressed
file blocks, fragments, symlinks, cross-block metadata cursors, count/extent/type
disagreements, cycles/depth, decompression limits, shared data/fragment budgets
and oversized XZ dictionaries. The gzip/fragment profile still requires native
Linux-generated fixture qualification. No claim is made for all SquashFS tools,
extended inode combinations or compressor options.

The implementation reads common and extended file/directory inodes, symlinks,
ID and fragment tables, with a 1 MiB data block limit, 8 KiB metadata block limit,
16 MiB shared decoded metadata, 4,096 cached metadata blocks, 100,000 inode/fragment
declarations, depth 64, 4,096-byte paths / 16 MiB combined path bytes, 256 MiB per
file, 262,144 shared file-block descriptors, 512 MiB shared data decompression and
16 MiB fragment cache. XZ dictionary/decoder memory is limited to 32 MiB before
dictionary allocation. Sparse blocks are supplied as logical zero bytes.

LZMA/LZO/LZ4/Zstandard compression, other filesystem versions and non-UTF-8 names
are explicit unsupported profiles. Symlinks/devices/sockets/FIFOs remain metadata;
xattr/ACL semantics, export indexes, mounting eligibility and runtime behavior
remain unresolved. Input `bytes_used` and every addressed metadata/data extent
are checked before reading. The filesystem is never mounted.

Format reference: Linux `fs/squashfs/squashfs_fs.h`,
https://github.com/torvalds/linux/blob/master/fs/squashfs/squashfs_fs.h.
