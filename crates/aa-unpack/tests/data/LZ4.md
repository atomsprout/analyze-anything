# Native LZ4 frame fixtures

The four `native-*.txt.lz4` files are unchanged outputs of the LZ4 1.9.4
command line writer in Linux CI run
[46107713119](https://github.com/atomsprout/analyze-anything/actions/runs/46107713119)
at `69e9821`. The source is project-authored Apache-2.0 inert text:
`b"Analyze Anything native LZ4 fixture. Project-authored Apache-2.0 data.\n"`
repeated 3,000 times, or `b"abc"` for the short stored block.

`native-lz4.ref.json` records the exact compressed and decoded SHA-256 hashes,
writer flags, frame headers and 40 passing checks against native `lz4 -dc`.
`tools/native-compare/lz4-frames.py` reproduces the comparison without running
any input as code. The default test checks the pinned file hashes and compares
all decoded bytes with the original source recipe.

The supported profile is a single modern frame with independent blocks,
including stored and compressed blocks, optional content size and declared
block/content checksums. Limits are 4 MiB per block, 65,536 blocks and 256 MiB
decoded data per frame. Linked blocks, dictionaries, legacy/raw streams,
skippable frames and concatenated frames remain explicit unsupported profiles.
Checksum agreement detects corruption and does not authenticate a file.
