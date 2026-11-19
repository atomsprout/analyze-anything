Small archives used by the engine's damaged-input test. Each holds `a.txt` (one line of text)
and `sub/b.bin` (3000 random bytes), packed with the system `zip`, `tar` (plain, gzip, bzip2,
xz, zstd) and `7z` tools. An engine test checks each unpacks to the same SHA-256 digests.
