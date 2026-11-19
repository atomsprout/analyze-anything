Inputs the fuzzer found that once crashed the engine. The damaged-input test runs each of them
(and corrupted variants) and requires a report.

- `fuzz-nsis-bzip2-panic.bin` — a panic inside the third-party NSIS decoder; unpackers are now
  guarded like analyzers.
- `fuzz-dmg-sector-overflow.bin` — a disk image trailer claiming a sector count whose size in
  bytes overflowed.
