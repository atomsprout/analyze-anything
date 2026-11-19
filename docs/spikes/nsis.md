# Spike 3: NSIS extraction and script recovery

Question from the plan: can NSIS installers be opened in pure Rust — embedded files extracted and
the install script recovered — or must they fall back to "PE plus opaque overlay"?

**Result: yes.** The `nsis` crate (0.6.1, Apache-2.0, `#![deny(unsafe_code)]`) does both. It is used
as it is; two gaps around uninstallers are closed in `crates/aa-windows/src/nsis.rs`.

## What was tested

Reference: 7-Zip 23.01 (`7z x`), comparing the SHA-256 of every extracted file.

| Installer | Variant | Files (7-Zip) | Identical |
|---|---|---|---|
| `tests/data/nsis-zlib.exe` (makensis 3.09) | NSIS 3 Unicode, deflate, non-solid | 5 | 5 |
| `tests/data/nsis-lzma-solid.exe` | NSIS 3 Unicode, LZMA, solid | 5 | 5 |
| `tests/data/nsis-bzip2-ansi.exe` | NSIS 3 ANSI, bzip2, solid | 5 | 5 |
| Notepad++ 8.6.9 x64 installer | NSIS 3 Unicode, LZMA, solid, 11 554 script entries | 242 | 242 |
| Motrix 1.8.19 setup (electron-builder) | NSIS 3 Unicode, 7z payloads in `$PLUGINSDIR` | 12 | 12 |

The three fixtures are compared in `tests/pipeline.rs` on every test run; the two real installers
were compared by hand (they are too large to commit).

Not tested, because no sample was built or found: NSIS 1.x and 2.x, the Jim Park Unicode fork,
logging builds, non-solid LZMA and non-solid bzip2. The crate's own test suite covers these
against 7-Zip listings, which was read but not re-run here.

## What the crate gives

- Detection of the first header in the PE overlay; header decompression for deflate, NSIS's own
  bzip2 variant and LZMA; solid and non-solid data blocks. A solid stream is decoded in memory
  under a byte budget (`max_decompressed_size`); when the budget is hit the header stays readable
  and `solid_status()` says so.
- Typed bytecode: entries with version-aware opcode numbering, strings with variables and shell
  folders resolved to names (`$INSTDIR`, `$SMSTARTUP`, `$PLUGINSDIR`).
- Analysis iterators: `files()`, `registry_ops()`, `exec_commands()`, `shortcuts()`,
  `plugin_calls()`, `uninstallers()`; `to_install_path()` names files the way 7-Zip does.
- `format_entry_params()` renders one entry as text. The analyzer writes all entries to a child
  named `[NSIS script].txt`, so the URLs and commands in the script reach the other analyzers.
  That child is a reconstruction, not a file of the installer, and a limitation
  (`nsis.script-synthetic`) says so in every report.

## What had to be added

1. **Uninstaller stub patches.** `Uninstaller::decompress()` returns the installer's stub followed
   by the uninstaller's data, without applying the icon patch list NSIS stores in front of that
   data (`size, offset, bytes` records, ending at a zero size). The result differed from 7-Zip's
   `uninstall.exe` in the icon bytes. `uninstaller_image()` applies the patches; all three fixtures
   then match.
2. **Whole-uninstaller variant.** When the script's `WriteUninstaller` entry has icon size 0, the
   block at its data offset is not a patch list but the complete uninstaller program (seen in the
   Notepad++ installer, whose uninstaller is separately signed). The crate reports
   "uninstaller icon data length prefix: expected at least 4 bytes". `uninstaller_image()` returns
   the block as it is when it starts with `MZ`; the result equals 7-Zip's.
3. **One destination, several contents.** `files()` yields every `File` instruction. The same data
   written to the same path from several sections is kept once; different data for the same path
   (per-language bitmaps in the Notepad++ installer) is kept in full, where 7-Zip keeps only one.
4. **Plug-in arguments.** Plug-ins take their arguments from the NSIS stack, which the crate does
   not model. The analyzer pairs a plug-in call with the strings pushed directly before it. This
   is positional guesswork: it is used only for download plug-ins (`inetc`, `NSISdl`), `nsExec`
   and `SimpleSC::InstallService`, and the evidence text says the pairing is by position.

## Known limits

- An installer built with a makensis compiled with non-default options numbers its opcodes
  differently; the crate rejects what does not decode consistently, and the file is then reported
  as `unpack_failed` and analyzed as a plain PE.
- Values computed at install time (`$R0`, registry reads, plug-in results) stay as variable names.
  A path such as `$R0\Uninstall Motrix.exe` is reported as written.
- The solid budget is 2 GiB for extraction and 16 MiB when only the script is needed.
- Entry numbers in evidence (`script entry 14`) are indexes into the entry table of the main
  header, as listed in `[NSIS script].txt`.
