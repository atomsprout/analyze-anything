# Known limitations

This lists what the tool itself cannot do or has not been verified to do. Specific problems met during a single analysis are written in the "Coverage and limitations" chapter of that report.

## Not done by design

- It does not execute, install or dynamically debug the object being analyzed.
- It starts no other program, with one exception that is off unless asked for: `--deep` hands program files to Ghidra or Hopper to be disassembled (see [DEEP.md](DEEP.md)). What that level was tried on, and what it misses, is said there.
- It does not decompile to pseudocode.
- It does not decrypt, unpack protected code, or bypass any protection. The main executable of an IPA downloaded from the App Store is encrypted with FairPlay, and its code segment cannot be read; the real code of a packed APK is not visible. These cases are identified and written into the report.
- Analysis does not use the network. It therefore does not check certificate revocation, whether a root certificate is trusted, or Apple notarization status. The only thing that uses the network is the optional AI interpretation, which does nothing until you set it up (see [AI.md](AI.md)).
- The AI interpretation checks only that the findings each statement cites exist in the report. It does not check that the model understood them, or that it drew no conclusion of its own from several of them. Each of its engines has produced a full answer for real at least once; [AI.md](AI.md) says exactly what was tried and with which model.
- It gives no "safe / unsafe" verdict and no single score; it only lists findings and their severity.

## Parts not verified on real samples

The following features have only been tested with data we constructed ourselves, and have not been compared against reference tools on real samples:

- **Apple**: APFS snapshots and multiple volumes, ECDSA signatures. An encrypted DMG is identified but cannot be read. FairPlay-encrypted IPAs downloaded from the App Store have been verified on real samples: the encryption is identified, metadata, signatures and resources are analyzed as usual, and the encrypted code cannot be read.
- **Windows**: Inno Setup 6.4 files can be extracted, but the reference tool cannot read this version, so the result cannot be checked; NSIS 1.x / 2.x and forked versions are untested; an MSI's own digital signature is verified (content digest, metadata digest, signature value, certificate chain), with osslsigncode as the reference tool and no comparison against Windows' own signtool; the position of the `MsiDigitalSignatureEx` stream in the digest has two readings, and when only the other reading matches, it is reported as "could not verify" without drawing a conclusion; a RAR self-extractor only has its appended data exported and is not unpacked (for license reasons); Quantum-compressed CABs, multi-volume CABs and external CABs are not unpacked.
- **Android**: XAPK / APKS have only been tested with hand-built samples; packers, Janus and unusual compression methods have only been tested on constructed samples; for AAB only the base module is analyzed in depth; a manifest in text format (apktool output) is not decoded.
- **Binaries**: Mach-O imports and exports are read from the symbol table, the export trie, chained fixups and bind opcodes, and have been compared against `dyld_info`, `nm` and `objdump`; compressed symbol names in chained fixups and the big-endian format are not read (recorded as a limitation). PE delay imports have only been verified on samples we constructed ourselves.

## Systems it has been verified on

The automated tests pass on Linux, macOS and Windows (GitHub Actions). Release builds were run successfully on Linux x64 / arm64, macOS arm64 / x64 and Windows x64 and passed the self-check. The large-scale comparison using release packages of open source projects was done on Linux.

It has been tested with real samples on one Apple silicon Mac (macOS 27): 8 installed applications (all 332 items match `codesign`), an encrypted IPA downloaded from the App Store and a decrypted IPA, and two DMGs (one of which unpacked to 7461 files). On the same Mac, version 0.1.1 was run over every app in the Applications folder (52 apps, 677,336 files); the findings that looked wrong were compared with `codesign` and the differences fixed ([TODO.md](TODO.md) lists them). The desktop app has only been verified on this Mac. Testing on a real Windows machine has not been done yet.

## Comparison with the system's own tools

The "Native comparison" workflow runs on GitHub's macOS and Windows machines and checks results against the system's own tools (the scripts are in `tools/native-compare/`). The most recent run passed completely:

- **macOS (98 items)**:
  - An item-by-item comparison with `codesign` of every architecture slice of system applications (Calculator, TextEdit, Terminal, Safari) and Rectangle: cdhash, identifier, team, flags, certificate chain, entitlement keys.
  - After a resource file or the code is modified, both `codesign --verify` and this tool report a failure.
  - Rectangle's DMG matches the mounted volume file by file.
  - HFS+ / APFS images generated on the spot with `hdiutil`, covering six methods (zlib, bzip2, LZFSE, LZMA, ADC, uncompressed) as well as files compressed inside the file system, all match file by file.
  - An encrypted image is identified as encrypted, and no file is claimed to have been read.
  - pkgs generated by `pkgbuild` in both the gzip and pbzx formats match file by file.
- **Windows (132 items)**:
  - A comparison with `Get-AuthenticodeSignature` on more than 40 system and common programs: whether an embedded signature is present, the signing certificate thumbprint, and whether all of this tool's checks pass when the status is "Valid".
  - After one byte is changed, Windows reports HashMismatch, and this tool's file digest check also fails.
  - Files extracted from MSZIP and LZX archives generated by `makecab` are byte-for-byte identical.

These comparisons do not cover: certificate revocation, root certificate trust, notarization status (this tool does not check these); they also do not cover iOS applications or App Store signatures.

## Other

- The fonts embedded for PDF only cover Chinese and Latin characters. Other scripts (Korean, Arabic, emoji and so on) appear as boxes in the PDF unless a font is added with `--font`; HTML and JSON are not affected.
- When an analyzer times out (300 seconds per file by default), it is abandoned and recorded as a limitation, and the run ends as usual; but on the command line the thread it runs on cannot be forcibly terminated and stays occupied until the process exits. The desktop app runs analysis in a child process and force-ends it if it has not exited within 5 seconds of cancellation. The unpack timeout (900 seconds per container by default) is only checked when the unpacker hands over the next file; an unpacker that never hands over a file is not interrupted.
- The executable with PDF is about 49 MB, of which the Chinese font is 8.6 MB.
- macOS has a command of its own called `aa` (Apple Archive). This program was called `aa` in its first releases (0.1.0 to 0.2.0 on Homebrew installed it as `analyze-anything`); it is `analyze-anything` everywhere now, with the short name `aaaa`.
- Heuristic findings (suspected credentials, packing, SDK identification) can be false positives; they are all marked "Heuristic" in the report.
- When the process is forcibly terminated, the files unpacked into the temporary directory are not cleaned up at that time (they are cleaned up on both normal exit and error); the next run clears these leftover directories when it starts.
- When two reports are diffed, findings are paired by "rule + file location within the input". Known artifact display parameters (including the largest-file path and the input bundle label) are normalized relative to the input. Arbitrary strings read from the input, including product names and embedded debug paths, remain literal; a difference in those values is still reported.
- Desktop app: history records only save the report, so a history report that is reopened cannot show hex evidence and the input must be analyzed again; there is no automatic update; on macOS no external tool can drive the system WebView, so the whole flow is covered by the application's self-check mode (see [DESKTOP.md](DESKTOP.md)), and the native menus, drag and drop, and system dialogs can only be checked manually.
