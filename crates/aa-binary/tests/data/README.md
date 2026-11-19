# Fixtures for aa-binary

Small executables built from the sources in `src/` by `build.sh` (gcc 13, clang/lld 18,
mingw-w64 13 on Ubuntu 24.04). Nothing here is third-party code. The tests in
`crates/aa-binary/src/tests/` hold the values `readelf`, `llvm-readobj`, `llvm-otool` and
`llvm-nm` printed for these exact files, so rebuilding with another toolchain version changes
addresses, build ids and timestamps and needs the expected values updated.

| File | What it is | Made with |
|---|---|---|
| `elf_hardened` | x86-64 PIE, full RELRO, stack protector, FORTIFY, stripped | `gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -Wl,-z,relro,-z,now -s` |
| `elf_weak` | x86-64 non-PIE, executable stack, no RELRO, no canary, RUNPATH, symbols and DWARF | `gcc -O0 -g -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro -Wl,-rpath,…` |
| `elf_lib.so` | x86-64 shared library with a soname and two exports | `gcc -shared -fPIC -Wl,-soname,libfixture.so.1 -s` |
| `elf_i386.o` | 32-bit little-endian relocatable object | `clang --target=i386-linux-gnu -c` |
| `elf_aarch64_be.o` | 64-bit big-endian relocatable object | `clang --target=aarch64_be-linux-gnu -c` |
| `elf_static` | static x86-64 executable, section headers removed | `ld.lld -static`, `llvm-strip --strip-sections` |
| `pe_mingw64.exe` | PE32+ console program, MinGW | `x86_64-w64-mingw32-gcc -O2 -s` |
| `pe_mingw32.dll` | PE32 DLL with two exports, MinGW | `i686-w64-mingw32-gcc -O2 -s -shared` |
| `pe_msvc64.exe` | PE32+, MSVC ABI, no CRT: CodeView/PDB reference, REPRO timestamp, load config with security cookie, GUARD_CF, one delay-loaded DLL | `clang --target=x86_64-pc-windows-msvc`, `lld-link /guard:cf /debug /Brepro /delayload:USER32.dll` |
| `pe_msvc32.exe` | PE32, MSVC ABI, no CRT: no ASLR, no DEP, relocations stripped, fixed timestamp | `clang --target=i686-pc-windows-msvc`, `lld-link /dynamicbase:no /nxcompat:no /fixed /timestamp:1700000000` |
| `pe_overlay.exe` | `pe_msvc32.exe` with the four bytes `DATA` appended | `cp`, `printf` |
| `macho_arm64` | arm64 macOS executable, PIE, stack protector, rpath, ad-hoc signature | `clang --target=arm64-apple-macos12 -fstack-protector-all -c`, `ld64.lld` against `src/libSystem.tbd` |
| `macho_x86_64` | x86-64 macOS executable, no PIE, no stack protector | `clang --target=x86_64-apple-macos10.13 -fno-stack-protector -c`, `ld64.lld -no_pie` |
| `macho_fat` | universal binary of the two above | `llvm-lipo -create` |
| `macho_arm64.o` | arm64 relocatable Mach-O object | `clang --target=arm64-apple-macos12 -c` |

`src/libSystem.tbd` is a hand-written stub naming the few libSystem symbols the fixtures import,
so that `ld64.lld` can link without an Apple SDK. `src/kernel32.def` and `src/user32.def` serve
the same purpose for the PE fixtures through `llvm-dlltool`.
