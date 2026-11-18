#!/bin/sh
# Rebuilds the fixtures in this directory. Needs gcc, clang + lld (LLVM 18), mingw-w64.
# Outputs depend on toolchain versions; tests/reference.rs holds the values reference tools
# (readelf, llvm-readobj, llvm-objdump) printed for the committed files.
set -eu
cd "$(dirname "$0")"
LLVM=/usr/lib/llvm-18/bin

# ELF, hardened: PIE, full RELRO, canary, FORTIFY, stripped.
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE -Wl,-z,relro,-z,now -s -o elf_hardened src/hello.c
# ELF, weak: fixed address, executable stack, no RELRO, no canary, RUNPATH, symbols and DWARF kept.
gcc -O0 -g -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -no-pie -z execstack -Wl,-z,norelro -Wl,-rpath,'$ORIGIN/lib:./plugins' \
    -Wl,--enable-new-dtags -o elf_weak src/hello.c
# ELF shared library with a soname.
gcc -O2 -shared -fPIC -Wl,-soname,libfixture.so.1 -s -o elf_lib.so src/lib.c
# ELF 32-bit little-endian and 64-bit big-endian relocatable objects (no libc needed).
clang --target=i386-linux-gnu -O1 -c -o elf_i386.o src/freestanding.c
clang --target=aarch64_be-linux-gnu -O1 -c -o elf_aarch64_be.o src/freestanding.c
# ELF static executable without section headers or libc: nothing to judge a canary by.
clang --target=x86_64-linux-gnu -O1 -ffreestanding -fno-stack-protector -c -o /tmp/aa_static.o -x c - <<'C'
void _start(void) { for (;;) {} }
C
ld.lld -static --no-rosegment -o elf_static /tmp/aa_static.o
"$LLVM/llvm-strip" --strip-sections elf_static

# PE, MinGW: 64-bit console program (GCC stack protector, COFF symbols stripped) and a 32-bit DLL.
x86_64-w64-mingw32-gcc -O2 -s -o pe_mingw64.exe src/hello.c
i686-w64-mingw32-gcc -O2 -s -shared -o pe_mingw32.dll src/lib.c
# PE, MSVC ABI through clang + lld-link, no C runtime: CodeView/PDB reference, load config with
# a security cookie, CFG flag, high-entropy ASLR, one delay-loaded DLL. One 64-bit, one 32-bit
# without ASLR/DEP.
"$LLVM/llvm-dlltool" -m i386:x86-64 -d src/kernel32.def -l /tmp/aa_k64.lib
"$LLVM/llvm-dlltool" -m i386:x86-64 -d src/user32.def -l /tmp/aa_u64.lib
sed 's/^ExitProcess$/ExitProcess@4/' src/kernel32.def > /tmp/aa_k32.def
"$LLVM/llvm-dlltool" -m i386 -k -d /tmp/aa_k32.def -l /tmp/aa_k32.lib
clang --target=x86_64-pc-windows-msvc -O1 -c -o /tmp/aa_msvc64.obj src/msvc.c
lld-link /nologo /entry:entry /subsystem:console /nodefaultlib /guard:cf /debug /pdb:/tmp/aa_msvc64.pdb /pdbaltpath:C:\\build\\fixture\\msvc64.pdb \
    /delayload:USER32.dll /Brepro /out:pe_msvc64.exe /tmp/aa_msvc64.obj /tmp/aa_k64.lib /tmp/aa_u64.lib
clang --target=i686-pc-windows-msvc -O1 -c -o /tmp/aa_msvc32.obj src/msvc.c
lld-link /nologo /entry:entry /subsystem:windows /nodefaultlib /dynamicbase:no /nxcompat:no /fixed /safeseh:no /timestamp:1700000000 \
    /out:pe_msvc32.exe /tmp/aa_msvc32.obj /tmp/aa_k32.lib
# The same 32-bit program with four bytes appended: an overlay.
cp pe_msvc32.exe pe_overlay.exe
printf 'DATA' >> pe_overlay.exe

# Mach-O: arm64 and x86_64 executables linked with ld64.lld against a stub libSystem, and a
# universal binary of the two. The x86_64 one is built without PIE and without a stack protector.
clang --target=arm64-apple-macos12 -O1 -fstack-protector-all -c -o /tmp/aa_arm64.o src/freestanding.c
"$LLVM/ld64.lld" -arch arm64 -platform_version macos 12.0 13.1 -L src -lSystem -rpath @executable_path/../Frameworks -o macho_arm64 /tmp/aa_arm64.o
clang --target=x86_64-apple-macos10.13 -O1 -fno-stack-protector -c -o /tmp/aa_x64.o src/freestanding.c
"$LLVM/ld64.lld" -arch x86_64 -platform_version macos 10.13 13.1 -L src -lSystem -no_pie -o macho_x86_64 /tmp/aa_x64.o
"$LLVM/llvm-lipo" -create macho_x86_64 macho_arm64 -output macho_fat
# A relocatable Mach-O object.
cp /tmp/aa_arm64.o macho_arm64.o
ls -l
