# ar fixtures and native reference

All archives are static read-only inputs. No object was linked, loaded or executed.

`upstream-libxxhash-0.8.1.a` is the unchanged `usr/lib/x86_64-linux-gnu/libxxhash.a`
member from Debian's `libxxhash-dev_0.8.1-1_amd64.deb`:

https://deb.debian.org/debian/pool/main/x/xxhash/libxxhash-dev_0.8.1-1_amd64.deb

The package SHA-256 is
`47e8309c6163f5ffa910520f6502cc264fda93dbb58ada840db4838575a86151`.
The archive SHA-256 is
`87fab2338536120cd3475971ea17eb9a842f36a9931f8766a4cd1cbca4b79b53`.
This is the BSD-2-Clause library, not the GPL command-line utility. Its unchanged
Debian copyright record is `COPYRIGHT-libxxhash-dev.txt`; see also `NOTICE`.

`native-gnu.a`, `native-bsd.a` and `native-thin.a` are project-authored Apache-2.0
fixtures made with LLVM 22.1.3 on Windows x64. `ar-native.c` was compiled, never
executed, twice with `clang --target=x86_64-linux-gnu -c`, adding `-DAR_SECOND`
for `short.o`. The first object is named
`a-long-member-name-for-gnu-and-bsd.o`. From their directory, LLVM ar was invoked
with `--format=gnu rcDs`, `--format=bsd rcDs` and `--format=gnu rcDTs` respectively.
Thin archive paths are relative declarations, and their referenced object files
are not needed or opened by the tests. Rebuilding does not promise identical
object bytes with another compiler version.

`ar-native.ref.json` records input hashes, ordered ordinary member names, sizes
and SHA-256 values independently read with LLVM `ar t` / `ar p`, and symbol-to-member
declarations printed by `nm --print-armap`. The cross-platform Rust tests compare
the supported GNU index entries and every stored member against these records.
BSD symbol-index descriptors are retained, but their entry semantics remain an
explicit limitation. The thin input is tested without passing it to native tools,
because a native reader might follow its external paths.

To compare a built analyzer using GNU or LLVM ar/nm:

```
python3 tools/native-compare/ar.py --cli target/debug/analyze-anything \
  crates/aa-linux/tests/data/native-gnu.a \
  crates/aa-linux/tests/data/native-bsd.a \
  crates/aa-linux/tests/data/upstream-libxxhash-0.8.1.a \
  --record out/native-linux/ar-reference.json
```

The supported profile is normal common/GNU/BSD archives with bounded UTF-8 names,
GNU long-name tables and BSD inline-name prefixes; GNU 32/64-bit symbol indexes;
and GNU thin references retained without opening host paths. Archive names have
a 4096-byte individual / 16 MiB aggregate budget, at most 100,000 member headers,
and shared 16 MiB / 100,000-entry symbol-index budgets. Unsupported name encodings,
other archive variants, BSD/COFF index semantics and external thin-member contents
remain explicit gaps. Successful index parsing does not establish linker behavior.
