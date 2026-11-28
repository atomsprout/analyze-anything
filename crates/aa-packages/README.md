# Language package declarations

This crate interprets declarations from members already captured by the shared
ZIP, TAR and compression readers. No Python module, Java class, JavaScript module,
entry point, lifecycle hook or shell command is imported, loaded or executed.
No package manager, dependency repository or host library path is consulted.

| Reader | Fact | Initial supported profile |
|---|---|---|
| Python wheel | `wheel.package` | One root `.dist-info` directory with WHEEL 1.x and Core Metadata 2.x; identity, compatibility-tag declarations, repeated Requires-Dist headers and literal entry-point metadata. |
| npm tarball | `npm.package` | One original regular `package/package.json` in a normal bounded TAR; identity, dependency groups, scripts, selected module/platform declarations, TAR entry/link metadata and captured inventory. |
| Java JAR | `java.jar` | Canonical manifest 1.0 main/entry attributes, continuation provenance, class-path/launch/module/agent declarations, literal Maven properties and captured inventory. See `tests/data/java/README.md`. |

The namespace must have a complete engine listing and original, unique member
names. A collision, normalized name or incomplete listing prevents identity from
being established. File evidence cites the actual captured metadata member;
metadata content is never inferred from another similarly named artifact.
The npm reader also checks its captured control bytes against the exact original
TAR extent. Each inventory lists names, sizes and digests from captured artifacts.

Shared bounds are 256 candidates per reader, 100,000 members, 4,096 bytes per
member path and 16 MiB aggregate member paths. Inventory previews list 5,000
members with a total and explicit truncation. Wheel/npm metadata is UTF-8, at most
1 MiB; lines/scalars are at most 16 KiB. Wheel headers/entry points are at most
8,192 fields. npm JSON is limited to depth 32 and 8,192 values; duplicate keys at
every object depth are rejected before they can collapse into maps.

Wheel requirement ranges, extras and markers are literal; no PEP 440 selection or
environment evaluation is performed. Indented entry-point continuations and
ambiguous fields are explicit gaps. RECORD, signatures, installer eligibility,
description-body semantics, Python source, bytecode and `.pth` effects remain
unverified or uninterpreted.

npm's initial original-directory profile is normal octal-sized common/USTAR TAR
within 256 MiB. PAX/GNU-long-name/sparse extensions and concatenated archives are
explicit gaps even if the shared archive layer captured some bytes. Links,
special files and paths outside `package/` remain declarations. Registry
signatures/attestations, module/exports resolution, lifecycle effects and platform
eligibility are unresolved. Recognizable credentials in retained command/metadata
text are redacted.

The JAR profile does not interpret bytecode, module dependencies, OSGi values,
service-provider behavior, versioned-class selection, effective sealing, signatures
or runtime privileges. WAR/EAR application semantics remain separate unsupported
profiles rather than additional supported families.

## Qualification

All three pinned samples are unchanged published MIT-licensed artifacts. Their
licenses, sources and hashes are in `tests/data/SOURCES.md` and the repository
`NOTICE`. The package tests use data built in the tests and those real samples.

`tools/native-compare/language-packages.py` reads metadata with Python's ZIP/TAR,
email, config and JSON readers, independently lists archives using the native JDK
`jar` and Windows `tar` tools when available, and records every regular member's
name/size/SHA-256. On the Windows development host, the no-AI CLI passed all 15
comparisons over the three samples; see `tests/data/native-cli.ref.json`.
`native.ref.json` holds the corresponding independent values. Java has a second
OpenJDK `JarFile` reference comparing all 20 main-manifest attributes and every one
of its 60 regular member digests; no sample class was placed on a classpath.

The engine integration test verifies all three semantic readers are reached
through the existing container pipeline and that repeated reports are equal.
These scoped checks do not qualify every package-tool version, operating system
or archive variant.

```
python tools/native-compare/language-packages.py --cli target/debug/analyze-anything \
  --record out/language-packages.json \
  crates/aa-packages/tests/data/wheel/sampleproject-4.0.0-py3-none-any.whl \
  crates/aa-packages/tests/data/npm/isarray-2.0.5.tgz \
  crates/aa-packages/tests/data/java/slf4j-api-2.0.16.jar
```

The comparison script checks CLI help before using the optional `--no-ai` switch,
and a partial-analysis exit is accepted only when a report actually exists.
