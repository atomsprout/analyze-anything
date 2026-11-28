# Java archive fixture

`slf4j-api-2.0.16.jar` is the unchanged published SLF4J API artifact from Maven
Central, downloaded only as bytes:

https://repo.maven.apache.org/maven2/org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar

SHA-256: `a12578dde1ba00bd9b816d388a0b879928d00bab3c83c240f7013bf4196c579a`.
The Central `.sha1` declaration is retained alongside it and matches the input:
`0172931663a09a1fa515567af5fbef00897d3c04`. This comparison does not establish
signature authenticity.

SLF4J source and binaries are MIT licensed (https://www.slf4j.org/license.html).
`LICENSE-slf4j.txt` is copied unchanged from the JAR's `META-INF/LICENSE.txt`,
including the archive's copyright notice for QOS.ch Sarl. The artifact contains
60 regular members, Maven identity declarations and a multi-release module
descriptor; no input class is ever loaded, linked or run.

`native.ref.json` is a project-authored read-only OpenJDK 25.0.3+9 reference.
The accompanying trusted `JarReference.java` uses `java.util.jar.JarFile` with
signature verification disabled, reads its manifest through the JDK parser and
hashes every regular member. The input JAR is not added to a classpath, and its
classes are not loaded. The reference contains no machine path or execution time.
The JDK `jar --list --file` tool independently listed the same archive.

Reproduce the native reference without running anything in the sample:

```
java crates/aa-packages/tests/data/java/JarReference.java \
  crates/aa-packages/tests/data/java/slf4j-api-2.0.16.jar
jar --list --file crates/aa-packages/tests/data/java/slf4j-api-2.0.16.jar
```

The Rust tests bind the reference to the input hash, compare all twenty JDK
main-manifest attributes (including folded values), and check every captured
member path, size and digest. Constructed tests cover continuation offsets,
case-insensitive manifest duplicates, sections, malformed versions, name/capture
ambiguity, text/count/section/class-path/Maven budgets, and literal Maven-property
case and source-path checks.

The supported profile is canonical UTF-8 `META-INF/MANIFEST.MF` version 1.0 with
72-byte physical lines, 65,535-byte unfolded attributes, at most 8,192 attributes,
256 sections and 1 MiB of source. Maven `pom.properties` support is deliberately
literal UTF-8 key=value text (64 KiB, 256 fields per file, 256 files); Java escape,
continuation and legacy encoding profiles remain explicit gaps. Module/class
files, OSGi values, agents, per-entry sealing, digests and signatures remain data
or literal declarations. Class-path URLs are never opened or resolved. WAR/EAR
server/application semantics and effective Java-version selection remain outside
the initial JAR profile.

Format reference: https://docs.oracle.com/en/java/javase/25/docs/specs/jar/jar.html
