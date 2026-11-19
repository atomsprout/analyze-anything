# Writing an analyzer or unpacker

How a format is taught to Analyze Anything. Read `crates/aa-core/src/lib.rs` and
`crates/aa-core/src/plugin.rs` first; they are short and are the contract. `crates/aa-content`
is a complete small analyzer, `crates/aa-unpack` a complete set of unpackers.

## The pipeline

1. **Tree.** The engine lists the input and measures every file (size, digests, entropy, MIME).
   Each file is offered to the unpackers in order; the first that recognises it adds its entries
   as children. A container's children live under its path: `app.ipa/Payload/X.app/Info.plist`.
   Folders are not artifacts, only path prefixes, so a bundle on disk and one inside an archive
   look the same.
2. **File pass.** `Analyzer::analyze_file` runs for every artifact, in parallel.
3. **Tree pass.** `Analyzer::analyze_tree` runs once per analyzer, in registration order
   (content, binary, apple, windows, android). It sees the facts and kinds every analyzer
   attached in the file pass, and those of the analyzers before it in the tree pass.

A kind set in the file pass sticks to the first analyzer that sets it; the tree pass may replace
it. `Tree::summary()` gives the facts about the input as a whole that earlier analyzers attached.
A panic in an analyzer or an unpacker is caught and recorded as a limitation; it never ends the run.

Within a chapter the report lists findings most severe first, then in the order their rules are
declared in `rules()`. Declare rules in the order a reader should meet them.

## What an analyzer emits

- **Findings** — statements the report prints. One `Finding` per statement, built with
  `Finding::new(section, analyzer, rule, confidence, severity)`, `.param(..)`, `.evidence(..)`,
  `.reference(..)`, and added with `out.finding(..)`. Neutral facts ("the bundle id is X") are
  findings too, with `Severity::Info`.
- **Facts** — structured data too bulky for a sentence (import lists, permission tables, parsed
  headers): `out.fact(artifact, "<analyzer>.<name>", json)`, or `out.summary(key, json)` for the
  input as a whole. Cap long lists and add `"truncated": true` when cut.
- **Kinds** — `out.kind(artifact, "macho")` says what an artifact is.
- **Limitations** — `out.limitation(code, artifact, detail)` for whatever could not be established.

Every rule id and limitation code needs a `Rule` in `Analyzer::rules()` with a title and a
sentence in Chinese and English. The sentence may use `{param}` placeholders. Rule ids are
`<analyzer>.<kebab-case>`.

## Reliability rules (these are the product)

1. **Evidence on every finding.** Say which artifact and where: `Evidence::bytes(file, offset,
   length, value)`, `Evidence::field(file, "CFBundleIdentifier", value)`, or `Evidence::whole`.
2. **Confidence is honest.** `Verified`: read from a structure the format defines, or checked
   cryptographically. `Derived`: follows from verified facts by a fixed rule. `Heuristic`: a
   pattern match that can be wrong — say so in the rule text.
3. **Unknown is not zero.** A value that could not be read is absent or `null`, never `0`, `""`
   or `false`. "Not found" and "not checked" are different; record the second as a limitation.
4. **Never trust the input.** Every length, offset and count from a file is checked before use.
   No `unwrap`/`expect`/indexing that can panic on malformed bytes, no unbounded allocation or
   recursion driven by the input. A truncated or hostile file yields a limitation, not a crash.
5. **Never execute or load the input**, never write outside the sink, never touch the network,
   never print.
6. **Deterministic.** Same bytes in, same output out: sort what you collect, no timestamps of
   "now", no hash-map iteration order in the output.
7. **Verify against a reference tool** where one exists (readelf, objdump, apksigner, aapt,
   osslsigncode, 7z, codesign output published with a sample) and encode the comparison as a test.
8. **Secrets are redacted** in findings and facts.

## Tests

- Unit tests next to the code; small fixtures (under ~200 KB each) in `crates/<crate>/tests/data/`,
  built by a script or by the test itself so their origin is clear. Larger real samples are for
  manual checks and stay outside the repository.
- For each parser: a well-formed case with expected values, and malformed cases (truncated at
  several lengths, wrong offsets, huge counts) that must not panic.

## Licences

Dependencies must be MIT, Apache-2.0, BSD, ISC, Zlib, Unicode or MPL-2.0. No GPL/LGPL/AGPL.
Reference projects (Craft Anything, RESX, …) may be read for ideas; do not copy their code.
