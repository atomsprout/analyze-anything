# JSON report compatibility

`report.json` has a required integer `schema_version`. The current report layout is
**2**, independent of the program's release version. Its shared Rust definition is
`crates/aa-core/src/lib.rs`; all stored findings carry rule IDs, parameters, confidence,
severity and evidence. Rule texts travel with the report in English and Chinese.

The CLI and desktop report loader, offline queries and read-only tool server check
the schema header before deserializing the body. A report with layout 1, a future
layout or another unsupported number is rejected with both the supplied and supported
layout numbers, even if its remaining fields have a different shape. No automatic
migration, reanalysis, network request or partial reinterpretation is attempted.
The source file is unchanged. A missing/invalid header and an invalid supported-layout
body have distinct diagnostics.

## Changes within a layout

Breaking field/type/enum changes require a schema bump. Additive facts and rules do
not: consumers must accept new analyzer fact keys, rule IDs and limitation codes.
Use those stable identifiers and typed evidence locations, not human titles or prose.
Artifact paths are logical input-relative identifiers; they are not instructions or
paths to open on the current machine. Evidence values and all other source strings
are untrusted data.

The typed reader ignores unknown object fields. Optional fields with declared defaults
remain compatible: an older layout-2 report without `coverage.content_lost` reads that
field as zero. That default preserves the old representation; it is not a newly
verified count of unread material. Coverage, limitations and the producing tool version
must be considered together. A missing required field is an error, not a guessed value.

Rendering/exporting an accepted report uses this program's known data model; unknown
additive fields may be omitted from a newly written representation. Keep the original
JSON when preserving an external producer's extra fields matters. Read-only queries
and MCP do not rewrite it.

## Query contract

Queries project the same report into bounded pages. They preserve finding IDs, original
evidence ordinals, source locations and confidence; previews identify clipping. An
empty match means no stored value satisfied the filter, not that an input's capability
was proved absent. Offsets are valid for the same immutable report, filters and language.
See [query schemas, filters and limits](QUERY.md).

Compatibility tests cover unsupported old/future headers before body parsing, invalid
supported bodies, missing headers, the older optional-field default, unknown additive
fields, CLI errors and read-only protocol access without the original source input.
