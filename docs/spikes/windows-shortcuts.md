# Windows shortcut reading

## Internet shortcuts

The first W3 reader handles `.url` files. The input is parsed directly as text; it is
never passed to a shell API. UTF-8 (optional BOM) and BOM-marked little/big-endian UTF-16
are supported. Invalid encodings, missing targets, text beyond 1 MiB and more than 256
supported declarations produce an unreadable limitation. No host ANSI code page is assumed.

Within `[InternetShortcut]`, URL, IconFile, IconIndex, WorkingDirectory, HotKey and
ShowCommand are kept in source order. Repeated keys are preserved rather than assigning
Windows resolution semantics. Unknown fields and malformed lines are counted; unknown
fields or repeated supported keys produce a partial-reading limitation. No variable,
target, network location or icon reference is resolved or opened.

Facts and evidence redact recognizable credential assignments, URL userinfo, authorization
values, provider token forms and private-key material markers. Generic HTTP URL facts use
the same redaction before deduplication, preventing them from publishing a shortcut's raw
credentials. This is pattern-based, not a guarantee that every possible secret is detected.
Counts refer to distinct redacted URL representations.

`tools/native-compare/windows-shortcut-fixture.ps1` generates `native.url` using Windows
WScript.Shell and saves the producer's TargetPath as the reference. The analyzer's URL
declaration matches that reference. The generated IDList and Prop3 properties are outside
the supported subset and correctly produce a limitation. The producer only creates this
project's fixed example.invalid URL; it does not load or activate supplied shortcuts.
This is a constructed native fixture, not independent real-world coverage.

Tests cover small files below the PE-header threshold, duplicate targets, an unexpanded
environment reference, a UNC icon reference retained only as text, UTF-16, malformed
encodings, field/size bounds and known credential redaction. An engine regression checks
the complete serialized report (including generic content facts), unchanged input bytes
and byte-identical repeated reports.

Reference: [Microsoft Internet Shortcuts](https://learn.microsoft.com/en-us/windows/win32/lwef/internet-shortcuts).
The property documentation supports the declarations; it does not establish complete INI
resolution semantics. LNK, REG and exported scheduled tasks remain W3 work.

Windows verification for this initial URL implementation: the core/content/Windows/engine
test suites passed, including the full fixture-mutation robustness test; targeted Clippy with
warnings denied passed; and the CLI built without default features. A no-AI CLI run on
`native.url` emitted the expected declaration finding and partial-reading limitation.
