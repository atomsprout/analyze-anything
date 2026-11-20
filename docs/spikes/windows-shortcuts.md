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
resolution semantics. REG and exported scheduled tasks remain W3 work.

Windows verification for this initial URL implementation: the core/content/Windows/engine
test suites passed, including the full fixture-mutation robustness test; targeted Clippy with
warnings denied passed; and the CLI built without default features. A no-AI CLI run on
`native.url` emitted the expected declaration finding and partial-reading limitation.

## Shell Links

The LNK reader recognizes the Shell Link header even under another extension. It checks
all structure ranges before reading them. The reader caps files at 1 MiB, ExtraData at 128
blocks and IDLists at 4,096 items. Truncation, invalid offsets, invalid UTF-16 and exhausted
structure budgets produce an unreadable limitation rather than a guessed target.

It reads ordered StringData declarations (name, relative path, working directory, arguments
and icon), LinkInfo local and UNC path strings, and environment target/icon declarations.
UTF-16 and ASCII are supported; non-ASCII legacy strings are omitted with a limitation
because the file does not establish a code page. Flags, icon index and show command are
recorded, including the declared run-as-user, prefer-environment and ignore-LinkInfo bits.
String evidence retains byte offsets and lengths; recognizable credentials are redacted.

No path is activated or resolved. Local, relative, UNC and environment declarations remain
separate; the reader does not choose which one Windows would use. Every shortcut receives
an unresolved-target limitation. Shell namespace IDList item semantics, volume/provider
metadata and unrecognized ExtraData blocks are not interpreted, and their presence yields
a partial-reading limitation. The parser is not a complete Shell namespace implementation.

The native producer now also saves `native.lnk`, referencing the existing system cmd.exe
without running it. Parsed target, description, arguments, working directory, icon/index
and window style match the producer properties. During development, a nonexistent target
produced only an IDList rather than LinkInfo path text; this establishes why an opaque IDList
cannot be represented as a known target path. No supplied shortcut is passed to COM.

The independent fixture is lnk-rs `tests/data/test.lnk`, pinned at
`f9c2ca66c161c1d5fd808cfb52335ba3cdfcadf4`, distributed under MIT with its license notice.
It contains a `C:\test\a.txt` path declaration, which is read alongside an explicit limitation
for uninterpreted IDList and ExtraData content. The pinned upstream bytes and local SHA-256
match. The source repository does not establish how that fixture was originally generated;
this is independent fixture coverage, not a claim about all real-world shortcut producers.

Unit tests cover every truncation point of a constructed Unicode link, redacted arguments,
unexpanded paths, malformed IDList items, UNC offsets outside the containing network block,
environment strings and excessive ExtraData blocks. The engine test confirms the complete
report is deterministic, both language texts are present, and the input is unchanged.
No-AI CLI runs on both native and independent fixtures produced the expected reports.

Format references: Microsoft's [ShellLinkHeader](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15),
[LinkInfo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/6813269d-0cc8-4be2-933f-e96e8e3412dc),
[StringData](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/17b69472-0f34-4bcf-b290-eccdb8de224b),
[network link structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/23bb5877-e3dd-4799-9f50-79f05f938537)
and [environment block](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/2224d03c-f417-44a0-81e3-df169938ba72).

After both shortcut readers were integrated, Windows `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and
`cargo build -p aa-cli --no-default-features` passed. The workspace test log is retained
locally at `out/windows-baseline/workspace-shortcuts.log`. This establishes Windows checks;
Linux/macOS runtime validation for these new readers remains pending.
