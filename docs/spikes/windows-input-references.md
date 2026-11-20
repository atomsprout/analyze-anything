# Supplied-file references from Windows entry points

The W3 tree pass uses only the finished artifact list and parsed declaration facts. It
never reads a target, consults the host environment or registry, resolves a COM class,
opens a shortcut through the shell, or fetches a URL. Tests use a Tree whose read method
panics, proving that the relationship pass does not read even supplied target bytes.
The normal engine already measured those artifacts; their existing digests identify them.

## What a positive link means

Microsoft's Shell Link StringData definition makes RelativePath relative to the shortcut
file. A unique, supported relative path can therefore identify another supplied artifact
inside that same logical namespace. Paths inside an archive stay within their immediate
container; neither another archive nor the outer filesystem supplies missing targets.
An input folder supplies its own namespace without its machine location.

The `windows.input-reference` finding is Derived/Info and cites the source field plus the
target artifact and digest. It says the declaration links to supplied bytes. It does not
choose among the shortcut's alternative target declarations or establish a Windows launch
target. Existing target-unresolved limitations and facts remain in place.

The initial matching profile covers ASCII names with ASCII case folding, 255-byte ordinary
components and paths up to 8 KiB. Dot components are normalized; parent components cannot
escape the container. Intermediate directories must be represented by supplied path
prefixes and cannot also be files. Case aliases, duplicate targets, unreadable targets,
drive/root/device/stream paths, reserved DOS names, trailing spaces/dots, short-name aliases,
variables and redacted values do not yield links. Any namespace containing non-ASCII names
is outside the positive profile, including for ASCII references: otherwise a non-ASCII
Windows case alias of an ASCII name could be overlooked. Portable Unicode alias handling
and a broader native path matrix remain open; no claim of complete Windows path resolution
is made.

The engine now attaches `engine.entry-name` metadata to archive artifacts whose names were
normalized or collided. Both an original colliding entry and its numbered copies are marked.
This prevents the generated display name of a duplicate from becoming a false unique
target. The byte streams are still preserved, and ambiguity does not count as lost content.

`engine.input-listing` records whether the input-file namespace was fully enumerated and
ingested. Each recognized container has `engine.container-listing` metadata: its listing is
not established complete after an unpacker failure/warning, a rejected/oversized/unreadable
entry, an exhausted limit or interrupted child ingestion. Positive links require affirmative
completeness for their own namespace; absent metadata is not treated as complete. This also
prevents an incomplete unpack from hiding a later same-named target. An unrelated broken
container does not invalidate a fully listed outer folder's relationships. This describes
the observed artifact tree, not an atomic filesystem snapshot or a claim against file races.

## What remains unresolved

`windows.input-references` records the source field, literal declaration (within the text
budget), reference basis, status, reason and any associated artifact/digest. Its runtime
resolution flag is always false. The collected references are LNK RelativePath, local/UNC
target and target/icon environment strings; Internet Shortcut URL/icon declarations;
registry autostart/service command or ServiceDll values and default Classes open commands;
and Task Scheduler Exec Command fields. Other literal fields stay in their reader facts.

URL resolution, command-line interpretation, host-relative bases and absolute host paths
are not guessed. A task's XML location is not its executable search directory. A REG file's
location does not anchor Run values or protocol commands. Even a same-named artifact beside
those documents does not establish a relationship. Source declarations and per-file reason
counts remain visible, with a bilingual unresolved-reference limitation.

Indexing is all-or-nothing under 100,000 artifacts, 32 MiB of full logical path bytes and
an 8 KiB per-path budget. At most 10,000 declaration sources and 512 references per source
are processed. Larger declaration text is not copied into the reference fact; its byte
length and the text-limit reason remain. Every exhausted budget is an explicit limitation;
a partial index is never used to assert uniqueness.
Text byte lengths in this fact count the decoded UTF-8 representation, not the original
UTF-16 field width; the original reader facts retain byte offsets/lengths where available.

## Verification

Unit tests cover a unique relative sibling, ASCII case folding, namespace escape, another
container, file/directory conflicts, missing intermediate directories, Unicode alias
uncertainty, ambiguous case aliases, normalized/colliding entry metadata, absolute/UNC/ADS
paths, variables, short names, redaction and count/byte/source/reference budgets. They also
show why a supplied sibling does not resolve task, REG or URL references.

Engine tests exercise real ZIP/TAR unpacking, both original and numbered duplicate entries,
normalized names, target digests, bilingual rules, unchanged input and deterministic reports.
They also cover partial outer/container listings and an unrelated broken container that
does not invalidate a complete outer namespace.
The independent MIT-licensed lnk-rs fixture links its RelativePath to a supplied a.txt while
its absolute host path remains unresolved.

`tools/native-compare/windows-reference-check.py` runs the first-party CLI only, never the
sample's targets. Seven checks cover supplied target/digest, no added artifacts, unresolved
runtime semantics, repeated JSON identity, renamed-input diff stability, English/Chinese
Markdown and inclusion in HTML. Native Windows shell resolution is deliberately not used
as an oracle for this portable declaration relationship.

References: [Microsoft Shell Link StringData](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/17b69472-0f34-4bcf-b290-eccdb8de224b)
and [Task Scheduler ExecAction.Path](https://learn.microsoft.com/en-us/windows/win32/taskschd/execaction-path).

Windows verification passed: `cargo fmt --all --check`, workspace Clippy with warnings
denied, `cargo test --workspace` (including fixture mutations), and the CLI build without
default features. Seven end-to-end CLI checks passed again with completeness guards in
place. The final local test log is `out/windows-baseline/workspace-input-references-final.log`.
Cross-platform CI passed for implementation commit `413e05e7e4f87c931b8a50b9c2dca32d11bfc662`:
[run 44806581603](https://github.com/atomsprout/analyze-anything/actions/runs/44806581603).
Core format, Clippy, tests and no-default-feature CLI builds passed on Linux, macOS and
Windows; the separate macOS desktop job passed its frontend, browser and Tauri checks,
and the license job passed. This is automated portable-reader evidence, not additional
native Shell/registry/task comparisons or a Windows desktop release qualification.
