# Task Scheduler XML declarations

The W3 reader recognizes a Task root and the Task Scheduler namespace in the first 16 KiB,
including prefixed namespaces and BOM-marked UTF-16. It does not treat a namespace string
embedded in a program or HTML example as a task document. The full input is decoded strictly
as UTF-8 or BOM-marked UTF-16 under a 2 MiB limit. Unmarked UTF-16, unsupported declared
encodings, DTDs, malformed XML and exhausted reader budgets are explicit limitations.

The in-process XML parser disallows DTDs and caps nodes at 20,000. Captured declarations
are capped at 4,096, depth 32, 128-byte element names, 2,048-byte namespaces, 8,192-byte paths,
32 attributes per element and 64 KiB text/attribute values. Unknown elements, foreign
namespaces, application-specific Data and unknown attribute values are omitted with a
limitation, retaining their location and uninterpreted status. The first 64 issue details
and total issue count remain visible. No external entity, event query or referenced file
is evaluated or opened.

The reader records common fields for all eight documented trigger families, including
calendar, repetition and event-query text; Exec, ComHandler, SendEmail and ShowMessage
action declarations; principal account/logon/run-level/privilege fields; registration
metadata and supported settings. Child order, duplicate singleton declarations and explicit
XML ids remain visible. Duplicate ids produce a limitation; effective values are never
chosen. Environment references stay literal. Account names, COM classes, paths, triggers,
schema defaults and full XSD scalar constraints are not resolved or evaluated. Every task
has an explicit semantics-unchecked limitation. A HighestAvailable run level or boot/logon
trigger produces a separate fixed-severity declaration finding, including when a trigger
or task is explicitly disabled; the text does not call it an installed active task.

Known credential forms are redacted before facts/evidence. Unknown payloads are not copied.
Mail header values use their declared header names for redaction, so Authorization values
are hidden in full. This remains pattern-based rather than complete secret identification.

`tools/native-compare/windows-task-fixture.ps1` creates a new ITaskDefinition in memory,
serializes it and records producer properties. It never registers or runs the definition
and never gives supplied XML to a task service. Action command/arguments/working directory,
trigger dates/enabled values, action context, run level and the supplied principal SID match
the reader. The native Principal.UserId getter normalizes that SID to SYSTEM, while XML
keeps the SID. The serializer omits LogonType even though the object has a ServiceAccount
property. The reader records only the XML declaration and does not invent the omitted field.

An independent deployment definition is `task.xml` from ms-azure-demos/
aks-windows-container-task-scheduler-powershell, pinned at
`b6a430f5f6a5dd74b376f00e1b6e15127874c517`, under MIT with its full license notice.
Its PowerShell command, repetition interval and principal text are read without running
anything. The upstream bytes are UTF-8 despite an XML declaration saying UTF-16; that
mismatch is explicitly recorded and importer compatibility is not claimed. Its source
does not prove all possible native task export variants.

Constructed tests cover all trigger/action families, calendar fields, UTF-16 in both byte
orders, opaque COM Data, mail-header credentials, namespaces, duplicates, malformed XML,
DTDs, oversized fields and declaration/XML-node budgets. The engine regression checks all
report rules have English/Chinese text, secrets do not leak through generic content facts,
the input remains unchanged, referenced files are not added and repeated reports match byte
for byte. Supplied-artifact target relationships remain separate W3 work.

Reference: [Microsoft Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema).
This supports field structure and names; it is not a claim that this reader validates the
entire XSD or predicts task execution.

The fact's `registered: false` records that this reader did not register a task; it does
not say whether a task with these declarations exists on the host. Host registration state
is not queried during analysis.

Windows verification after the REG/task integration and reader/report bounds: format check,
workspace Clippy with warnings denied, the full workspace test suite (including fixture
mutation robustness), and the CLI build without default features all passed. The final test
log is retained locally at `out/windows-baseline/workspace-entry-points-final.log`. No-AI CLI
runs produced the expected registry, native task and independent task reports, and Chinese
output was checked. English single-count task wording was checked in the rendered Markdown.
The pinned upstream XML uses `-text` in `.gitattributes`; Git's Windows checkout filter
preserves its recorded SHA-256. Linux/macOS runtime checks for these readers remain pending.
