# PowerShell static syntax inspection

W4 starts with an in-process PowerShell syntax inventory for `.ps1` and `.psm1`.
Tree-sitter 0.26.9 and the Airbus CERT PowerShell grammar 0.26.4 are pinned
under the MIT license. The runtime reads the compiled grammar through its
safe Rust interface. Windows PowerShell and PowerShell 7 are development
references. See the [grammar source](https://github.com/airbus-cert/tree-sitter-powershell/tree/v0.26.4)
and [PowerShell parser API](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parseinput).

The inventory records literal command names, invocation syntax, selected
literal URL and path arguments, and line and byte positions in decoded UTF-8.
Known names for network requests, services, scheduled tasks and security
configuration receive declaration labels. The standalone administrator
directive and simple literal `Start-Process -Verb RunAs` form get separate
evidence. Comments and literal strings do not become command nodes. Commands
inside a script block remain declarations. Variables, dynamic invocation,
argument expressions and unsupported syntax receive limits or unresolved
records. Aliases and command binding depend on the execution environment.

The reader accepts UTF-8 and BOM-marked UTF-16, with a 512 KiB input cap and
bounded parser callbacks, traversal depth, node counts, record counts and
published argument bytes. Each finding is tied to the captured source digest
and a decoded position. Standard credential redaction applies and arguments
attached to credential-like parameter names are omitted. The grammar can
recognize a subset of the native language, and a tree with syntax errors
produces a limitation rather than relying on recovered commands.

Six project-authored syntax references exercise comments, strings, here
strings, direct and dynamic calls, an if block, a pipeline and an administrator
directive. The checked-in snapshot was verified with PowerShell 7.6.9 using
`tools/native-compare/windows-powershell-ast-check.ps1`. The test invokes
`Parser.ParseInput` on fixture text. It compares names, invocation operators,
positions and the native elevation requirement. Rust tests use the snapshot
on every host.

Three repository scripts also matched the native literal command inventory when
read as input on Windows. These were the registry, task and shortcut fixture
generators under `tools/native-compare`, each licensed with the repository.
The comparison parsed their text through native `ParseFile` and the offline
CLI using `windows-powershell-ast-check.ps1 -Cli <no-AI CLI>`. The reference
check reads the generators as inputs.

## Batch literal segments

The separate `.bat` and `.cmd` reader handles double-quote boundaries and
simple `&`, `&&`, `|` and `||` segments. It records declared commands
with source positions, selected literal paths and URLs, and exact-name tool
labels. Literal `echo` text does not produce a second command. Standalone
comments and labels are ignored. Lines with percent or delayed expansion,
caret escapes or continuations, grouping or redirection receive unresolved
records. Control flow and nested command dispatch also have explicit limits.
The same text decoder, input budget and digest binding apply as for PowerShell.
See Microsoft’s [cmd reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd)
and [echo quoting examples](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/echo).

The pinned MSIX Packaging build script `makeaosponwinx86.cmd` is a real
redistributable batch sample. The test checks the literal `mkdir`, `cd` and
`ninja` lines and confirms that the nine-line caret continuation stays
unresolved. Synthetic cases exercise comments, operators, quoting, variable
expansion and resumption after unsupported lines. The reference uses source
bytes and documented cmd syntax. It does not invoke the build script.

Encoded command provenance and broader script declaration semantics remain
open under W4.
