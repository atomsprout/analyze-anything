# Registry export declarations

The W3 reader reads `.reg` files directly. It never opens a registry handle, invokes an
importer or expands variables. Version 5 exports support UTF-8 and BOM-marked UTF-16;
REGEDIT4 supports ASCII only because the input does not establish the original ANSI code
page. Unmarked UTF-16, invalid text and files above 4 MiB are refused with a limitation.

Key sections, key deletions, named/default values and value deletions stay in source order.
Duplicate writes are preserved; effective registry state is not calculated. Supported
values include quoted strings, DWORD, typed hex strings (including unexpanded strings and
symbolic-link text), multi-strings, little/big-endian DWORD and little-endian QWORD. Hex
continuations are joined under a 128 KiB logical-line limit. Key paths are capped at 4 KiB
to bound amplification when the selected key is repeated in many value records. Binary and unknown typed
payloads retain only type, byte length and digest, with an explicit limitation. Malformed
entries are skipped with line-numbered issues; an invalid key section clears the previous
key context so following values cannot be misattributed. At most 4,096 entries and the first
64 issue details are retained; total issue count and truncation remain visible.

Recognizable credential field names hide the whole value, including spaces. Other strings
use the shared token/assignment/userinfo redaction. This remains pattern-based, not a
guarantee of identifying every secret. The existing installer registry classifier supplies
separate fixed-severity findings for associated autostart, service/driver, firewall,
association/protocol, shell extension, uninstall, environment, security and certificate-store
paths. They are explicitly heuristic path/name matches, not observed installations. Deletions
do not reuse write classifications.

`tools/native-compare/windows-registry-fixture.ps1` exports the existing Windows
`HKLM\SYSTEM\CurrentControlSet\Control\Nls\CodePage` subtree with `reg.exe export` and reads
all its values independently through Microsoft.Win32.Registry without expansion. It changes
no key and imports no REG. The recorded fixture contains two keys and 147 values (146
strings and one DWORD); every key, value type and value matches the parser. Only metadata
is redistributed, not Windows program code. Constructed tests cover deletion, duplicates,
escaped strings, REGEDIT4, UTF-16, integer endianness, QWORD bounds, multi-string termination,
continuations, invalid sections and size/count limits.

References: [Microsoft reg export](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-export)
and [registry value types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).
The historical REG-file KB 310516 currently redirects to a general help page; no complete
current REG text grammar is claimed from that page. The supported textual forms are checked
against the native export and explicit constructed cases. Other importer dialects, binary
hive files, permissions, registry virtualization and final import effects are outside this
reader's scope.

The fact's `applied: false` records that this reader did not apply the declarations; it
does not say whether equivalent settings are present on the host. No host registry state
is queried during analysis.

Windows targeted tests and the full workspace regression after REG/task integration passed,
alongside workspace Clippy, format checking and the CLI build without default features. The
final suite includes the 4 KiB key-path amplification regression. The no-AI CLI native export
run produced one registry declaration summary with no registry-reading limitation. See the
[task record](windows-tasks.md) for the final combined test-log location. Other operating
systems have not yet been run for these new readers.
