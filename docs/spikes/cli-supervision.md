# CLI process supervision

2026-11-20. W2 implementation progress on Windows x64.

CLI analyze now starts the same executable in an internal worker mode. Native-encoded command
arguments preserve input and rule paths. The child constructs the original registry, including
YARA and optional deep configuration, and serves the existing request protocol. The parent
displays progress, receives the report, ends the worker, and only then exports or requests AI
interpretation. The desktop's default worker entry point retains its standard registry.

Ctrl+C sets a cancellation flag in the supervisor. An optional --run-timeout limits the whole
analysis. Either asks the worker to cancel, allowing five seconds to return a finished partial
report, then force-terminates the worker if necessary. If no report arrived, the command fails
without writing a new one. A report already present in the requested output folder is not
evidence that this run succeeded. The deadline excludes export and AI interpretation.

The [ctrlc dependency](https://github.com/Detegr/rust-ctrlc) is MIT OR Apache-2.0 and provides platform signal handling outside the
analysis engine. Windows workers request no console; Unix workers have a separate process
group so the supervisor can handle terminal cancellation first. No new report fields or
network calls are added. Creating a process group does not itself terminate all descendants.

Three executable-level tests passed with both default and no-default-features builds:
the supervised JSON equals a direct engine report; quoted/Chinese paths, YARA and the severity
exit threshold survive; missing-rule startup fails without a report; and a zero run deadline
returns a valid partial report or an explicit failure. Six worker tests passed, including a
real helper process with a permanently blocked analyzer: force termination ends it within
five seconds and dropping the worker removes its scratch folder. The helper test is ignored
in the outer harness and deliberately invoked by the subprocess test.

Workspace Clippy with warnings denied, formatting and the no-AI CLI build passed. Actual
console Ctrl+C delivery on each host, a real disassembler run under supervision, per-parser
hard isolation, termination of external disassembler descendants, cleanup when the supervisor
itself is forcibly killed, and supervision of CLI inspect remain open. Full workspace
regression is tracked separately from these targeted tests. W2 is not complete.

The supervised no-AI CLI also passed eight native comparisons on the installed dotnet.exe,
its modified-byte copy and generated MSZIP/LZX cabinets. Native signature identity and all
shared cryptographic checks agreed for the installed executable; both tools detected tampering,
and extracted cabinet contents matched their original bytes. The raw development record is
under ignored out/windows-baseline/supervised-native.json.

## Parent disconnect and scratch recovery

Standalone worker entry points now impose a five-second shutdown deadline after their request
pipe closes or Close arrives. A stuck analyzer cannot indefinitely keep those workers alive.
The library serve entry points retain host-managed lifetime and never exit the embedding process.

Both supervisor and worker hold a shared lock on .owner.lock inside the worker scratch folder.
The next worker start recovers only recognized worker folders whose markers can be exclusively
locked. It checks the resolved target is a direct child of the intended root and skips reparse
points. Unmarked and unrelated folders remain untouched, including legacy folders that cannot
be proven to belong to this recovery scheme. This is recovery on the next run, not immediate
cleanup after every possible crash.

On Windows, seven worker integration tests and two scratch unit tests passed. A real blocked
worker exits after its parent pipe closes, releases ownership and can then be recovered. Shared
locks prevent recovery while either owner remains; a junction cannot redirect recovery outside
the test scratch root. The CLI/app targeted suites passed after preserving the existing missing
input error path. A broad regression caught an old spill-count assertion including the new marker;
that assertion was corrected and the affected tests passed.

CLI and app supervisors also validate scratch placement before creating the worker directory.
Storage inside a selected input directory is refused; users must choose a narrower input or an
external temporary location. Engine tests cover existing/missing nested paths and parent-directory
components without writing into the input. Per-parser process isolation, disassembler descendant
termination and actual parent-kill scenarios beyond the tested pipe-disconnect behavior remain
open. No claim of complete W2 coverage is made by these checks.
