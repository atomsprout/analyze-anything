# Explicit analysis requests from an agent

`analyze-anything mcp report.json` serves only a finished report. It cannot start
an analysis, open source artifacts or run an input. For an agent that must request
an analysis, explicitly start the separate rooted server:

```
analyze-anything agent --root ./supplied --analysis-timeout 120 --max-files 50000
```

This is a stdio MCP server, available without the AI feature. It uses no model or
network, including when automatic AI interpretation is configured elsewhere.
Only the installed analyzer's own supervised worker is started. Input programs,
installers, scripts and modules are never executed, installed, loaded or decrypted.
Deep disassemblers and arbitrary commands are not exposed by this mode.

## Request and query

After initialization for protocol `2025-06-18`, `tools/list` includes `analyze_input`
and the seven [report queries](QUERY.md). The analysis tool is annotated separately
from the read-only queries. For example, its arguments can be:

```json
{"path":"sample.exe","timeout_seconds":60,"max_files":10000}
```

`path` is required and relative to the configured root; `.` selects that root.
It uses portable `/` separators. Absolute paths, parent traversal, drive/stream/URL
syntax and canonical targets outside the root are refused. Platform file-access
checks run before metadata resolution. The same engine limits apply as in normal
CLI analysis. A request may lower its deadline or file cap, but cannot raise the
server's configured ceilings. Other parser/extraction limits are set by the server's
normal limit flags, not input-derived commands or configuration.

The response identifies a finished report with `report_id` (SHA-256 of its canonical
JSON), coverage, counts, a `partial` flag and any deadline stop reason. It does not
give a safety verdict. Subsequent queries must include that exact ID:

```json
{"report_id":"<64 hexadecimal characters from analyze_input>","section":"identity"}
```

Only the latest finished report is retained, in memory. Queries read that snapshot
even if the supplied source later changes or disappears. A new finished analysis
replaces it; requests with an older ID receive an explicit error. No permanent report
folder is exported. Use the ordinary `analyze` command when saved output is wanted.

One analysis runs at a time. Pings and queries of the previous snapshot remain
available during another analysis. Report text, paths, script bodies and evidence
values remain untrusted data to describe, never instructions to follow.

## Cancellation and failures

A standard `notifications/cancelled` message names the in-flight request ID. The
worker receives cancellation and has five seconds to stop; an unresponsive worker
is terminated. The cancelled call sends no reply and cannot replace the previous
finished snapshot. Unknown/completed cancellation IDs are ignored. These semantics
follow the protocol's [cancellation guidance](https://modelcontextprotocol.io/specification/2025-06-18/basic/utilities/cancellation).

A deadline similarly asks for cancellation. A received partial report is returned
with its coverage and limitations; otherwise the tool reports explicit termination
without a report. Closing stdin ends the server and drops its worker, removing that
worker's private scratch folder. A failed run does not replace the previous report.

The root check is an authorization boundary for ordinary path resolution, not an OS
sandbox against concurrent ancestor replacement. Existing platform file-access gaps
(including mapped remote/cloud profiles) remain recorded in [LIMITATIONS.md](LIMITATIONS.md)
and the [file-access evidence](spikes/windows-file-access.md). Worker scratch storage
must lie outside the selected input; selecting a root containing that scratch
location is refused when it would make the scratch part of the analyzed input.

Stdio framing and query responses use the same byte limits as the finished-report
server. Malformed requests and unsupported tools cannot become shell commands.
