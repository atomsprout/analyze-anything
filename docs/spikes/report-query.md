# Offline query qualification

The report query implementation now lives in `aa-query`, which depends at runtime
only on `aa-core`, serde and serde_json. CLI queries, the finished-report MCP server
and optional interpretation share it. The existing interpretation-facing module
paths and language representation remain re-exports of the shared implementation.

The seven tools expose findings, individual findings, files, individual-file facts,
evidence, limitations and coverage. Filters run on original source values before
preview clipping. Pages retain explicit offsets and byte budgets. Report schema
headers are checked before bodies, including old/future-layout rejection.

Local Windows checks passed:

- Nine query tests: filtered paging and stable tie order, original evidence/path
  and byte ranges, artifact versus run-wide limitations, invalid arguments,
  untrusted literal text, evidence continuation, schema compatibility, protocol
  bounds/recovery and byte-budgeted long-path pages.
- Three no-AI CLI integration tests: query access without an existing source input,
  unchanged report bytes/no added files, schema discovery without a report,
  seven read-only stdio tools and explicit unsupported-layout errors.
- The optional interpretation's 12 unit and 15 integration tests, using recorded
  model replies or loopback transports; no live model was asked for this change.
- The app's seven no-PDF integration tests, including worker byte access and export
  parity, plus targeted Clippy with warnings denied.
- Ten Linux package engine tests against the updated 125-check native snapshot.

A local full-workspace run started before the module migration finished its runtime
tests, then its aa-interpret doc step encountered the old dependency graph after the
source files were changed. That run is not counted as a pass. A subsequent full
workspace test run on the stable combined d047df8 source passed, together with
workspace Clippy, formatting and the no-AI CLI build. Hosted
[CI 45382506185](https://github.com/atomsprout/analyze-anything/actions/runs/45382506185)
passed all three core and desktop platforms and the advisory/license gate.

The subsequent navigation and explicit-analysis work is recorded in
[the 0.5 workflow qualification](report-workflows.md). These query tests alone do
not establish its platform acceptance. See [the query contract](../QUERY.md)
and [JSON compatibility](../JSON.md).
