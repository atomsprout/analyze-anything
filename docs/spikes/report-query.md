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
source files were changed. That run is not counted as a pass. Complete workspace
checks must be repeated on the final stable source state. The separate hosted
52bb060 CI run qualified the preceding 0.4 state on all platforms.

Large-report browser navigation and explicit agent analysis requests are still
required for 0.5; neither is claimed complete by these query tests. See [the query
contract](../QUERY.md) and [JSON compatibility](../JSON.md).
