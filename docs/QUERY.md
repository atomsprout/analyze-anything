# Offline report queries

Queries read a finished `report.json`. They do not open its source artifacts,
start analysis, run an input, contact a model or use the network. They are
available in the CLI built with `--no-default-features`, as is the read-only
MCP server. Optional interpretation uses the same query implementation.

```
analyze-anything query --list-tools
analyze-anything query out/report.json findings --args '{"section":"identity","limit":10}'
analyze-anything query out/report.json evidence --args '{"under":"app.exe","query":"hostname"}'
analyze-anything query out/report.json files --args '{"coverage":"limited"}'
analyze-anything query out/report.json coverage
analyze-anything query out/report.json limitations --args '{"run_wide":true}'
analyze-anything mcp out/report.json
```

Use `--lang zh` for stored Chinese finding/limitation texts. JSON keys, kinds,
rule IDs and source values keep their technical spelling. Input-derived text is
untrusted data to describe, never instructions for an agent to follow.

## Queries and filters

CLI view names are aliases of the tool names. The complete argument schemas are
printed by `query --list-tools` and by MCP `tools/list`. Invalid types, enum values,
unknown arguments and missing required arguments produce errors.

| CLI view | Tool | Selected filters |
|---|---|---|
| findings | list_findings | section, severity, confidence, exact rule, query over original title/text/parameters/paths, evidence_query over source values, artifact, under |
| finding | get_finding | id, offset/limit over its evidence |
| evidence | list_evidence | finding id, artifact, under, query, location (bytes/field/whole), exact field, byte_offset inside the declared byte range |
| files | list_files | query over path, exact kind/parent, artifact, under, has_findings, coverage |
| file | get_file | exact path, exact fact key, offset/limit over fact entries |
| limitations | list_limitations | code, artifact, under, query, run_wide |
| coverage | get_coverage | artifact, under |

`artifact` is an exact logical path. `under` matches that path or descendants at a
`/` boundary; `app` does not match `application`. Word searches are literal,
case-insensitive, require every word and inspect the original values before display
clipping. File order is lexical path order. Findings and evidence use descending
severity and then the report's finding order; evidence ordinals retain source order.

File coverage filters distinguish `limited`, `without_recorded_limitations`, `unread`
and `incomplete_container`. These describe recorded information, not a percentage
of semantic understanding. Run-wide limitations are listed separately. A file can
have readable bytes and unresolved semantics at the same time.

## Pagination and previews

Lists include `matching`, `offset`, `limit`, `returned`, `has_more` and `next_offset`.
Pass the returned `next_offset` with the same report and filters until it is null.
Offsets count filtered matches. A serialized-row byte budget can end a page before
its requested item limit; always use `next_offset`, not an assumed page length.

Finding/evidence/limitation/fact pages permit up to 50 items; file pages permit 100.
`get_finding` permits 20 evidence items per page and returns their continuation in
`evidence_page`. The row budget is 192 KiB, excluding small page metadata. MCP requests
are limited to 64 KiB including the newline, and replies to 512 KiB. An oversized reply
produces an explicit error asking for a smaller page. Oversized request lines are
drained without retaining them, preserving the next request.

Finding text is previewed at 600 Unicode characters, evidence/parameter/fact values
at 400, and logical paths at 4096. Truncation flags and totals identify omitted text
or entries. `observed` retains a typed JSON value when its serialized size is at most
4096 bytes; otherwise it is null and `value` remains a preview. Finding parameters
and references are limited to 20 entries, with explicit totals/truncation. The full
saved report and `explain` remain available for details beyond these query previews.
The report is loaded into memory; this is not a streaming reader for arbitrarily
large JSON files. Query result bounds do not bound the source report's memory use.

Finding rows carry a short `id` and `full_id`. A lookup accepts a unique hexadecimal
prefix of at least eight characters. Queries do not change finding IDs or the report.

## Tool protocol

The stdio server implements initialization, ping, tool listing and tool calls for
protocol revision `2025-06-18`, and stops on EOF. It advertises only the seven
read-only queries above. It has no analysis tool. Notifications receive no reply;
invalid envelopes and malformed JSON receive JSON-RPC errors. Query failures are
tool errors. Input text appears only in JSON data, never in commands or tool names.

See [the JSON compatibility contract](JSON.md). Large-report browser navigation and
explicit agent analysis requests are the remaining 0.5 work, tracked in [TODO.md](TODO.md).
