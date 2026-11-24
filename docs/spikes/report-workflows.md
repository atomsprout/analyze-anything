# Report navigation and explicit agent workflows

The selected-finding HTML view resolves IDs directly and renders one finding with
its bounded evidence pages. It does not render preceding chapter groups/variants.
Stable `#finding-<64 hex ID>` links support reload and browser history; ID search
accepts unique prefixes. Desktop citation messages use the same unambiguous lookup.
Filters remain intact, Return restores focus, and language changes keep the selection.
The view is omitted from printing. Evidence/file associations use sets, so source
paths cannot collide with JavaScript object prototype names.

A reproducible Node fixture builds 12,000 declared findings and renders them with
the production Rust renderer. The browser tests open its last finding with only
ten initial variant rows in the original chapter, inspect its evidence, follow
previous/back/reload, retain filters/focus, switch English/Chinese, and reject unknown
or malformed fragments. A script-shaped value stays text. Chromium and WebKit both
passed these six checks. Screenshots of the selected view were inspected at each
browser's resolution; navigation, source text and evidence fit without clipping.
The complete page suite passed 38 browser checks and 14 unit tests. Report rendering's
24 tests passed, including hostile text and the 50,000-file/5,000-finding report.

`agent --root` is a separate stdio mode. It adds explicit `analyze_input` requests to
the seven bounded queries; the original `mcp report.json` remains read-only and has
no analysis capability. It uses the existing trusted process worker, never an input
program or disassembler. Paths must resolve within the configured root. Queries
require an immutable report hash; newer successful analyses replace the one retained
snapshot. Cancellation discards the request without replying or replacing that snapshot.
Deadlines accept a received partial report or report termination explicitly. EOF drops
the worker and removes its private scratch folder.

Local Windows validation passed five real-process agent tests and three no-AI
finished-report CLI tests: engine/hash agreement, source independence, snapshot
replacement, rejected path/tool/limit syntax, partial file-budget coverage, cancellation
responsiveness and EOF cleanup. A separate trusted test child that ignores requests
verified cancellation and forced termination at a controlled grace deadline, including
scratch cleanup. Its intentionally ignored helper test is only a subprocess fixture,
not an unverified production case. The Unix external-symlink test passed in hosted CI.

A final cancellation review found that a client cancellation arriving during deadline
shutdown could still receive the deadline reply. The state now changes to cancellation
while retaining the original shutdown deadline, so repeated cancellations cannot extend
the grace period. A second controlled worker test verifies reply suppression and cleanup
in that state. Both worker unit tests, all eight no-AI CLI query/agent integration tests
and no-AI CLI Clippy passed locally after the correction.

Nine query tests, the optional interpretation regression and targeted Clippy also
passed after sharing stdio parsing/response bounds. No live model was invoked.
The root preflight reuses the platform file policy before canonicalization; it is
not an OS sandbox against concurrent filesystem changes. Existing W1 gaps remain.
See [the explicit server contract](../AGENT-SERVER.md).

Hosted [CI 45382506185](https://github.com/atomsprout/analyze-anything/actions/runs/45382506185)
at the combined d047df8 source passed all three core and desktop platforms and the
advisory/license gate. Local full-workspace tests, Clippy, formatting, the no-AI CLI
build and production page build also passed. Packaged-artifact qualification is
recorded separately in [delivery qualification](delivery-qualification.md).

After the cancellation correction, [CI 45386227144](https://github.com/atomsprout/analyze-anything/actions/runs/45386227144)
at 9dab32b passed all seven jobs again, including the Unix path guards, both controlled
shutdown tests and all three desktop/browser platforms. The intermediate documentation
revision 4f78fe4 also passed CI 45385912274. No live AI service was used.

The local Windows `cargo test --release` run also passed on 9dab32b, including
the damaged-fixture corpus, worker lifecycle tests and doctests. A separate no-AI
release run passed all five agent and three query process tests. These local runs
do not substitute for the packaged-runtime checks recorded in delivery qualification.
