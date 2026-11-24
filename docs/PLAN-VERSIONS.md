# Delivery plan: 0.2 through 0.5

This plan implements the product direction agreed for the next four milestones in one
pull request. The milestone numbers describe acceptance groups; merging the pull request
does not publish four releases. Work proceeds in order, preserving the five guarantees
in [AGENTS.md](../AGENTS.md). Each milestone improves the explanation of a supplied file
or folder, from identifying its contents to retrieving the evidence behind an answer.

## 0.2: Reliable use

- Qualify packaged CLI archives, including Windows without a separately installed VC
  runtime and Linux x64/ARM64 in explicitly named clean userspaces.
- Run hosted Windows desktop checks and release packaging; record actual runs and failures.
- Keep whole-run cancellation, deadlines, resource limits and partial-report behavior
  explicit. Do not describe cooperative parser deadlines as hard process isolation.
- Synchronize installation and platform documentation with recorded evidence.

Acceptance requires repository format, lint, workspace tests, the no-AI CLI build,
desktop tests, hosted platform checks and packaged-artifact qualification. Parser accuracy
is checked against reference tools reading the same representative real samples, with
recorded hashes and reference results. These development checks do not import Windows
trust policy into offline findings.

## 0.3: Understand the supplied software

- Expose relationships between supplied entry points, payloads, components and integrity
  declarations with the source evidence and resolution status retained.
- Distinguish a declaration, a matched supplied file and a verified content relationship.
- Lead reports with useful answers about identity, contents, declared capabilities and
  unread material. Keep detailed evidence available in every output.
- Make coverage attributable to specific artifacts and unsupported structures, without
  presenting file counts as a percentage of semantic understanding.

Acceptance requires end-to-end reports on representative multi-file inputs, unresolved
and ambiguous relationships, bilingual output, deterministic bytes and escaped input text.

## 0.4: Read more of the supplied contents

- Add bounded .NET single-file and PyInstaller container readers, reusing the artifact
  tree and existing analyzers for extracted members.
- Add Linux package coverage in separately documented format profiles, starting with deb
  and rpm. Preserve package metadata and declared installation actions as data.
- Report unsupported versions, compression, encrypted content, malformed offsets and
  exhausted budgets explicitly. Never run a payload, installer or package script.

Each format must meet [the analyzer completion gates](ANALYZERS.md): constructed tests,
a redistributable real sample with source and license, a reference comparison where
available, tested limitations and a documented supported profile. Office, firmware and
disk images remain separate projects.

## 0.5: Find and reuse answers

- Provide deterministic structured queries over finished reports with finding evidence,
  artifact and coverage filters. Queries do not require a model or network.
- Make report navigation and evidence lookup work for large reports.
- Document JSON compatibility, unsupported schema handling and old-report behavior.
- Extend agent workflows to explicitly request an analysis while keeping finished-report
  queries read-only and treating all input-derived text as untrusted data.

Acceptance requires CLI and tool-protocol tests, bounded query results with explicit
pagination, schema compatibility tests and browser checks of report navigation.

## Tracking

All four scoped milestones are implemented and verified in
[PR #6](https://github.com/atomsprout/analyze-anything/pull/6):

| Milestone | Acceptance evidence |
|---|---|
| 0.2 | [Delivery qualification](spikes/delivery-qualification.md): three-platform CI, native desktop windows on Windows/Linux, four packaged CLI targets, Windows portable/NSIS packages and named Linux clean userspaces |
| 0.3 | [Report understanding](spikes/report-understanding.md): bilingual questions, supplied-file relationships, attributable coverage, deterministic rendering and inspected PDFs |
| 0.4 | [Executable bundles](spikes/executable-bundles.md) and [Linux packages](spikes/linux-packages.md): bounded supported profiles, licensed samples, native references and tested limitations |
| 0.5 | [Offline queries](spikes/report-query.md) and [report/agent workflows](spikes/report-workflows.md): query/schema/protocol tests, 12,000-finding navigation and supervised rooted analysis |

CI 45386227144 passed all seven jobs at the final code revision 9dab32b. Release
rehearsal 45382485314 passed at d047df8, which includes all four milestones; the later
code correction changes only cancellation during deadline shutdown and has local
release and hosted regression evidence. Exact artifact hashes and revision boundaries
are retained in the linked records. Subsequent acceptance-record edits are documentation
only. No release or tag was created.

Remaining work is tracked in [TODO.md](TODO.md). Existing W0–W12 and D6 items retain
their broader completion gates; these milestones do not silently mark them complete.
Physical Linux display acceptance, broader signature/format profiles and signed delivery
remain separate work.
