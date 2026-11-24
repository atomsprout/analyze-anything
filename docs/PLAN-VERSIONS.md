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

Implementation and evidence are tracked in [TODO.md](TODO.md). Existing W0–W12 items
remain engineering work with their own profiles; these milestones do not silently mark
them complete. Unavailable platform checks remain open until an actual run establishes
the result. One pull request accumulates the implementation and records outstanding gates
until all four milestones are reviewable and verified.
