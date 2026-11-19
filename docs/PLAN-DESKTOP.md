# Analyze Anything — Phase Two Plan: Desktop App

> Version: v1.0 final (2026-11-19). Prerequisite: the phase one command-line tool is complete, see [PLAN.md](PLAN.md).
> Positioning in one sentence: **a graphical interface on the same analysis engine. Drop a file in → watch progress → browse the report → export.** No new analysis capability.

---

## 0. Summary

| Item | Decision |
|---|---|
| Framework | Tauri 2 (current stable is 2.12, requires Rust 1.90; we pin 1.100) |
| Platform order | macOS first; Windows and Linux after the macOS version is usable |
| Report UI | Reuse the `report.html` from phase one, no rewrite |
| Where analysis runs | A separate child process, not in the UI process (see §3.2) |
| Frontend | TypeScript + Vite, no UI framework (see §3.4) |

**The macOS version is estimated at about 8–10 weeks**, in 6 milestones (§6). This is a rough estimate, to be revised after the D0 technical validation is done.

**The decisions** are recorded in §9; completion status is in §10.

---

## 1. Product definition

### 1.1 What it does

1. **Open**: drag a file or folder into the window, or choose one with the "Open" dialog.
2. **Analyze**: show the stage and progress (which file is being read, how many containers have been unpacked); can be cancelled.
3. **Read the report**: overview, needs attention, 12 sections, file inventory, coverage and limitations; can filter, search, and switch between Chinese and English.
4. **View evidence**: click a finding to jump to the file and position it references; show a hex view for byte ranges.
5. **Browse the file tree**: the full artifact tree after unpacking, with each file's type, size, hashes, and the data read by the analyzers.
6. **Export**: PDF, HTML, Markdown, TXT, JSON, SARIF, CycloneDX, and an output folder with a manifest.
7. **History**: a list of previously analyzed reports, which can be reopened.
8. **Compare**: pick two reports and see the findings that were added, disappeared, or changed (typical use: two versions of the same app).

### 1.2 What it does not do

- No new analysis capability. The desktop app can show only what the command line can show, and the reverse also holds.
- No executing or installing the analyzed object, same as the command line.
- No network access. No accounts, no cloud sync, no telemetry.
- Not in phase two: auto-update, a plugin system, AI interpretation (these belong to phase three).

### 1.3 Relationship to the command line

The desktop app and `analyze-anything` share `aa-engine`, `aa-report`, `aa-export`. The same input produces a byte-identical `report.json` on both sides; this must be guaranteed by an automated test.

---

## 2. Current state: what the engine still lacks for the desktop app

§3.4 of the phase one plan lists seven constraints as "provisions for the desktop app". Checked one by one against the actual code:

| Constraint | Current state |
|---|---|
| All analysis logic is in libraries, the CLI is a thin shell | Met |
| One entry point `analyze(input, options, sink)` | Met |
| Progress is structured events | **Partly met**: the tree-building stage has per-file events; the analysis stage has only one "analysis started" event and no per-file progress; the event types cannot be serialized yet |
| Cancellable | Met |
| `report.json` is self-contained | Met; `analyze-anything render` proves it |
| Get bytes by node | **Not met**: the artifact tree is discarded when analysis ends, the unpacked files disappear with it, and there is no external read interface |
| Configuration is data | Met |

So before work on the desktop app starts, the engine needs two additions first (placed in D1):

1. **Analysis session**: add an entry point that returns "the report + an artifact tree that is still readable". While the session is alive, any byte range of any file can be read by path; temp files are cleaned up when the session ends.
2. **Progress events**: report progress per file in the analysis stage; the event types support serialization, so they can be passed across processes.

---

## 3. Architecture

### 3.1 Directories

```
analyze-anything/
├── crates/                  # The 12 crates from phase one, structure unchanged
│   └── aa-engine            # Added: analysis session, serializable progress events
├── apps/
│   └── desktop/
│       ├── src-tauri/       # Rust: window, commands, child process management, history
│       └── src/             # Frontend: TypeScript
└── docs/
```

`apps/desktop/src-tauri` is a new member of the workspace. It does not enter the dependencies of the `analyze-anything` command line, so the size and build time of the command line are not affected.

### 3.2 Analysis runs in a child process

The UI process does not call the engine directly. It starts a worker child process to do the analysis, and the two exchange JSON messages over standard input and output.

Reasons for doing it this way:

- **A hang can really be terminated**. The phase one timeout can only "give up waiting"; a stuck thread cannot be killed. With a process, it can simply be ended.
- **A crash does not take the UI down**. The engine already isolates panics, but problems such as stack overflow and memory exhaustion cannot be isolated.
- **Memory is returned as soon as it is no longer used**. The memory taken by analyzing a large file is all returned when the child process exits.
- **Cancellation is deterministic**. Send a cancel message first; if it does not exit within a few seconds, force it to end.

The worker child process is the desktop program itself, started once more with a hidden argument. There is no need to distribute an extra executable.

The cost is one more layer of message protocol, and "reading evidence bytes" has to go through inter-process communication. The volume of byte-read requests is small (one read per user click), which is acceptable.

### 3.3 Message protocol

UI process → worker process: `analyze`, `cancel`, `read_bytes`, `close`.
Worker process → UI process: `progress` (per file), `report` (done), `bytes`, `error`.

Each message is one line of JSON. The protocol is written as Rust types in a small crate shared by both sides; it has round-trip tests.

### 3.4 Frontend

- **Language and build**: TypeScript + Vite.
- **No UI framework** (none of React, Vue, Svelte). Reason: the shell UI has only four views (home, progress, report, compare), and the existing report UI is a 51 KB vanilla script; adding a framework would leave two styles of code side by side.
- **Report view**: put the `report.html` rendered by `aa-report` into a restricted embedded frame, loaded through a custom protocol (e.g. `report://<id>/`), without writing temp files.
- **Changes to the report UI**: the existing `app.js` gains a "host mode": in the desktop app, clicking a piece of evidence sends "file path + byte range" to the shell as a message, and the shell opens the hex view. The behavior of a `report.html` opened on its own does not change.
- **Hex view**: newly written. It requests bytes from the worker process on demand, with virtual scrolling, and does not read the whole file at once.

### 3.5 History

- Stored under the system's application data directory, one folder per analysis: `report.json`, `manifest.json`, and a little metadata (input name, time, SHA-256 of the input).
- **The analyzed original file is not saved**, and neither is the unpacked content. When a past report is reopened, the report can be read but the hex evidence cannot be viewed; the UI must explain why and offer "Re-analyze".
- The analysis time is recorded only in the history index and does not go into `report.json`, so the report stays reproducible.
- Provide "Delete this entry" and "Clear history".

### 3.6 Compare

- A finding's ID is a hash of its content, so the same observation has the same ID in two reports. The comparison first finds the findings that are exactly identical by ID, then pairs the rest by "rule + file path"; those that pair up count as "changed", those that do not count as "added" or "disappeared".
- The comparison logic lives in a library (`aa-export` or a new crate), and the command line gets `analyze-anything diff a.json b.json` at the same time.
- The same applies at the file level: by path and hash, list the files that were added, removed, or changed in content.

---

## 4. Security

The desktop app adds an attack surface: the text in a report comes from untrusted files, and it is now displayed inside an application that has privileges.

- **Content security policy**: keep the strict policy the report page already has (only inline scripts and styles with hashes are allowed, all external loading is forbidden). The shell page likewise forbids remote content.
- **The report frame is restricted**: the embedded frame is sandboxed and cannot access the shell's interfaces; there is only one kind of message between it and the shell ("open this evidence"), and on receiving it the shell checks that the path really belongs to the current report.
- **Least privilege**: the Tauri permission manifest opens only the commands that are needed. The ability to run external programs is not opened; file reads and writes are limited to paths the user chose through a dialog or drag and drop, plus the application data directory.
- **Dropped paths**: read-only, symlinks are not followed, same as the command line.
- **Worker process**: after it crashes or is killed, the UI process is responsible for cleaning up the temp directories it left behind.

---

## 5. Testing

| Layer | Method |
|---|---|
| The engine's analysis session and byte reads | Rust unit tests and integration tests; the bytes read are compared with the original file and with the content extracted by 7-Zip |
| Message protocol | Round-trip tests; malformed messages do not crash either side |
| Worker process | Start a real child process: normal completion, cancellation, forced kill on timeout, cleanup after a crash |
| Consistency with the command line | For the same input, the `report.json` of the desktop app and of `analyze-anything` are byte-for-byte identical |
| Frontend logic | Unit tests (Vitest) |
| Host mode of the report UI | Keep using the existing Playwright browser tests, plus "clicking evidence sends the correct message" |
| Compare | Construct pairs of reports and verify the classification into added, disappeared, changed |
| End-to-end for the whole application | See below |

**Limits of end-to-end testing**: Tauri's official automation driver supports only Windows and Linux; the macOS system WebView has no corresponding driver. So:

- Automated end-to-end tests run on Linux CI.
- On macOS, the UI is covered by browser tests (with mock data for the backend), the Rust side is covered by the layers of tests above, and the whole-machine flow relies on a manual checklist.
- This means the full "drop in → report → export" flow of the macOS version has no automated safeguard and needs you to accept it on a real machine.

---

## 6. Milestones (macOS first)

At the end of every milestone there is an application that runs.

| Milestone | Content | Acceptance | Estimate |
|---|---|---|---|
| **D0 Technical validation** | A minimal Tauri application; one analysis run through the child process + message protocol; load `report.html` through a custom protocol; confirm that the strict content security policy takes effect in the WebView; measure application size and startup time | Can drop in a file and see the report; write up the validation conclusions | 1 week |
| **D1 Engine additions** | Analysis session (keep the artifact tree, read bytes by range), per-file progress, serializable events, message protocol crate | Tests pass; command-line behavior and output unchanged | 1–1.5 weeks |
| **D2 Main flow** | Drag and drop and open, progress UI, cancel, report view, Chinese/English switch, export to each format | The full "open → analyze → read → export" flow works; byte-for-byte identical to the command-line output | 2 weeks |
| **D3 Evidence and file tree** | Host mode of the report UI, hex view, file tree browsing, jumping from a finding to its evidence | Clicking any finding with a byte range shows the corresponding bytes | 1.5–2 weeks |
| **D4 History and compare** | History list, reopen, delete; comparison logic and UI; `analyze-anything diff` | For two versions of the same app, the added and disappeared findings can be seen | 1.5 weeks |
| **D5 Packaging and polish** | `.app` and DMG, icon, menus, shortcuts, light and dark mode, error messages, CI build; signing and notarization (only when a certificate is available, see §9) | A macOS version that can be distributed to others for installation | 1–1.5 weeks |
| **D6 Windows and Linux** | Build, installers (MSI / NSIS, AppImage / deb), platform differences, end-to-end tests on Linux | Estimated separately, about 1–2 weeks | Later |

D0 through D5 total 8–10 weeks.

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| The strict content security policy conflicts with scripts injected by Tauri | Validate in D0; the report sits in a separate restricted frame and does not need Tauri's interfaces anyway |
| No end-to-end automation on macOS | Push the logic into testable layers as far as possible; manual checklist; run automation on Linux |
| Without an Apple developer certificate, the system blocks other people from opening the application | See §9 item 5; without a certificate you can still use it yourself, only distribution is limited |
| Size: the engine with PDF is about 48 MB, plus the shell | Measure in D0; if necessary make PDF optional in the desktop app |
| Large reports (tens of thousands of files) stutter in the UI | The existing report UI has been tested with virtual scrolling on 50,000 files; the hex view likewise loads on demand |
| Reports in the history are incompatible with a new version | `report.json` has a version number; when an old version is read, prompt to re-analyze |
| Real-world feedback not yet gathered in phase one will change the report UI | There is only one report UI; changes carry over to the desktop app automatically |

---

## 8. Impact on phase one

- `aa-engine` gains the analysis session and finer-grained progress events; the existing entry point is kept, and the behavior and output of the command line do not change.
- The report script in `aa-report` gains host mode; a `report.html` opened on its own does not change.
- A new `analyze-anything diff` command is added.
- The command line may choose to reuse the child process approach, so that `--analyzer-timeout` really terminates a stuck analysis. This is optional and is not committed to in this phase.

---

## 9. Decisions made (2026-11-19)

The items below are set as recommended and can be changed at any time:

1. **Frontend**: TypeScript + Vite, no UI framework.
2. **Application name and identifier**: "Analyze Anything", `com.atomsprout.analyze-anything`.
3. **The history does not save the original file**, nor the unpacked content. Past reports cannot show hex evidence; the UI offers "Re-analyze".
4. **Auto-update**: not in phase two.
5. **Signing and notarization**: whether an Apple Developer ID certificate is available is not yet confirmed. Until D5, work as if there is none (the application can be used by yourself; when it is distributed to others, they need to allow it manually); at D5, if a certificate is available, add signing and notarization.

## 10. Current state (2026-11-19)

D0–D5 are complete. The macOS (Apple silicon) version is signed, notarized and released through Homebrew. D6 (Windows and Linux) has not started.

- The D0 validation conclusions are in [spikes/desktop.md](spikes/desktop.md); structure, test layering, self-check mode and the release method are in [DESKTOP.md](DESKTOP.md).
- Where things differ from this plan:
  - The message protocol did not become a small crate of its own. It lives in `aa-worker` together with the worker process's server and client; the application layer that does not depend on the UI (export, history, run control) lives in `aa-app`, and the command line also writes files through it.
  - §5 says the whole-machine flow on macOS "relies on a manual checklist". In practice an application self-check mode was added, and the flow in a real window is checked automatically; only three things remain manual: menus, drag and drop, and system dialogs.
  - §9 item 5: a Developer ID certificate is available, and signing and notarization were done in D5.
  - "File tree browsing" uses the file inventory built into the report page (tree, filtering, each file's type, size, hashes and the data read by the analyzers); the shell only adds "View bytes".
  - Besides the report, the history also saves the path of the original file, used for "Re-analyze"; the original file and the unpacked content are still not saved.
