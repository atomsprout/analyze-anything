# Desktop app

A graphical interface for the same analysis engine: drop a file in → watch progress → read the report → look at the evidence bytes → export → history and diff. It adds no analysis capability; the same input produces byte-identical reports in the desktop app and in `analyze-anything`. The plan is in [PLAN-DESKTOP.md](PLAN-DESKTOP.md).

Only a macOS (Apple silicon) build exists for now.

## Install

```
brew install --cask atomsprout/tap/analyze-anything-desktop   # desktop app
brew install atomsprout/tap/analyze-anything                  # command line, installed as analyze-anything
```

Neither depends on the other; you can install just one.

For driver-package inputs, the home page offers **Driver source mapping (optional)**.
Add logical INF/distribution-root pairs before selecting or dropping the input; the
same limits and interpretation as `--windows-source-root` apply (see [USAGE.md](USAGE.md)).
The default is no assignments. Returning home clears the draft; language changes keep
it, and analyzing a kept report again uses that report's validated assignments.

## Structure

| Location | Contents |
|---|---|
| `crates/aa-engine` | The analysis session (after analysis ends it can still read the bytes of any file by range), per-file progress, serializable events |
| `crates/aa-worker` | The worker child process: the message protocol (one JSON per line), the server loop, the client (can end the child process deterministically and clean up its temporary directory) |
| `crates/aa-app` | The UI-independent application layer: export to each format (the command line uses it too), history records, running one analysis through the worker process |
| `diff` in `crates/aa-export` | The diff of two reports, shared by `analyze-anything diff` and the desktop app |
| `apps/desktop/src-tauri` | The Tauri shell: window, menus, commands, the `report://` protocol, self-check mode |
| `apps/desktop/src` | The page: TypeScript, no UI framework |

The desktop program started with the `--worker` argument is itself the worker process; no separate executable is distributed. The UI process never analyzes anything in its own process.

The report view is the `report.html` that the command line writes, placed in a sandboxed frame that only allows scripts to run, and loaded through `report://localhost/<id>`. It carries its own strict content security policy and cannot reach any command of the shell; it sends the shell only one kind of message ("show this range of bytes of this file"), and the shell validates it again on receipt.

Every command the page can call is listed in `src-tauri/build.rs` and allowed one by one in `capabilities/default.json`; no file system, program execution or network capability is opened. The page can only request analysis of paths the user selected through a dialog, drag and drop, or "Open With".

The optional AI interpretation ([AI.md](AI.md)) is the one thing that reaches outside: the shell, never the page, asks the model the user set up in `~/.analyze-anything/config.toml`, and only when the user presses the button on a report. The page still has no network capability. The host tells the report frame which finding to show when a citation is clicked; the frame looks the id up among its own findings and is told nothing else. Started as `mcp <report.json>`, the desktop program is the read-only tool server for an engine that hands the work to another program, as `analyze-anything mcp` is.

## Development

```
cd apps/desktop
npm ci
npm run tauri dev          # run in development mode
npm test                   # unit tests for the page logic (Vitest)
npm run fixture            # generate the sample report used by the browser tests
npm run test:browser       # test the page in WebKit and Chromium (Playwright, backend uses mock data)
```

The workspace's default members do not include the desktop app, so `cargo build` / `cargo test` do not compile it; use `-p aa-desktop` when needed.

## Test layers

The logical-root control passed the 14 page unit tests, TypeScript/Vite build and
28 WebKit/Chromium browser tests on the Windows x64 development host. These include
invalid-path refusal, canonical assignments, clearing new-input settings, preserving
drafts across language changes and retaining mappings when reanalyzing history.
The browser backend is a stand-in; a separate `aa-app` test compares the configured
worker's complete report with a direct engine run on a constructed INF/payload folder.
This does not qualify the control in a native Windows window.

| Layer | Where |
|---|---|
| Analysis session, reading bytes, progress events, cleanup of leftover temporary directories | `crates/aa-engine/tests/analyze.rs` |
| Message protocol round trips, malformed messages, and completion / cancellation / force-killing a hung process / crash cleanup with a real child process | `crates/aa-worker/tests/worker.rs` |
| Run control, export to each format, history records | `crates/aa-app/tests/app.rs` |
| Diff | `crates/aa-export/src/diff.rs` |
| Page logic (text, hex view conversions, progress) | `apps/desktop/tests/format.test.ts` |
| The page working with a real report page (sandboxed frame, clicking evidence sends a message, language sync, export, history, diff) | `apps/desktop/tests/browser/app.spec.ts` |
| The whole flow in a real window, and exports being byte-for-byte identical to the command line | `tools/desktop-check/check.py` |

On 2026-11-20 the Windows x64 development host passed `npm ci`, the 10 page unit tests,
`npm run build`, sample generation with `npm run fixture`, and all 22 WebKit/Chromium
browser tests. Fixture generation now uses Node's file-copy API instead of a POSIX `cp`
command and explicitly disables optional AI interpretation. These browser tests use the
stand-in backend. They do not establish native Windows WebView2 behavior, real-window
CLI parity, menus, dialogs, Explorer drop/open integration, packaging or signed delivery;
those remain W10/D6 acceptance work.

A later Windows x64 check passed the production page build, 14 unit tests and all
28 WebKit/Chromium browser tests, including retained driver source mappings. The
MSIX content commit's CI run 44868624432 passed the three core platform jobs and
licence check but timed out in one Chromium history test. That test counted evidence
disclosures before its report frame had loaded. The shared evidence interaction now
waits for a disclosure before counting; the history test also holds the report response
until the host is visible to exercise the separate loading stages. This is browser-test
synchronization, and does not establish any additional native Windows behavior.

### Windows x64

The Windows desktop build uses WebView2. Its report iframe uses Tauri's
`http://report.localhost` protocol mapping. The Windows content security policy
permits that origin for the sandboxed iframe. The packaged application and
worker use the same executable.

On Windows 11 Home x64 build 26200 with WebView2 157.0.4341.60, the extracted
portable build and the NSIS-installed build each passed 67 real-window
self-checks. The inputs used Unicode paths 318 characters long. All seven
export formats and the folder manifest matched the CLI byte for byte.
A separate installed-window run produced the same partial report as the CLI
on a folder containing a file held open with exclusive sharing. Closing the
window removed the worker scratch directories.

Native checks also covered Tab focus, Ctrl+O, Ctrl+Shift+O and Ctrl+E, the
Windows file and folder pickers, the PDF save dialog, and normal and maximized
window sizes. The saved PDF matched the CLI. A logical driver source-root
assignment entered in the native window associated the supplied driver payload
and produced the same JSON as the equivalent CLI command.

In the Windows 10 x64 guest, dropping `sample.zip` from Explorer onto the
installed app produced a report. Windows display scaling was exercised at
100% and 125% on a 1024 × 768 display. During a change from 100% to 125%, an
ordinary window could grow past the display edge. The updated release build
fits the window to the monitor work area after a DPI change. The report and
export controls stayed visible when scaling with the window open, and the
home view stayed within the display when scaling while minimized and restoring
the window.

The desktop CI matrix includes a Windows WebView2 job that launches the actual
desktop window, runs the self-check with a cancellation input and compares the
exports with the CLI. The CI build command passed locally. A hosted run with
the new Windows desktop job remains pending. See [CI](../.github/workflows/ci.yml).

### Self-check mode

The macOS system WebView has no usable automation driver, so the application can check itself: when started with the environment variable `AA_DESKTOP_SELFTEST=<plan file>`, the page clicks through its own interface like a user and runs the whole flow, records what it sees, and the application writes the results to a file and exits. No dialogs appear in this mode: "Open" returns the inputs in the plan in turn, and "Save" writes into the folder the plan specifies. Without this variable, the three related commands always refuse.

```
python3 tools/desktop-check/check.py \
    "target/aarch64-apple-darwin/release/bundle/macos/Analyze Anything.app/Contents/MacOS/analyze-anything-desktop" \
    target/release/analyze-anything  old-version.ipa new-version.ipa --slow a-very-large.dmg
```

The self-check keeps its history in a separate data folder. On macOS the
WebView shares language settings with the installed application, so the
self-check restores the original language before it exits. The 0.1.0 package
predates that behavior. Its language can be changed in the View menu.

On Windows, the runner also gives WebView2 a separate user-data folder. Supply
a slow fixture that remains busy long enough for the cancellation test.

It checks: the page's content security policy is in effect (an injected script does not run, text cannot be executed as code, the network cannot be reached), analysis and progress, the report loads in the frame, the bytes shown in the hex view match the file and the evidence range is marked, jumping to an offset, refusing paths that are not in the report, export in 7 formats and "all formats to a folder", switching language and appearance, opening and deleting history, a history report explaining why the bytes cannot be viewed, the diff numbers, returning to the home page after cancellation without leaving a record, the AI interpretation (with a stand-in program for the model, so nothing leaves the machine: the panel says who is asked, the statements and their findings are shown and kept, a folder exported afterwards holds `ai.json` and `ai.md`, and they go when the report is deleted); after exit no worker process or temporary file is left behind; every exported file is byte-for-byte identical to the file `analyze-anything` writes for the same input, and `analyze-anything verify` accepts the exported folder.

`--ai-config <file>` uses the settings in that file in place of the stand-in, which really asks the model they name.

### Three places checked by hand

The self-check goes through the page. The three places below go through system UI and have no automated coverage. They were checked by hand on 2026-11-19 with the released 0.1.0 on macOS (Apple silicon), and should be checked again when the shell changes:

- The native menu bar: the items work (language and appearance in "View" were switched, and the menu bar itself changes language), and so do the shortcuts ⌘O, ⇧⌘O, ⌘E, ⇧⌘E and ⇧⌘H.
- Drag and drop: a file dragged from Finder highlights the drop zone, and analysis starts on release.
- The system open and save dialogs (a file was chosen and analyzed; a PDF was exported through the save dialog), and opening a file with the app from Finder ("Open With").

## Release

### Windows x64

```powershell
./tools/release/windows.ps1
```

Run with PowerShell 7 on a Windows x64 MSVC Rust host. The script writes a
portable ZIP, a per-user NSIS installer and SHA-256 sums to
`dist/release/windows-<version>`. The ZIP needs an available Microsoft Edge
WebView2 Runtime. The installer embeds Microsoft's standalone WebView2 runtime
installer so it can provide the runtime offline. File associations are deferred
for the Windows installer. [Tauri WebView2 installer options](https://v2.tauri.app/distribute/windows-installer/#webview2-installation-options)

The local packages were built without code signing. On the development host,
the NSIS installer installed and uninstalled successfully in a separate test
directory. An isolated process pointed at an empty WebView2 runtime directory
showed the native runtime-unavailable notice and exited after acknowledgment.
The host's installed runtime was available for the NSIS test. A separate
Windows 10 Enterprise LTSC Evaluation x64 guest (build 19044) had zero active
network adapters, zero default routes and no registered WebView2 runtime.
The per-user NSIS installer completed under an unelevated account and
registered WebView2 158.0.4370.33 for that user. The installed app passed all
40 native self-checks in the guest. Its seven export formats and folder
manifest matched the CLI outputs byte for byte. The comparison used the
development host's CLI because the local release CLI build imports
`VCRUNTIME140.dll`, which was absent in the baseline guest.

### Apple silicon macOS

```
tools/release/macos.sh
```

Builds `analyze-anything` (tar.gz) and the desktop app (DMG) for Apple silicon, signs them with a Developer ID certificate, enables the hardened runtime, and submits them for Apple notarization. It needs the environment variables `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_SPECIFIC_PASSWORD`, and that team's "Developer ID Application" certificate in the keychain. The artifacts are written to `dist/release`; the script itself uploads nothing.

Release packages are placed in the Releases of this repository, and the Homebrew definitions are in [atomsprout/homebrew-tap](https://github.com/atomsprout/homebrew-tap).

## Where data is stored

- History records: `~/Library/Application Support/com.atomsprout.analyze-anything/history/`, one folder per analysis, containing `report.json`, `manifest.json` and `entry.json` (name, time, SHA-256 of the input, path of the original file). The analyzed file is not saved, and neither is the unpacked content.
- Temporary files: `~/Library/Caches/com.atomsprout.analyze-anything/scratch/`, large files unpacked during analysis. Deleted when the report is closed, when the next analysis starts, or on exit; if the application was forcibly ended, they are cleaned up at the next launch.
- The environment variable `AA_DESKTOP_DATA_DIR` moves both locations to another folder, for trying things out without affecting the real history.
