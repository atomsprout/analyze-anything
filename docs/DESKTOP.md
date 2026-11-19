# Desktop app

A graphical interface for the same analysis engine: drop a file in → watch progress → read the report → look at the evidence bytes → export → history and diff. It adds no analysis capability; the same input produces byte-identical reports in the desktop app and in `analyze-anything`. The plan is in [PLAN-DESKTOP.md](PLAN-DESKTOP.md).

Only a macOS (Apple silicon) build exists for now.

## Install

```
brew install --cask atomsprout/tap/analyze-anything-desktop   # desktop app
brew install atomsprout/tap/analyze-anything                  # command line, installed as analyze-anything
```

Neither depends on the other; you can install just one.

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

| Layer | Where |
|---|---|
| Analysis session, reading bytes, progress events, cleanup of leftover temporary directories | `crates/aa-engine/tests/analyze.rs` |
| Message protocol round trips, malformed messages, and completion / cancellation / force-killing a hung process / crash cleanup with a real child process | `crates/aa-worker/tests/worker.rs` |
| Run control, export to each format, history records | `crates/aa-app/tests/app.rs` |
| Diff | `crates/aa-export/src/diff.rs` |
| Page logic (text, hex view conversions, progress) | `apps/desktop/tests/format.test.ts` |
| The page working with a real report page (sandboxed frame, clicking evidence sends a message, language sync, export, history, diff) | `apps/desktop/tests/browser/app.spec.ts` |
| The whole flow in a real window, and exports being byte-for-byte identical to the command line | `tools/desktop-check/check.py` |

### Self-check mode

The macOS system WebView has no usable automation driver, so the application can check itself: when started with the environment variable `AA_DESKTOP_SELFTEST=<plan file>`, the page clicks through its own interface like a user and runs the whole flow, records what it sees, and the application writes the results to a file and exits. No dialogs appear in this mode: "Open" returns the inputs in the plan in turn, and "Save" writes into the folder the plan specifies. Without this variable, the three related commands always refuse.

```
python3 tools/desktop-check/check.py \
    "target/aarch64-apple-darwin/release/bundle/macos/Analyze Anything.app/Contents/MacOS/analyze-anything-desktop" \
    target/release/analyze-anything  old-version.ipa new-version.ipa --slow a-very-large.dmg
```

The self-check uses a separate data folder and does not touch the real history; the interface language is recorded in the WebView's storage, which is shared with the normally installed application, and the self-check changes it back to the original language when it ends (the 0.1.0 release package does not have this step yet; after running the self-check against it the interface stays in English, and you can change it back in the "View" menu).

It checks: the page's content security policy is in effect (an injected script does not run, text cannot be executed as code, the network cannot be reached), analysis and progress, the report loads in the frame, the bytes shown in the hex view match the file and the evidence range is marked, jumping to an offset, refusing paths that are not in the report, export in 7 formats and "all formats to a folder", switching language and appearance, opening and deleting history, a history report explaining why the bytes cannot be viewed, the diff numbers, returning to the home page after cancellation without leaving a record; after exit no worker process or temporary file is left behind; every exported file is byte-for-byte identical to the file `analyze-anything` writes for the same input, and `analyze-anything verify` accepts the exported folder.

### Three places that still need manual checking

The self-check goes through the page. The three places below go through system UI and have no automated coverage:

- The native menu bar: each item can be clicked, and the shortcuts work (⌘O, ⇧⌘O, ⌘E, ⇧⌘E, ⇧⌘H).
- Drag and drop: drag a file onto the window, the drop zone highlights, and analysis starts on release.
- The system open / save dialogs, and opening a file with "Open With" in Finder.

## Release

```
tools/release/macos.sh
```

Builds `analyze-anything` (tar.gz) and the desktop app (DMG) for Apple silicon, signs them with a Developer ID certificate, enables the hardened runtime, and submits them for Apple notarization. It needs the environment variables `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_SPECIFIC_PASSWORD`, and that team's "Developer ID Application" certificate in the keychain. The artifacts are written to `dist/release`; the script itself uploads nothing.

Release packages are placed in the Releases of the public repository [atomsprout/analyze-anything-release](https://github.com/atomsprout/analyze-anything-release), and the Homebrew definitions are in [atomsprout/homebrew-tap](https://github.com/atomsprout/homebrew-tap).

## Where data is stored

- History records: `~/Library/Application Support/com.atomsprout.analyze-anything/history/`, one folder per analysis, containing `report.json`, `manifest.json` and `entry.json` (name, time, SHA-256 of the input, path of the original file). The analyzed file is not saved, and neither is the unpacked content.
- Temporary files: `~/Library/Caches/com.atomsprout.analyze-anything/scratch/`, large files unpacked during analysis. Deleted when the report is closed, when the next analysis starts, or on exit; if the application was forcibly ended, they are cleaned up at the next launch.
- The environment variable `AA_DESKTOP_DATA_DIR` moves both locations to another folder, for trying things out without affecting the real history.
