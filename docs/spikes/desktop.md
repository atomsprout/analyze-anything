# Desktop app technical validation (D0): findings

2026-11-19, an Apple silicon Mac, macOS 27.2, Tauri 2.12, the system WebView (WKWebView). The findings for the questions the plan listed as risks for D0 to answer are below.

## Can you drop a file in and see a report

Yes. A minimal application uses "starting itself once more with `--worker`" as the worker child process; the two communicate with messages of one JSON per line, and a real analysis ran end to end. The report page is loaded into an embedded frame through the custom protocol `report://localhost/<id>` and displays normally.

## Does a strict content security policy take effect in the WebView

It does; both layers were verified.

- **Report page**: the policy that `report.html` carries (`default-src 'none'`, scripts and styles allowed only by SHA-256) takes effect as is, and the interactive interface runs normally. The frame it lives in is `sandbox="allow-scripts"` with no same-origin permission; Tauri's interface is not injected into it, and it cannot call any command of the shell. The "conflict between the strict policy and the scripts Tauri injects" that the plan worried about did not happen: the conflict presupposes that Tauri injects scripts into this frame, and it does not.
- **Shell page**: `default-src 'none'; script-src 'self'; frame-src report:; connect-src ipc: …`. The application's self-check confirmed in a real window: a dynamically inserted inline script does not execute, `eval` is refused, and `fetch` to an external address is refused.

One detail worth recording: the development server (Vite) rewrites the HTML pages it serves. Once the report page is rewritten, the script hashes no longer match, the policy refuses them, and the whole page is blank. So in the browser tests the sample report is served unchanged by a middleware that does no rewriting. The application does not have this problem, because the report page is rendered directly on the Rust side.

## Is reading evidence bytes across processes fast enough

Yes. The hex view asks the worker process for data in 64 KB blocks and draws only the rows on screen; there is no perceptible delay between clicking a piece of evidence and the bytes appearing. The bytes pass through two layers of inter-process communication as hexadecimal text (worker process → UI process → page), about 128 KB of text per block.

## Is cancellation deterministic

Yes. On cancellation a message is sent first, and the worker process is force-ended if it has not ended within 5 seconds. For a 320 MB DMG that unpacks to 7461 files, clicking cancel while analysis was in progress returned to the home page in about 1.1 seconds; after exit no worker process or temporary file was left behind. In a test with a fake worker process that "does not respond at all", the forced end happened after the 5-second grace period.

## Size

| Item | Size |
|---|---|
| Command line `analyze-anything` (with PDF) | 45 MB |
| Desktop app executable (with PDF and the WebView shell) | 50 MB |
| `Analyze Anything.app` | 48 MB (on disk) |
| DMG | 26 MB |
| Command line tar.gz | 24 MB |

The shell makes the executable only about 5 MB larger than the command line, because the WebView is the one that ships with the system. The plan's fallback of "making PDF optional if necessary" is not needed.

## What to do about the lack of end-to-end automation on macOS

The plan's answer was a "manual checklist". The actual approach goes further: the application has a self-check mode in which, in a real window, the page clicks through its own interface, runs the whole flow and writes out the results; an external script then compares the exported files byte for byte with the command line output ([tools/desktop-check](../../tools/desktop-check/), described in [DESKTOP.md](../DESKTOP.md)). This makes 53 checks in the real WebView automatic; only three places — native menus, drag and drop, and system dialogs — need a manual look.

How the page works with the report page (clicking "View bytes" in the sandboxed frame → the shell receives the message → the hex view opens) is tested with Playwright in WebKit and Chromium, with mock data for the backend.

## Estimate correction

The plan estimated 8–10 weeks in total for D0–D5. In practice, reusing the report interface and the engine already being written as "library + thin shell" made the shell work far smaller than estimated; what took the most time was not the interface, but making cancellation, cleanup, and byte-for-byte consistency with the command line things that tests can prove.
