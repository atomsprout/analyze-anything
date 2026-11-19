Checks the desktop app in its real window, on the machine it runs on.

No tool can drive the system web view on macOS from outside, so the app does it from inside:
started with `AA_DESKTOP_SELFTEST` it goes through its own screens (open, progress, report,
bytes, export, language, history, compare, delete, cancel) and writes down what it saw. This
script starts the app that way, reads the result, and then compares every file the app exported
with what the `analyze-anything` command writes for the same input: they must be the same bytes.

    python3 tools/desktop-check/check.py \
        "target/release/bundle/macos/Analyze Anything.app/Contents/MacOS/analyze-anything" \
        target/release/analyze-anything  first-input second-input [--slow large-input]

The inputs must be single files (an archive, a disk image, an IPA); two versions of one app make
the comparison part meaningful. `--slow` names a large input used to check cancelling. The app's
window appears while the check runs; the real history is not touched.
