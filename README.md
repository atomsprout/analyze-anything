# Analyze Anything

[中文](README.zh-CN.md) · [Website](https://atomsprout.github.io/analyze-anything/)

Give it any artifact on your computer — an IPA, an APK, a macOS app, a DMG or pkg, a Windows installer or program folder, an archive, a folder, any file — and get a report you can trust and trace: every finding carries its evidence (which file, where in it, what was read there) and a confidence, and whatever could not be analyzed is listed under coverage and limitations.

```
analyze-anything App.ipa
```

That writes `App.ipa.report/` with the report as HTML, PDF, Markdown, plain text and JSON. SARIF and CycloneDX are available too.

- **Static only.** The input is read, never run, installed or loaded.
- **Offline.** The analysis connects to nothing and uses no language model.
- **Deterministic.** The same input gives the same report, byte for byte.
- **Written in Rust**, with no outside tools needed at run time.

There are two ways to use it, on the same engine, giving the same report for the same input:

- the **command line**, `analyze-anything` (short name `aaaa`);
- the **desktop app** for macOS: drop a file, watch the progress, read the report, click a piece of evidence to see its bytes, export, keep a history and compare two versions, and, if you set it up, have a model explain the report beside it.

## Install

macOS on Apple silicon, with Homebrew:

```
brew install atomsprout/tap/analyze-anything                  # the command line
brew install --cask atomsprout/tap/analyze-anything-desktop   # the desktop app
```

Each works without the other. Both are signed with a Developer ID certificate and notarized by Apple.

On other platforms, build the command line from source (Rust 1.90 or newer):

```
cargo build --release
target/release/analyze-anything <file or folder>
```

Released builds exist for Apple silicon Macs only. On Linux and Windows the code builds and its tests pass in CI, but nobody has used it by hand there yet.

## Use

```
analyze-anything <file or folder>                 # analyze; the report goes to <name>.report/
analyze-anything App.ipa -o out --lang zh         # choose the folder; write the report in Chinese
analyze-anything diff old/report.json new/report.json    # what changed between two versions
analyze-anything explain out/report.json <finding id>    # one finding with all its evidence
analyze-anything verify out/                      # are the files still what was written?
```

The full guide is [docs/USAGE.md](docs/USAGE.md).

## What it reads

| | |
|---|---|
| Apple | `.app` and other bundles, IPA, DMG (HFS+ and APFS), pkg; Info.plist, code signatures and certificate chains, sealed resources, entitlements, provisioning profiles, privacy manifests, FairPlay encryption |
| Android | APK, AAB, XAPK / APKS / APKM; manifest, resources, signature schemes v1–v3.1, DEX, SDKs and packers |
| Windows | PE, Authenticode, .NET assemblies, MSI (with its own signature), NSIS, Inno Setup, CAB, self-extractors, Electron (asar), MSIX, installed program folders |
| General | Mach-O, ELF and PE structure and hardening; zip, tar, 7z, gzip, bzip2, xz, zstd, nested to any depth; URLs, likely credentials, entropy, duplicate files |

## Optional: an AI reading of the report

Off unless you turn it on. Once a report is written, a language model can explain it in plain words:

```
analyze-anything ai claude          # once: choose who does it (here Claude Code, no API key needed)
analyze-anything App.ipa --ai       # analyze, then write ai.md next to the report
```

You choose who does it: a model service you have an API key for (Claude, or anything that speaks OpenAI's protocol), Claude Code, Codex, or a model that Ollama runs on your own machine. A program of your own works too. The model sees the report, never the analyzed files, and looks things up in it through read-only tools. Every statement it makes must cite findings of the report; those that do not are dropped. See [docs/AI.md](docs/AI.md).

## Good to know

- Severity is a fixed property of each rule, there to order your reading. The report does not say whether an input is safe.
- Findings marked heuristic (likely credentials, packers, SDK detection) can be false positives.
- Signatures are checked against the file itself: digests, signature values, certificate chains. Revocation, system trust settings and Apple's notarization status are not checked; that would need the network.
- An IPA downloaded from the App Store is encrypted: this is recognized, and metadata, signature and resources are analyzed as usual, but the encrypted code cannot be read.
- Use it only on things you have the right to analyze.

More in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Documentation

- [docs/USAGE.md](docs/USAGE.md) — the command line in full ([中文](docs/USAGE.zh-CN.md))
- [docs/AI.md](docs/AI.md) — the optional AI interpretation
- [docs/DESKTOP.md](docs/DESKTOP.md) — the desktop app: structure, development, testing, release
- [docs/LIMITATIONS.md](docs/LIMITATIONS.md) — known limitations
- [docs/ANALYZERS.md](docs/ANALYZERS.md) — how to add a format
- [docs/TODO.md](docs/TODO.md) — what is left to do
- [docs/PLAN.md](docs/PLAN.md), [docs/PLAN-DESKTOP.md](docs/PLAN-DESKTOP.md), [docs/RESEARCH.md](docs/RESEARCH.md), [docs/spikes/](docs/spikes/) — how it was planned and what was tried

## Development

```
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The desktop app lives in `apps/desktop`; see [docs/DESKTOP.md](docs/DESKTOP.md). Issues and pull requests are welcome. Please do not attach files you have no right to share: the one finding from `report.json` that shows the problem is usually enough.

## License

Apache-2.0; see [LICENSE](LICENSE). What is bundled from others, the fonts in the reports among them, is listed in [NOTICE](NOTICE).
