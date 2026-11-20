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

## Examples

Reports about public releases of open-source software, as PDFs, are on the [website](https://atomsprout.com/analyze-anything/#examples): an IPA, an APK, a DMG, a macOS pkg, an NSIS and an MSI installer, and a Linux program. `tools/site/examples.py` makes them again from the same files.

## What it reads

| | |
|---|---|
| Apple | `.app` and other bundles, IPA, DMG (HFS+ and APFS), pkg; Info.plist, code signatures and certificate chains, sealed resources, entitlements, provisioning profiles, privacy manifests, FairPlay encryption |
| Android | APK, AAB, XAPK / APKS / APKM; manifest, resources, signature schemes v1–v3.1, DEX, SDKs and packers |
| Windows | PE, Authenticode, .NET assemblies, MSI (with its own signature), NSIS, Inno Setup, CAB, self-extractors, Electron (asar), MSIX, installed program folders |
| General | Mach-O, ELF and PE structure and hardening; zip, tar, 7z, gzip, bzip2, xz, zstd, nested to any depth; URLs, likely credentials, entropy, duplicate files |

## How it works

One pass, read only: the input is opened layer by layer, each file is read by the analyzers that understand it, a last step relates the files to one another, and everything that was found is written down with its evidence. The report is the single source of every output format.

```mermaid
flowchart LR
  input["Any file or folder<br/>IPA · APK · DMG · pkg<br/>MSI · exe · archive"]:::sun --> unpack["Unpack<br/>layer by layer<br/>read only, never run"]:::coral
  unpack --> analyze["Analyzers<br/>content · binary<br/>Apple · Android · Windows"]:::sky
  analyze --> relate["Correlate<br/>across files"]:::lime
  relate --> report[("Report<br/>findings + evidence + confidence<br/>coverage and limitations")]:::pink
  report --> formats["HTML · PDF · Markdown · text<br/>JSON · SARIF · CycloneDX"]:::orange
  report -. "optional, off by default" .-> ai["AI interpretation<br/>may only cite findings"]:::sun
  classDef sun fill:#ffc93c,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef coral fill:#ff6b5e,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef sky fill:#5ccbf2,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef lime fill:#a6e05a,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef pink fill:#ff8fb1,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef orange fill:#ff9f1c,stroke:#2b2118,stroke-width:2px,color:#2b2118;
```

The command line and the desktop app are two faces of the same engine, so one input gives the same report in both. The desktop app never analyzes in its own process: a worker does, and can be stopped for certain.

```mermaid
flowchart LR
  cli["Command line<br/>analyze-anything"]:::sun
  app["Desktop app<br/>window ⇄ shell ⇄ worker process"]:::coral
  subgraph engine["Engine (Rust crates)"]
    direction LR
    unpack["aa-unpack"]:::sky --> analyzers["aa-content · aa-binary<br/>aa-apple · aa-android · aa-windows"]:::sky --> correlate["aa-correlate"]:::sky
  end
  report[("Report<br/>aa-core")]:::lime
  exports["aa-report · aa-export<br/>HTML · PDF · Markdown · text<br/>JSON · SARIF · CycloneDX"]:::orange
  ai["aa-interpret<br/>optional AI interpretation"]:::pink
  mcp["mcp<br/>read-only tool server<br/>for AI agents"]:::pink
  cli --> unpack
  app --> unpack
  correlate --> report
  report --> exports
  report -.-> ai
  report -.-> mcp
  classDef sun fill:#ffc93c,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef coral fill:#ff6b5e,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef sky fill:#5ccbf2,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef lime fill:#a6e05a,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef pink fill:#ff8fb1,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  classDef orange fill:#ff9f1c,stroke:#2b2118,stroke-width:2px,color:#2b2118;
  style engine fill:#5ccbf222,stroke:#5ccbf2,stroke-width:2px;
```

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
