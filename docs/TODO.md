# What is left to do

Phase one (the command line) and the macOS desktop app of phase two (D0–D5) are done, and so is the optional AI interpretation of phase three. This file lists what is not finished, item by item; the direction and the order of the larger work are in [ROADMAP.md](ROADMAP.md). Known limits of what the program does are in [LIMITATIONS.md](LIMITATIONS.md); the desktop app is described in [DESKTOP.md](DESKTOP.md).

## Next (planned 2026-11-20, after 0.1.1)

The order in which the open items below are taken up. It follows the first direction of the roadmap, "the same thing on every system", and starts with what needs nothing but this repository.

1. Work in the code alone, needing no other machine and no sample:
   - the command line runs the analysis in a child process, as the desktop app does, so that `--analyzer-timeout` really stops a stuck analyzer;
   - a comparison no longer counts a finding as changed because its text holds the input's name;
   - the CMS signature of the Apple pkg inside Xcode is read (the tag the parser does not expect).
2. The command line for Linux and Intel Macs: try the builds CI makes by hand, then release them.
3. A first run on a Windows machine, with the signature findings compared against `signtool`. It waits for a machine; the Windows build of the command line is released after it.
4. Real samples for the formats that were only tried on constructed data (see "Needs real samples").

After these: the desktop app for Windows and Linux (D6), and the signed release built in CI.

## Done (2026-11-19, on one Apple silicon Mac)

- [x] **The command line tried on a Mac**: 8 installed apps, 5 real IPAs and DMGs. 332 points agree with `codesign`. Five problems were found and fixed: files added by the App Store reported as "added after signing"; wildcard profiles and sandbox entitlements reported as exceeding the profile; a private-key marker with no key material reported as "embedded private key (high)"; an empty name when the input folder is itself an app; English file types inside Chinese reports.
- [x] **Encrypted IPAs from the App Store**: FairPlay encryption is recognized; metadata, signature and resources are analyzed in full.
- [x] Findings that are the same for every slice of a universal binary are merged into one, with the architectures in brackets.
- [x] An MSI's own digital signature: content digest, metadata digest, signature value and certificate chain are verified (compared with osslsigncode).
- [x] Mach-O export tries, chained fixups and bind opcodes (compared with `dyld_info`, `nm`, `objdump`).
- [x] Temporary folders left by a run that was killed are removed when the next run starts.
- [x] Scripts that compare against real samples are in the repository: `tools/native-compare/macos_real.py` (signatures), `macos_symbols.py` (imports and exports).
- [x] A stuck analyzer is really stopped in the desktop app, which runs the analysis in a child process and kills it on cancel. The command line still only stops waiting.
- [x] The desktop app, D0–D5: spikes, engine additions, the main flow, evidence and the hex view, history and comparison (with `analyze-anything diff`), packaging, signing and notarization.
- [x] Released through Homebrew: the command line and the desktop app install separately; Apple silicon only.
- [x] Reports and the app are in English unless another language is asked for.
- [x] The command is `analyze-anything` everywhere (it was `aa`, which macOS already has as Apple Archive), with the short name `aaaa`; a bare path is analyzed; the report goes to `<input>.report`.
- [x] The optional AI interpretation: the model looks things up in the report through read-only tools; run by a model service with an API key, Claude Code, Codex, Ollama, or a command; settings in `~/.analyze-anything/config.toml`. See [AI.md](AI.md).
- [x] CI passes on Linux, macOS and Windows for the current code (run of 2026-11-19). It found two things macOS had hidden: a worker that ended before it was asked was reported as a broken pipe, and two imports unused outside Unix.
- [x] An interface for AI agents: `analyze-anything mcp` serves a report's read-only tools over MCP.

## Done for 0.1.1 (2026-11-20)

- [x] **Every app in the Applications folder of one Mac**: 52 apps, 677,336 files, about seven and a half minutes, no failure. What looked wrong was compared with `codesign`, and six things were fixed:
  - a program whose bundle's `Info.plist` names no executable (the key absent, or empty) was reported as a file added after signing; the system goes by the bundle's name then, and so does this now;
  - a main program with a plist section of its own was reported as having a broken seal, though its Info.plist slot seals the bundle's file;
  - a framework that holds two versions (Chrome keeps the previous one beside the new) was reported as replaced code;
  - a TIFF picture was taken for an HFS+ disk because of two letters;
  - team-prefixed macOS app groups were reported as beyond the provisioning profile;
  - a bundle given as a folder was called "a folder".
- [x] Counts read right: "1 file", "1 URL scheme", "1 kind / 1 finding", with the verb agreeing, in rule texts, limitation details and the report's own words.

Left from that run, both honest limitations rather than wrong findings:

- [ ] The CMS signature of one Apple pkg inside Xcode (`XcodeSystemResources.pkg`) is not read: a tag the parser does not expect.
- [ ] The file system of Xcode's device-support disk images (`*_DDI.dmg`) is read only in part ("block 12 is not a B-tree node").

## The AI interpretation

- [x] Run the `claude` engine for real: done with a signed-in Claude Code on a 456-finding IPA report (no statement dropped).
- [x] Run the `codex` engine for real: done with Codex CLI 0.170 on the same report (no statement dropped).
- [x] Run the `ollama` engine against a real Ollama: done with `qwen3:4b` on a 456-finding IPA report (no lookups made by this small model, no statement dropped). A larger model that uses the tools has not been tried.
- [x] Run the Anthropic protocol of the `api` engine with a real key: done with `claude-opus-5-5` on a 456-finding IPA report (9 lookups, no statement dropped).
- [ ] Put the interpretation into the HTML and PDF reports as a chapter of its own, marked AI-generated.
- [x] Offer it in the desktop app: a panel beside the report, with the same settings file. Setting it up from inside the app, and stopping an interpretation that is under way, are not there yet.
- [ ] Follow-up questions about a report: `analyze-anything ask out/ "which hosts does it mention?"`.
- [ ] A SKILL.md, and a tool-server mode in which an agent can also ask for an analysis.

## The deep level

Done: `--deep` with Ghidra and Hopper, tried on a real IPA with both ([DEEP.md](DEEP.md)).

- [ ] IDA as a third tool. The interface is there; it has to be written where IDA can be run.
- [ ] Try it on Windows programs (PE), and Ghidra on Linux and Windows.
- [ ] Confirm that Hopper closes the documents the level opens: the script asks it to, and the windows are no longer on screen, but this was not looked at in the app itself.
- [ ] A longer list of APIs, and one a user can add to.
- [ ] Offer the level in the desktop app (the worker has to be told to use it).

## Waiting for a person

- [ ] GitHub Actions refused to start jobs for this organization while the repository was private ("recent account payments have failed or your spending limit needs to be increased"). Public repositories are not affected, so CI runs now; the billing notice still stands for anything private.
- [ ] The website is published by hand with `tools/site/publish.sh`; a workflow could take that over.
- [x] **Three manual checks of the desktop app**: native menus and shortcuts, drag and drop, the system's open and save dialogs. Done on 2026-11-19 with the released 0.1.0 (see [DESKTOP.md](DESKTOP.md)); to be repeated when the shell changes.
- [ ] **Read a real report through**: where `report.html` and `report.pdf` are wordy or lack something takes a person to judge. How much each chapter says, and how many findings of a kind are listed before they are merged (10 now), wait for that.
- [ ] **Try it on a Windows machine** (postponed): run a real installer and an installed program folder; compare the signature findings, the MSI ones included, with `sigcheck` or `signtool verify /pa /v`.
- [ ] Wire the two new scripts of [tools/native-compare/](../tools/native-compare/) into the "Native comparison" workflow. They need real apps on the machine; samples must be chosen for GitHub's runners first.

## Needs real samples

These formats were tested with constructed data only:

- [ ] **Packed APKs** (360, Tencent Legu, Bangcle and the like): confirm that the packer is recognized and that the report says the real code is not visible.
- [ ] **XAPK / APKS / APKM**. An `.apks` can be made from an AAB with Google's bundletool:
      `java -jar bundletool-all.jar build-apks --bundle=app.aab --output=app.apks`
- [ ] **Encrypted DMGs**: only "recognized as encrypted, and no content is claimed" was verified.
- [ ] **Inno Setup 6.4 installers**: the files come out, but the reference tool `innoextract` cannot read this version, so the result is unchecked.

## Loose ends of phase one

- [ ] English fragments left in Chinese rule text: file types follow the language now; the technical reason a signature failed (an error text from the parsing library) does not.
- [ ] The command line could use the child process too, so that `--analyzer-timeout` really stops a stuck analysis.
- [ ] In a comparison, findings whose text holds the input's name count as changed; the name could be taken out of the parameters before comparing.

## After phase two

- [ ] D6: the desktop app for Windows and Linux (build, installers, platform differences, end-to-end automation on Linux).
- [ ] Released builds of the command line for Linux, Windows and Intel Macs. They are built in CI on a version tag but have not been tried by hand.
- [ ] Automatic updates (out of scope for phase two).
- [ ] The signed release build is made on a developer's Mac with `tools/release/macos.sh`. Moving it into CI needs the certificate and the notarization credentials as repository secrets.

## Phase three: the ecosystem

- [ ] More inputs: Linux packages (deb, rpm, AppImage), HarmonyOS HAP, PyInstaller and similar bundles.
- [x] A `deep` level: done with Ghidra and Hopper; what is left of it is under "The deep level" above.
