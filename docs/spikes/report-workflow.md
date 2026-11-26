# Real reports and packaged workflows

This is the first delivery work package after published v0.2.0-preview.2, reviewed on
Windows x64 on 2026-11-26. It asks whether one supplied artifact can be understood and
its evidence revisited. Inputs were only read: none was run, loaded or installed.
Each scenario is independent; the MSI and installed directory are not a version comparison.

The source corrections described here are **after** preview.2. The published archive
was checked separately for its existing analysis/query/agent workflow. Its reports do
not acquire the source corrections until another build is distributed.

## Inputs, sources and scope

| Scenario | Input and source | Licence/source record | Files analyzed | Findings |
|---|---|---|---:|---:|
| Installer with supplied payloads | [7-Zip 24.08 x64 MSI](https://www.7-zip.org/a/7z2408-x64.msi), embedded CAB payloads only | [7-Zip licence](https://www.7-zip.org/license.txt): LGPL/BSD and unRAR restrictions for the respective components; sample not committed | 111 | 103 |
| Installed program directory | Locally present 7-Zip directory, History.txt starts with 25.00; 107 regular files | The directory's License.txt and the same upstream licence; sample not committed | 107 | 106 |
| Mobile application | [iSH 1.3.2 build 494 IPA](https://github.com/ish-app/ish/releases/download/builds/494/iSH.ipa) | [iSH licence](https://github.com/ish-app/ish/blob/master/LICENSE.md): GPLv3 with additional iOS terms, plus bundled components' licences; sample not committed | 190 | 235 |
| Linux package | [Debian node-isarray 2.0.5-1](https://deb.debian.org/debian/pool/main/n/node-isarray/node-isarray_2.0.5-1_all.deb), existing pinned fixture | Expat/MIT, including Debian packaging; root NOTICE and aa-linux/tests/data/COPYRIGHT-node-isarray.txt | 14 | 9 |
| Modern executable bundle | [WinSW v3.0.0-alpha.11 x64](https://github.com/winsw/winsw/releases/download/v3.0.0-alpha.11/WinSW-x64.exe) | [Source project MIT licence](https://github.com/winsw/winsw/blob/v3.0.0-alpha.11/LICENSE.txt), bundled .NET components retain their licences; sample not committed | 81 | 595 |

All five runs captured every enumerated file with no truncation or recorded content
loss. That is byte coverage, not complete semantic understanding. Limits below remain
explicit even when an analysis exits zero.

File hashes, the installed directory's complete relative-path/hash inventory, selected
finding IDs/evidence/confidence, coverage and limitations are in
[report-workflow.json](report-workflow.json). A directory has no invented whole-input
digest. Its listed file hashes bind this particular installed snapshot.

## Read each report through

These answers were checked against the complete Markdown reports, their finding
evidence and the corresponding bilingual HTML data. Empty sections were read as
unanswered questions. No runtime behavior, application entry selection or host state
was inferred from names alone.

| Scenario | Identity | Entries and components | Declared operations and network references | Evidence route | Unread or unresolved |
|---|---|---|---|---|---|
| MSI | Product 7-Zip 24.08 x64, declared version 24.08.00.0 and claimed publisher Igor Pavlov | 106 declared files; embedded executable/DLL payloads and two shortcut declarations are visible | 16 registry values, including shell-extension declarations; API imports and host strings remain static observations | Product `16b54d2d342e6174`, installation inventory `0541230abeeb5826`; original table rows remain in `windows.installer` facts | Action ordering/conditions and effective installation paths are not established; absent MSI signature does not identify a publisher |
| Installed directory | A folder of 107 files; no product identity is invented from its folder name | PE identities identify EXE/DLL files and architectures, with relative file names; no actual launch entry is selected | One manifest requests administrator rights; import capabilities are distinct from calls; host strings are not connections | Folder `db29c9269f4fbe35`, PE identity `41734d4b79562771`, manifest `6b4776537e20a5bf`; every loose file digest checked independently | Installation history, effective settings, loader resolution and runtime behavior remain outside this directory snapshot |
| iSH IPA | app.ish.iSH, version 1.3.2/build 494 | Info.plist names iSH as executable; an embedded FileProvider extension has its own identity and component evidence | Location/local-network purpose strings and background declarations are visible; declarations do not establish permission use | Identifier `238e99d90bf4ff1d`, purpose `07878be21e2e6f84`, signature `c77318c70db29b9c`; component evidence now points to the extension's actual Info.plist | Online trust, revocation and Apple policy were not evaluated; Assets.car contents are not extracted, as its finding states; no native codesign run on this Windows host |
| Debian | node-isarray 2.0.5-1, architecture all | Separate control/payload archives; JavaScript/package metadata is listed without selecting a runtime entry | Literal Depends: nodejs; no capabilities finding means unanswered, not absent; host strings are only strings | Identity `cbd2477343a5e8bb`, dependency `0f4086ee8cad91c1`, component `cee7e182b1b64024`; original Deb822 lines retained | Package authenticity, repository/host dependency resolution and script/JavaScript execution semantics are not established |
| WinSW | Windows Service Wrapper, declared version 3.0.0.0 | Version-6 single-file manifest, 80 embedded files, 78 managed assemblies; supplied XML service configuration is absent | Native/PInvoke imports indicate capabilities, not calls; .NET metadata records references and namespaces | Product `b0b3f55449725388`, bundle `b10787da96dac4a8`, assemblies `b4d17f3d18279b7a`; original manifest entry offsets retained | IL method bodies/call flow unread, now explicit for all 78 managed assemblies; runtime service commands and effective configuration cannot be reconstructed from this executable alone |

## Corrections from the review

- Identity previews previously let signing/risk totals displace identity facts. They now
  prioritize kind/product/version/identifier and identity findings. Directory identity
  previews name the source file when all evidence comes from that file. Full findings,
  severity and confidence are unchanged.
- Installer descriptions and operation titles now describe captured declarations. They
  do not claim actual writes, launches, downloads or deliberate concealment of encoded
  commands. Counts do not imply that every action or conditional branch was understood.
- Supported installer declarations always retain
  `windows.installer-semantics-unresolved`. Managed metadata retains
  `windows.dotnet-code-unread`. These semantic limits do not pretend bytes were lost.
- Apple component sources previously named bundle directories, which are not artifacts,
  leaving iSH's component finding without evidence. They now cite the captured child
  Info.plist, falling back to the containing declaration when necessary. App-extension
  components are classified as applications. A constructed engine regression and the
  real IPA check cover the correction.

MSI action sequence/condition reading remains the next feature increment. This package
does not implement it, IL analysis or retained raw-byte evidence.

## Independent checks

[report-workflow-native.json](report-workflow-native.json) retains sanitized results:

- Windows Installer OpenDatabase mode 0: eight checks over the MSI hash, product,
  version, publisher, file count/bytes, registry count and shortcut count. No installation,
  administrative extraction or setup execution.
- The Windows reference harness: 125 checks, zero failures, including 107 loose-file
  hashes, signature observations, tamper-copy and generated CAB cases. Installed dotnet.exe
  is a supplementary signed reference sample, only read. It is not a sixth product-review
  scenario. Native trust policy remains separate from offline mathematical checks.
- WinSW BinaryReader/DeflateStream reference: five checks over the version, header,
  identifier, every manifest field and all 80 embedded member digests.
- iSH: independent Python zipfile/plistlib identity and 91 direct ZIP-member digests.
  This checks bytes/metadata, not native Apple policy.
- Debian: the hash-bound dpkg-deb/libarchive observations in
  [linux-packages-native.json](linux-packages-native.json) were reused for every recorded
  regular control/payload member. Linux native tools were not rerun on Windows.

## Packaged workflow gate

`tools/release/check-workflow.py` uses only Python's standard library and the supplied
analyzer executable. It passes on the extracted **published** preview.2 Windows CLI
and on an immutable copy of the updated Windows executable. Program hashes and results
are in [report-workflow-processes.json](report-workflow-processes.json). The archive's
SHA-256 matches its public sidecar:
`0fce07982a62e9fc49d7a8d3a181e2e3fe72d2686e2026a551f6ef7ab1b099ce`.

The gate checks real supervised analysis, byte-identical repeat reports, CLI query and
explain, seven read-only snapshot MCP tools, queries after caller removal of the input,
eight rooted-agent tools, matching CLI/agent report IDs, explicit file-limit partial
results/limitations, cancellation preserving the previous report, and EOF while worker
scratch is present. It requires clean process/pipe exits, removed worker scratch and
unchanged caller-owned sentinels. Inputs are inert text and sparse bytes, never executed.

Each run owns its temporary parent. It covers a fresh worker root, a root aged one hour
before startup, and an aged unmarked sibling directory that the engine must preserve.
Creating a worker can refresh the root timestamp; the engine's separate aged-root
regression directly covers the ownership-marker boundary. Existing marker/junction,
unresponsive-worker and process regressions remain in place. Hard per-analyzer deadlines,
deep-tool descendants and supervisor-crash guarantees remain separate W2 work.

The release workflow runs this gate **after extracting each native archive**, before
artifact upload/draft release. CI also runs it on the no-AI executable on all three
platforms. CI uploads JSON results; a gate failure fails its job. Local runs qualify
Windows here; hosted results must be read before making further platform claims.

## Reproduction

Obtain the published inputs above, verify the hashes in the record, and supply an
already installed directory without running its programs. Keep output outside the input.
The checker performs no downloads:

```powershell
python tools/release/review-reports.py path/to/analyze-anything.exe --installer path/to/7z2408-x64.msi --installed path/to/7-Zip --mobile path/to/iSH.ipa --bundle path/to/WinSW-x64.exe --output out/report-review
python tools/release/check-workflow.py path/to/extracted/analyze-anything.exe --record out/packaged-workflow.json
pwsh -NoProfile -File tools/release/review-msi.ps1 -Sample path/to/7z2408-x64.msi -Report out/report-review/installer/report.json -Record out/msi-native.json
```

The five-scenario checker requires pinned public file hashes, checks repeated JSON,
renders English/Chinese HTML and Markdown, verifies evidence/confidence and artifact
references, digests and byte-range bounds for every finding, exercises query/explain, compares the installed directory's
digests and leaves source/report bytes unchanged. Semantic gap codes are required where
the review found unsupported behavior. It is a regression gate for these cases, not a
coverage percentage or a guarantee about all inputs.

Local source validation passed `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and
`cargo build --locked -p aa-cli --no-default-features`. The rendering suite includes
English/Chinese PDF regressions; this review regenerated HTML/Markdown rather than
repeating a platform's native window qualification. Source reading corrections and
worker ownership still have their separate Rust regressions.

The English and Simplified Chinese README/install/reading guidance now agree on the
published packages and raw-byte history boundary. The other README translations retain
their explicit English-may-be-newer notices; their delivery prose has not been requalified.
