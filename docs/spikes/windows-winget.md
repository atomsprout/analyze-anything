# WinGet manifests and supplied installer bytes

The analyzer reads [WinGet 1.x manifest declarations](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest)
from a bounded YAML document. It retains literal package identity and version,
locale and publisher metadata, architectures, installer types, URLs, SHA-256
digests, switches and dependencies. The report records source files and line
numbers. Duplicate mapping keys, anchors, aliases, complex keys and multiple
documents are outside the supported YAML profile.

A multi-file set requires unique version, installer and default locale
manifests with identical package identifiers, versions and manifest schema
versions in the same supplied directory. It checks the declared default locale.
Other matching locale files contribute their source evidence. A singleton can
also contribute an identity to the shared component inventory and CycloneDX.

An installer row links to a unique supplied file with the declared SHA-256
in the same directory and container. A missing or ambiguous match has a
recorded status. The reader preserves default and installer-specific
dependency declarations and can link a unique supplied package candidate in
the same input or container if its version literally equals the declared
minimum, or if no minimum was declared. Installer-specific declarations keep
their source row. The analyzer leaves WinGet version ordering, installer
selection, built-in switches, catalog queries, download and execution outside
the analysis.

## Windows reference comparison

WinGet 1.29.380 accepted the four manifests for 7zip.7zip 24.09 using its
[validate command](https://learn.microsoft.com/en-us/windows/package-manager/winget/validate):

```powershell
winget validate --manifest crates/aa-windows/tests/data/winget-7zip-24.09 --disable-interactivity
```

The fixture bytes come from `manifests/7/7zip/7zip/24.09` in
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs).

| Manifest suffix | Git blob |
|---|---|
| `.yaml` | `b2a9e4b8e6ce0975a7a39f3e54fbe589c5b3c847` |
| `.installer.yaml` | `82ed6d4d08a12098e9c61ca5f3365050955e353a` |
| `.locale.en-US.yaml` | `2b65637d61fe85bd29173d962ef0866e36583b78` |
| `.locale.zh-CN.yaml` | `e5bb5177d49c7ae4fc67acf7c82501bffd5723a1` |

The no-AI CLI joined all four manifests and reported six installer rows. In a
separate input directory containing those manifests and the two [publisher
release files](https://github.com/ip7z/7zip/releases/tag/24.09), the two x64
SHA-256 associations matched independently computed digests. The remaining
four rows recorded that no supplied file matched. The Chinese Markdown
report and CycloneDX export preserved the package identity. Constructed inputs
cover switch overrides, duplicate payloads, unsupported YAML and unresolved
dependency versions.
