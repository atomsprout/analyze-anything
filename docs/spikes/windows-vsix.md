# VSIX package declarations and captured members

The analyzer reads bounded [VSIX 2.0 deployment manifests](https://learn.microsoft.com/en-us/visualstudio/extensibility/vsix-extension-schema-2-0-reference)
with the 2011 namespace and a unique metadata identity. It retains the extension
ID, version, publisher, display name, license path, installation targets,
architectures, prerequisites, dependencies and declared assets. Evidence keeps
the captured manifest digest and decoded UTF-8 offsets.

A package requires a complete captured ZIP listing and a unique root
`extension.vsixmanifest`. Asset and license paths can link to unique captured
members of that package. A dependency with a package-relative location can link
to a nested VSIX when its declared ID and exact version match the nested manifest.
Reports retain missing, external, conflicting and unsupported targets and ranges.
CycloneDX includes the declared publisher and qualified exact dependencies.

The comparison profile accepts ordinary relative member names and numeric exact
dependency versions with the same number of components. It leaves broader
ranges, external locations, folder or URI-encoded paths and ambiguous manifests
unresolved. VSIX 1.0, full schema validation, product compatibility, extension
signatures and host installation state are outside this profile.

## Windows comparison

The published [Markdown Editor v2 2.0.464](https://github.com/madskristensen/MarkdownEditor2022/releases/tag/2.0.464)
VSIX has SHA-256 `ccfa1464c695a63b5252eee84806df2bd2df47cd642317ffa6112bdb877fe38c`.
The reference script opened the ZIP with .NET on Windows x64 in PowerShell
7.6.9, selected elements with namespace-qualified XML queries and independently
hashed the declared member streams.

```powershell
./tools/native-compare/windows-vsix.ps1 -Package MarkdownEditor2022.vsix
```

The CLI agreed on the package identity, publisher, two installation targets
(`amd64` and `arm64`), one Visual Studio prerequisite, three declared assets and
all three member digests. The package license file was found at its declared
location. The Chinese Markdown report included the identity and CycloneDX
retained the publisher. The repository carries the real deployment manifest
and licence, with the source and licence recorded in NOTICE. Constructed
packages test the supported exact dependency, mismatched identity and version,
unresolved ranges, remote and out-of-scope locations, and duplicate declarations.
