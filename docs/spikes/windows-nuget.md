# NuGet package declarations and supplied payloads

The Windows analyzer reads bounded nuspec XML and retains the package ID,
literal version, license declaration and dependency groups with decoded UTF-8
offsets. A package occurrence requires one qualified root manifest, its captured
digest and a complete ZIP listing. The package fact inventories captured library,
reference, runtime, build, tool, analyzer and content assets by path and digest.
The component inventory prefers captured package metadata over loose declarations
of the same identity and keeps assembly data in the captured file facts.

Dependency relationships use the ID and version declared inside each candidate
package. Matching is limited to exact stable numeric ranges such as `[1.0]`.
The directory and containing archive must match, and the supplied listing
must be complete. The report names present, missing, ambiguous and incomplete
cases. Framework-specific groups are retained with their declared framework.
CycloneDX emits an edge when a flat declaration links two listed components.
Licenses appear as declared-expression or file-reference properties.

The reader leaves interval, floating and prerelease ranges unresolved.
It does not choose a framework, load assemblies, run build scripts, verify
NuGet signatures, restore packages or inspect dependencies outside the input.

## Reference comparison

On Windows x64, PowerShell 7.6.9 loaded the NuGet libraries from the installed
.NET SDK 10.0.401. The reference script opens the published package read-only
and records the result of `PackageArchiveReader` and `NuspecReader`.

```powershell
./tools/native-compare/windows-nuget.ps1 -Package crates/aa-windows/tests/data/nuget.versioning.6.11.1.nupkg -SdkDirectory 'C:/Program Files/dotnet/sdk/10.0.401'
```

The package is NuGet.Versioning 6.11.1, SHA-256
`7e5f25c8284c8d5ed2a7c91e00fec2757661ec044dfe6537f53de01bbe230d66`.
The engine test checks the manifest path, identity, license, two empty framework
groups and the two library asset paths. The SDK normalizes the framework names
to `net472` and `netstandard2.0`. The analysis report preserves their XML spelling.
The SDK also confirms that `[1.0]` accepts `1.0.0.0`, while a bare `1.0` accepts
later versions. Constructed analyzer inputs cover an exact match with a different
archive filename, a framework-group candidate, a bare range, a missing dependency,
an ambiguous duplicate and a directory with an unread package.

A second comparison used the published [NuGet.Configuration 6.11.1 package](
https://api.nuget.org/v3-flatcontainer/nuget.configuration/6.11.1/nuget.configuration.6.11.1.nupkg),
SHA-256 `247d940a98d883ca64ab14388f806b5a24ca846ce07e7e7934caf7db07faf854`.
The CLI and the SDK agreed on both asset paths, identity, license and three
nonempty dependency declarations, including the excluded asset names.
The generated Chinese report included the package identity finding, and the
CycloneDX export included the package identity and left those three minimum
version ranges unresolved.
