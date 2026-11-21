param(
    [Parameter(Mandatory)] [string] $Package,
    [Parameter(Mandatory)] [string] $SdkDirectory
)

$ErrorActionPreference = 'Stop'
foreach ($name in 'Common', 'Configuration', 'Frameworks', 'Versioning', 'Packaging') {
    Add-Type -Path (Join-Path $SdkDirectory "NuGet.$name.dll")
}

$stream = [IO.File]::OpenRead((Resolve-Path -LiteralPath $Package).Path)
try {
    $archive = [NuGet.Packaging.PackageArchiveReader]::new($stream)
    try {
        $manifest = $archive.NuspecReader
        $license = $manifest.GetLicenseMetadata()
        $files = [Collections.Generic.List[string]]::new()
        $files.AddRange([string[]] $archive.GetFiles())
        $files.Sort([StringComparer]::Ordinal)
        $groups = @($manifest.GetDependencyGroups())
        [ordered] @{
            sdk = Split-Path -Leaf $SdkDirectory
            package_sha256 = (Get-FileHash -LiteralPath $Package).Hash.ToLowerInvariant()
            manifest = $archive.GetNuspecFile()
            name = $manifest.GetId()
            version = $manifest.GetVersion().ToFullString()
            license_kind = $license.Type.ToString().ToLowerInvariant()
            license_value = $license.License
            dependency_frameworks = @($groups | ForEach-Object { $_.TargetFramework.GetShortFolderName() })
            dependency_counts = @($groups | ForEach-Object { @($_.Packages).Count })
            dependencies = @(for ($index = 0; $index -lt $groups.Count; $index++) {
                foreach ($dependency in $groups[$index].Packages) {
                    [ordered] @{
                        group = $index
                        id = $dependency.Id
                        range = $dependency.VersionRange.OriginalString
                        exclude = @($dependency.Exclude)
                    }
                }
            })
            assets = @($files | Where-Object { $_ -match '^(lib|ref|runtimes|build|buildtransitive|buildmultitargeting|tools|analyzers|contentfiles)/' })
            exact_normalized = [NuGet.Versioning.VersionRange]::Parse('[1.0]').Satisfies([NuGet.Versioning.NuGetVersion]::Parse('1.0.0.0'))
            minimum_accepts_later = [NuGet.Versioning.VersionRange]::Parse('1.0').Satisfies([NuGet.Versioning.NuGetVersion]::Parse('2.0'))
        } | ConvertTo-Json -Depth 6
    } finally {
        $archive.Dispose()
    }
} finally {
    $stream.Dispose()
}
