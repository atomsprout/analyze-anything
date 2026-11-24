# Build independent SDK-produced samples; never run the resulting executables.
param([Parameter(Mandatory)][string]$Output)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$outputRoot = [IO.Path]::GetFullPath($Output)
$project = Join-Path $root 'tools/fixtures/executable-bundles/BundleFixture.csproj'
dotnet publish $project --artifacts-path (Join-Path $outputRoot 'artifacts') -r win-x64 --self-contained false -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=false -c Release -o (Join-Path $outputRoot 'uncompressed')
dotnet publish $project --artifacts-path (Join-Path $outputRoot 'artifacts') -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -c Release -o (Join-Path $outputRoot 'compressed')
