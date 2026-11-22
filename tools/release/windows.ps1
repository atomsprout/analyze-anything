# Builds the Windows x64 desktop ZIP and offline NSIS installer locally.
# Run from PowerShell 7 with the repository toolchain installed.
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true

$repository = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
$desktop = Join-Path $repository 'apps/desktop'
if ((rustc -vV | Select-String '^host: x86_64-pc-windows-msvc$').Count -ne 1) {
    throw 'The Windows x64 MSVC Rust toolchain must be the host toolchain.'
}

Push-Location $desktop
try {
    $metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
    $version = ($metadata.packages | Where-Object name -eq 'aa-desktop').version
    if ($version -notmatch '^\d+\.\d+\.\d+[-+.\w]*$') {
        throw 'Could not determine the desktop version.'
    }
    npm ci --no-audit --no-fund
    npm run tauri build -- --bundles nsis
} finally {
    Pop-Location
}

$build = Join-Path $metadata.target_directory 'release'
$program = Join-Path $build 'analyze-anything-desktop.exe'
$installer = Join-Path $build "bundle/nsis/Analyze Anything_${version}_x64-setup.exe"
foreach ($required in $program, $installer) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Build output is missing: $required"
    }
}

$output = Join-Path $repository "dist/release/windows-$version"
$null = New-Item -ItemType Directory -Force $output
$portable = "analyze-anything-desktop-$version-windows-x64-portable"
$stage = Join-Path $output $portable
$null = New-Item -ItemType Directory -Force $stage
Copy-Item -LiteralPath $program, (Join-Path $repository 'LICENSE'), (Join-Path $repository 'NOTICE') -Destination $stage
@'
Extract the ZIP and run analyze-anything-desktop.exe.
The portable build requires the Microsoft Edge WebView2 Runtime.
The accompanying offline NSIS installer can install the runtime.
'@ | Set-Content -LiteralPath (Join-Path $stage 'README.txt') -Encoding utf8

$zip = Join-Path $output "$portable.zip"
Compress-Archive -LiteralPath $stage -DestinationPath $zip -Force
$setup = Join-Path $output "analyze-anything-desktop-$version-windows-x64-offline-setup.exe"
Copy-Item -LiteralPath $installer -Destination $setup -Force
Get-FileHash -LiteralPath $zip, $setup | ForEach-Object {
    "$($_.Hash.ToLowerInvariant())  $(Split-Path -Leaf $_.Path)"
} | Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS') -Encoding ascii
$output
