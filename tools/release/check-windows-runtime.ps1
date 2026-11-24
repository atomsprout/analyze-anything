# Inspect regular and delay-load dependencies of the packaged CLI without executing it.
param([Parameter(Mandatory)][string]$Program)
$ErrorActionPreference = 'Stop'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (!(Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio tool discovery is required for runtime qualification.' }
$dumpbin = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC/Tools/MSVC/**/bin/Hostx64/x64/dumpbin.exe' | Select-Object -First 1
if (!$dumpbin) { throw 'Could not locate the x64 dependency inspection tool.' }
$dependencies = & $dumpbin /nologo /dependents $Program
if ($LASTEXITCODE -ne 0) { throw 'Could not inspect packaged CLI dependencies.' }
$names = [regex]::Matches(($dependencies -join "`n"), '(?im)^\s+([a-z0-9_.-]+\.dll)\s*$') |
    ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique
if (!$names) { throw 'Dependency inspection returned no DLL names.' }
$externalRuntime = $names | Where-Object { $_ -match '^(vcruntime|msvcp|ucrtbase|api-ms-win-crt)' }
if ($externalRuntime) { throw "Packaged CLI depends on a separate CRT: $($externalRuntime -join ', ')" }
$names
