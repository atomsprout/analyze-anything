param(
    [string]$Fixture = (Join-Path $PSScriptRoot '../../crates/aa-windows/tests/data/powershell-ast.ref.json'),
    [string]$Cli
)

$ErrorActionPreference = 'Stop'
$cases = Get-Content -Raw -LiteralPath $Fixture -Encoding utf8 | ConvertFrom-Json
foreach ($case in $cases) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($case.source, [ref]$tokens, [ref]$errors)
    $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
    if ($commands.Count -ne $case.commands.Count -or $errors.Count -ne $case.errors.Count) {
        throw "Parser shape changed for $($case.case)"
    }
    for ($i = 0; $i -lt $commands.Count; $i++) {
        $actual = $commands[$i]
        $expected = $case.commands[$i]
        if ($actual.GetCommandName() -cne $expected.name -or $actual.InvocationOperator.ToString() -cne $expected.operator -or
                $actual.Extent.StartLineNumber -ne $expected.line -or $actual.Extent.StartColumnNumber -ne $expected.column) {
            throw "Command projection changed for $($case.case) at index $i"
        }
    }
    $elevation = $null -ne $ast.ScriptRequirements -and $ast.ScriptRequirements.IsElevationRequired
    if ($elevation -ne $case.requires_administrator) {
        throw "Administrator requirement changed for $($case.case)"
    }
}
"Matched $($cases.Count) owned PowerShell syntax references using ParseInput."

if ($Cli) {
    $Cli = (Resolve-Path -LiteralPath $Cli).Path
    $repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '../..')).Path
    $referenceOutput = Join-Path $repo 'out/windows-baseline/w4-real-powershell'
    foreach ($name in @('windows-registry-fixture', 'windows-task-fixture', 'windows-shortcut-fixture')) {
        $source = Join-Path $PSScriptRoot "$name.ps1"
        $destination = Join-Path $referenceOutput $name
        $sourceHash = (Get-FileHash -LiteralPath $source).Hash
        & $Cli $source -o $destination --format json | Out-Null
        if ($LASTEXITCODE -notin @(0, 2)) {
            throw "Analyzer failed for $name"
        }
        $report = Get-Content -Raw -LiteralPath (Join-Path $destination 'report.json') -Encoding utf8 | ConvertFrom-Json
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
        $native = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
                ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $observed = @($report.artifacts[0].facts.'windows.powershell'.commands.name)
        if ($errors.Count -ne 0 -or ($native -join "`n") -cne ($observed -join "`n") -or
                (Get-FileHash -LiteralPath $source).Hash -ne $sourceHash) {
            throw "Analyzer literal command projection or input digest changed for $name"
        }
        "Matched $($observed.Count) literal command declarations in $name."
    }
}
