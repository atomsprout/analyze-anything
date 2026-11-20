param([Parameter(Mandatory = $true)][string]$Destination)

# Produce only this project's test URL; never load, resolve or activate a supplied shortcut.
$ErrorActionPreference = 'Stop'
$fixtureDirectory = (New-Item -ItemType Directory -Force -Path $Destination).FullName
$fixturePath = Join-Path $fixtureDirectory 'native.url'
$fixtureShell = New-Object -ComObject WScript.Shell
$fixtureShortcut = $fixtureShell.CreateShortcut($fixturePath)
$fixtureShortcut.TargetPath = 'https://example.invalid/windows-shortcut-reference'
$fixtureShortcut.Save()
$fixtureReference = [ordered]@{ producer = 'Windows WScript.Shell'; target = $fixtureShortcut.TargetPath }
$fixtureJson = ($fixtureReference | ConvertTo-Json) + "`n"
[System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'native.url.ref.json'), $fixtureJson, [System.Text.UTF8Encoding]::new($false))

# Only a known system file is referenced; no supplied LNK is opened by COM.
$fixtureLink = $fixtureShell.CreateShortcut((Join-Path $fixtureDirectory 'native.lnk'))
$fixtureTarget = Join-Path $env:SystemRoot 'System32\cmd.exe'
if (-not (Test-Path -LiteralPath $fixtureTarget -PathType Leaf)) { throw 'Native fixture target is absent' }
$fixtureLink.TargetPath = $fixtureTarget
$fixtureLink.Arguments = '--fixture "two words"'
$fixtureLink.WorkingDirectory = 'C:\aa-fixture-missing'
$fixtureLink.Description = 'Analyze Anything shortcut fixture'
$fixtureLink.IconLocation = 'C:\aa-fixture-missing\icon.ico,3'
$fixtureLink.WindowStyle = 7
$fixtureLink.Save()
$fixtureLinkReference = [ordered]@{
    producer = 'Windows WScript.Shell'
    target = $fixtureLink.TargetPath
    arguments = $fixtureLink.Arguments
    working_directory = $fixtureLink.WorkingDirectory
    description = $fixtureLink.Description
    icon = $fixtureLink.IconLocation
    show_command = $fixtureLink.WindowStyle
}
[System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'native.lnk.ref.json'), (($fixtureLinkReference | ConvertTo-Json) + "`n"), [System.Text.UTF8Encoding]::new($false))
