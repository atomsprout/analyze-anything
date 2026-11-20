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
