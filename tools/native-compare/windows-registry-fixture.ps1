param([Parameter(Mandatory = $true)][string]$Destination)

# Export only this fixed system metadata key. Never import a supplied REG file or change a key.
$ErrorActionPreference = 'Stop'
$fixtureDirectory = (New-Item -ItemType Directory -Force -Path $Destination).FullName
$fixtureKeyPath = 'SYSTEM\CurrentControlSet\Control\Nls\CodePage'
$fixtureFile = Join-Path $fixtureDirectory 'native-codepages.reg'
& reg.exe export ('HKLM\' + $fixtureKeyPath) $fixtureFile /y | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Native registry export failed' }
$fixturePending = [System.Collections.Generic.Queue[string]]::new()
$fixturePending.Enqueue($fixtureKeyPath)
$fixtureKeys = [System.Collections.Generic.List[object]]::new()
while ($fixturePending.Count -gt 0) {
    if ($fixtureKeys.Count -ge 64) { throw 'Unexpectedly large code-page metadata subtree' }
    $fixturePath = $fixturePending.Dequeue()
    $fixtureKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($fixturePath, $false)
    if ($null -eq $fixtureKey) { throw 'Native reference key is absent' }
    try {
        $fixtureValues = @($fixtureKey.GetValueNames() | Sort-Object | ForEach-Object {
            [ordered]@{
                name = $_
                kind = $fixtureKey.GetValueKind($_).ToString()
                value = $fixtureKey.GetValue($_, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        })
        $fixtureKeys.Add([ordered]@{ key = ('HKEY_LOCAL_MACHINE\' + $fixturePath); values = $fixtureValues })
        foreach ($fixtureChild in ($fixtureKey.GetSubKeyNames() | Sort-Object)) { $fixturePending.Enqueue($fixturePath + '\' + $fixtureChild) }
    } finally { $fixtureKey.Dispose() }
}
$fixtureReference = [ordered]@{ producer = 'Windows reg.exe export and Microsoft.Win32.Registry read-only'; keys = $fixtureKeys.ToArray() }
[System.IO.File]::WriteAllText((Join-Path $fixtureDirectory 'native-codepages.reg.ref.json'), (($fixtureReference | ConvertTo-Json -Depth 8) + "`n"), [System.Text.UTF8Encoding]::new($false))
