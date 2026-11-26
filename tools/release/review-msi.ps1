# Read table declarations through Windows Installer; never install or extract the input.
param([Parameter(Mandatory)][string]$Sample, [Parameter(Mandatory)][string]$Report, [Parameter(Mandatory)][string]$Record)
$ErrorActionPreference = 'Stop'
$samplePath = (Resolve-Path -LiteralPath $Sample).Path
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($samplePath, 0)
function Read-Rows([string]$Sql, [int]$Columns) {
    $view = $database.OpenView($Sql)
    try {
        [void]$view.Execute()
        while ($null -ne ($row = $view.Fetch())) {
            try {
                $values = @()
                for ($index = 1; $index -le $Columns; $index++) { $values += $row.StringData($index) }
                ,$values
            } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($row) }
        }
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view)
    }
}
try {
    $properties = [ordered]@{}
    foreach ($row in (Read-Rows 'SELECT `Property`, `Value` FROM `Property`' 2)) { $properties[$row[0]] = $row[1] }
    $files = @(Read-Rows 'SELECT `File`, `FileName`, `FileSize` FROM `File`' 3)
    $registry = @(Read-Rows 'SELECT `Registry` FROM `Registry`' 1)
    $shortcuts = @(Read-Rows 'SELECT `Shortcut` FROM `Shortcut`' 1)
    $saved = Get-Content -Raw -LiteralPath $Report | ConvertFrom-Json
    $model = $saved.artifacts[0].facts.'windows.installer'
    $sha = (Get-FileHash -LiteralPath $samplePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($saved.input.sha256 -ne $sha) { throw 'MSI report belongs to different bytes' }
    foreach ($pair in @(@('product', 'ProductName'), @('version', 'ProductVersion'), @('publisher', 'Manufacturer'))) {
        if ($model.($pair[0]) -ne $properties[$pair[1]]) { throw "MSI identity mismatch: $($pair[0])" }
    }
    if ($model.files -ne $files.Count -or $model.registry_writes.Count -ne $registry.Count -or $model.shortcuts.Count -ne $shortcuts.Count) {
        throw 'MSI table count mismatch'
    }
    $bytes = ($files | ForEach-Object { [long]$_[2] } | Measure-Object -Sum).Sum
    if ($model.files_bytes -ne $bytes) { throw 'MSI declared payload size mismatch' }
    [ordered]@{sample = [IO.Path]::GetFileName($samplePath); sha256 = $sha; reader = 'WindowsInstaller.Installer OpenDatabase mode 0';
        product = $properties['ProductName']; version = $properties['ProductVersion']; publisher = $properties['Manufacturer'];
        files = $files.Count; file_bytes = $bytes; registry = $registry.Count; shortcuts = $shortcuts.Count;
        checks = 8; execution = 'none'; installation = 'none'} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Record -Encoding utf8
    Write-Output 'PASS: 8 read-only native MSI identity and table checks'
} finally {
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
}
