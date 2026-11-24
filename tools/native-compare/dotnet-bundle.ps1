# Read-only reference using the SDK runtime's BinaryReader and DeflateStream.
param([Parameter(Mandatory)][string]$Sample, [Parameter(Mandatory)][string]$Record)
$ErrorActionPreference = 'Stop'

function Read-Text([IO.BinaryReader]$Reader) {
    $count = $Reader.Read7BitEncodedInt()
    if ($count -lt 0 -or $count -gt 4096) { throw 'String outside reference profile' }
    $raw = $Reader.ReadBytes($count)
    if ($raw.Length -ne $count) { throw 'Truncated string' }
    [Text.UTF8Encoding]::new($false, $true).GetString($raw)
}

function Read-Digest([IO.Stream]$Stream, [long]$Expected, [bool]$Probe) {
    $digest = [Security.Cryptography.IncrementalHash]::CreateHash([Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $buffer = [byte[]]::new(65536)
        $left = $Expected
        while ($left -gt 0) {
            $read = $Stream.Read($buffer, 0, [int][Math]::Min($left, $buffer.Length))
            if ($read -eq 0) { throw 'Truncated member' }
            $digest.AppendData($buffer, 0, $read)
            $left -= $read
        }
        if ($Probe -and $Stream.ReadByte() -ne -1) { throw 'Member exceeds declared size' }
        [Convert]::ToHexString($digest.GetHashAndReset()).ToLowerInvariant()
    } finally { $digest.Dispose() }
}

$file = [IO.File]::OpenRead($Sample)
try {
    if ($file.Length -gt 256MB) { throw 'Sample exceeds reference input limit' }
    $reader = [IO.BinaryReader]::new($file, [Text.Encoding]::UTF8, $true)
    $raw = $reader.ReadBytes([int]$file.Length)
    $signature = [Convert]::FromHexString('8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae')
    $markers = @()
    for ($at = 8; $at -le [Math]::Min($raw.Length, 16MB) - 32; $at++) {
        if ($raw[$at] -ne $signature[0]) { continue }
        $same = $true
        for ($index = 1; $index -lt 32; $index++) { if ($raw[$at + $index] -ne $signature[$index]) { $same = $false; break } }
        if ($same) {
            $pointer = [BitConverter]::ToInt64($raw, $at - 8)
            if ($pointer -ge $at + 32 -and $pointer -lt $raw.Length) { $markers += $pointer }
        }
    }
    if ($markers.Count -ne 1) { throw 'Reference requires one bundle header' }
    $header = $markers[0]
    $file.Position = $header
    $major = $reader.ReadUInt32()
    $minor = $reader.ReadUInt32()
    if ($major -notin 1,2,6 -or $minor -ne 0) { throw 'Unsupported reference bundle version' }
    $count = $reader.ReadInt32()
    if ($count -lt 0 -or $count -gt 10000) { throw 'Entry count outside reference profile' }
    $bundleId = Read-Text $reader
    if ($major -ge 2) { $file.Position += 40 }
    $entries = @()
    for ($index = 0; $index -lt $count; $index++) {
        $metadata = $file.Position
        $offset = $reader.ReadInt64()
        $size = $reader.ReadInt64()
        $compressed = if ($major -ge 6) { $reader.ReadInt64() } else { 0L }
        $kind = $reader.ReadByte()
        $name = Read-Text $reader
        $next = $file.Position
        $stored = if ($compressed -gt 0) { $compressed } else { $size }
        if ($offset -lt 0 -or $size -lt 0 -or $size -gt 512MB -or $stored -lt 0 -or $stored -gt $header -or $offset -gt $header - $stored) {
            throw 'Member outside reference range/size profile'
        }
        $file.Position = $offset
        if ($compressed -gt 0) {
            $data = $reader.ReadBytes([int]$compressed)
            $memory = [IO.MemoryStream]::new($data, $false)
            $inflate = [IO.Compression.DeflateStream]::new($memory, [IO.Compression.CompressionMode]::Decompress)
            try { $sha = Read-Digest $inflate $size $true } finally { $inflate.Dispose(); $memory.Dispose() }
        } else { $sha = Read-Digest $file $size $false }
        $entries += @{path=$name; offset=$offset; size=$size; compressed_size=$compressed; type=$kind; manifest_offset=$metadata; sha256=$sha}
        $file.Position = $next
    }
    @{version=$major; minor=$minor; header_offset=$header; bundle_id=$bundleId; files=$entries; runtime=[Environment]::Version.ToString(); powershell=$PSVersionTable.PSVersion.ToString()} |
        ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Record -Encoding utf8
} finally { $file.Dispose() }
