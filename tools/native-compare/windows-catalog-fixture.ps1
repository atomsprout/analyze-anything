# Creates controlled catalog fixtures. No certificate is added to a system store.
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [switch]$MemberAttributes
)
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$destination = [IO.Path]::GetFullPath($OutputDirectory)
if (-not $destination.StartsWith((Join-Path $repository 'out') + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Fixture generation requires a directory below the repository out folder.'
}
[IO.Directory]::CreateDirectory($destination) | Out-Null
$sdk = Get-ChildItem -Path 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\makecat.exe' |
    Sort-Object { [version]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
if (-not $sdk) { throw 'x64 SDK MakeCat was not found.' }
$signTool = Join-Path $sdk.Directory.FullName 'signtool.exe'
if (-not (Test-Path -LiteralPath $signTool)) { throw 'SignTool was not found beside MakeCat.' }
$payload = Join-Path $destination 'catalog-payload.txt'
[IO.File]::WriteAllBytes($payload, [Text.Encoding]::ASCII.GetBytes("Analyze Anything catalog fixture.`r`n"))
[IO.File]::Copy((Join-Path $repository 'crates/aa-windows/tests/data/hello.exe'), (Join-Path $destination 'hello.exe'), $true)
$privatePath = Join-Path $destination 'ephemeral-fixture-key.pfx'
if (Test-Path -LiteralPath $privatePath) { throw 'A private fixture key already exists; choose a fresh output directory.' }
$key = [Security.Cryptography.RSA]::Create(2048)
$certificate = $null
try {
    $request = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=Analyze Anything Catalog Fixture', $key, [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $usages = [Security.Cryptography.OidCollection]::new()
    $usages.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($usages, $true))
    $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature, $true))
    $certificate = $request.CreateSelfSigned([DateTimeOffset]::new(2025,1,1,0,0,0,[TimeSpan]::Zero), [DateTimeOffset]::new(2045,1,1,0,0,0,[TimeSpan]::Zero))
    # This is an ephemeral, project-generated test key, never a user credential.
    [IO.File]::WriteAllBytes($privatePath, $certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'fixture-only'))
    Push-Location -LiteralPath $destination
    try {
        foreach ($version in @(1, 2)) {
            $hash = if ($version -eq 1) { 'SHA1' } else { 'SHA256' }
            $variant = if ($MemberAttributes) { '-named' } else { '' }
            $name = "native-catalog$variant-v$version"
            $cdf = "[CatalogHeader]`r`nName=$name.cat`r`nCatalogVersion=$version`r`nHashAlgorithms=$hash`r`nPageHashes=false`r`n[CatalogFiles]`r`n"
            foreach ($member in @('catalog-payload.txt', 'hello.exe')) {
                $cdf += "<HASH>$member=$member`r`n"
                if ($MemberAttributes) {
                    $cdf += "<HASH>${member}ATTR1=0x10010001:File:$member`r`n<HASH>${member}ATTR2=0x10010001:OSAttr:2:10.0`r`n"
                }
            }
            [IO.File]::WriteAllText((Join-Path $destination "$name.cdf"), $cdf, [Text.Encoding]::ASCII)
            & $sdk.FullName -r "$name.cdf"
            if ($LASTEXITCODE -ne 0) { throw "MakeCat failed for $name." }
            [IO.File]::Copy((Join-Path $destination "$name.cat"), (Join-Path $destination "$name-unsigned.cat"), $true)
            & $signTool sign /fd SHA256 /f $privatePath /p fixture-only "$name.cat"
            if ($LASTEXITCODE -ne 0) { throw "SignTool failed for $name." }
        }
    } finally { Pop-Location }
} finally {
    if ($certificate) { $certificate.Dispose() }
    $key.Dispose()
    if (Test-Path -LiteralPath $privatePath) { Remove-Item -LiteralPath $privatePath }
}
Write-Output "Generated catalogs with SDK $($sdk.Directory.Parent.Name); no key or certificate store entry retained."
