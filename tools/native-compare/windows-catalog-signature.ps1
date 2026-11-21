# A development reference: verify embedded CMS signers without checking Windows trust.
param([Parameter(Mandatory=$true)][string]$CatalogFile)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$path = (Resolve-Path -LiteralPath $CatalogFile).Path
$bytes = [IO.File]::ReadAllBytes($path)
if ($bytes.Length -gt 16MB) { throw 'Catalog exceeds the reference byte budget.' }
$cms = [Security.Cryptography.Pkcs.SignedCms]::new()
$cms.Decode($bytes)
if ($cms.SignerInfos.Count -gt 16) { throw 'Catalog exceeds the reference signer budget.' }
$checks = @()
foreach ($signer in $cms.SignerInfos) {
    if (-not $signer.Certificate) {
        $checks += @{ combined_content_and_signature = 'not-checked'; reason = 'no embedded signer certificate' }
        continue
    }
    $status = 'passed'
    try { $signer.CheckSignature($true) } catch { $status = 'failed' }
    $checks += @{
        combined_content_and_signature = $status
        signer_sha256 = $signer.Certificate.GetCertHashString([Security.Cryptography.HashAlgorithmName]::SHA256).ToLowerInvariant()
    }
}
@{ content_type = $cms.ContentInfo.ContentType.Value; signatures = $checks } | ConvertTo-Json -Depth 5 -Compress
