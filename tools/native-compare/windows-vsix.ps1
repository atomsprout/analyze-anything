param(
    [Parameter(Mandatory)] [string] $Package
)

$ErrorActionPreference = 'Stop'
$archive = [IO.Compression.ZipFile]::OpenRead((Resolve-Path -LiteralPath $Package).Path)
try {
    $manifest = $archive.GetEntry('extension.vsixmanifest')
    $stream = $manifest.Open()
    try {
        $settings = [Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [Xml.XmlReader]::Create($stream, $settings)
        try {
            $xml = [Xml.XmlDocument]::new()
            $xml.XmlResolver = $null
            $xml.Load($reader)
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
    $stream = $manifest.Open()
    try {
        $manifestHash = (Get-FileHash -InputStream $stream).Hash.ToLowerInvariant()
    } finally {
        $stream.Dispose()
    }
    $names = [Xml.XmlNamespaceManager]::new($xml.NameTable)
    $names.AddNamespace('vsix', 'http://schemas.microsoft.com/developer/vsx-schema/2011')
    $identity = $xml.SelectSingleNode('/vsix:PackageManifest/vsix:Metadata/vsix:Identity', $names)
    $title = $xml.SelectSingleNode('/vsix:PackageManifest/vsix:Metadata/vsix:DisplayName', $names)
    $license = $xml.SelectSingleNode('/vsix:PackageManifest/vsix:Metadata/vsix:License', $names)
    [ordered] @{
        package_sha256 = (Get-FileHash -LiteralPath $Package).Hash.ToLowerInvariant()
        source_sha256 = $manifestHash
        id = $identity.GetAttribute('Id')
        version = $identity.GetAttribute('Version')
        publisher = $identity.GetAttribute('Publisher')
        name = $title.InnerText
        license_path = $license.InnerText
        targets = @($xml.SelectNodes('/vsix:PackageManifest/vsix:Installation/vsix:InstallationTarget', $names) | ForEach-Object {
            [ordered] @{
                id = $_.GetAttribute('Id')
                range = $_.GetAttribute('Version')
                architecture = $_.SelectSingleNode('vsix:ProductArchitecture', $names).InnerText
            }
        })
        prerequisites = @($xml.SelectNodes('/vsix:PackageManifest/vsix:Prerequisites/vsix:Prerequisite', $names) | ForEach-Object {
            [ordered] @{
                id = $_.GetAttribute('Id')
                range = $_.GetAttribute('Version')
                display_name = $_.GetAttribute('DisplayName')
            }
        })
        assets = @($xml.SelectNodes('/vsix:PackageManifest/vsix:Assets/vsix:Asset', $names) | ForEach-Object {
            $entry = $archive.GetEntry($_.GetAttribute('Path').Replace('\', '/'))
            $stream = $entry.Open()
            try {
                [ordered] @{
                    type = $_.GetAttribute('Type')
                    path = $_.GetAttribute('Path')
                    sha256 = (Get-FileHash -InputStream $stream).Hash.ToLowerInvariant()
                }
            } finally {
                $stream.Dispose()
            }
        })
    } | ConvertTo-Json -Depth 6
} finally {
    $archive.Dispose()
}
