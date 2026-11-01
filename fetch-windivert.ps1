# Download WinDivert 2.2.2 into vendor\ and check it against the hash recorded
# when NetLeash was set up. Defender flags WinDivert as "potentially unwanted",
# so add an exclusion first (in an Administrator PowerShell):
#   Add-MpPreference -ExclusionPath "<this folder>\vendor\WinDivert-2.2.2-A"

$ErrorActionPreference = 'Stop'
$url = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$sha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'
$vendor = Join-Path $PSScriptRoot 'vendor'
$dest = Join-Path $vendor 'WinDivert-2.2.2-A'

New-Item -ItemType Directory -Force $dest | Out-Null
$zip = Join-Path $dest 'download.zip'
Invoke-WebRequest $url -OutFile $zip
$got = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($got -ne $sha256) {
    Remove-Item $zip
    throw "SHA-256 mismatch: expected $sha256, got $got"
}
Expand-Archive $zip -DestinationPath $vendor -Force
Remove-Item $zip

$sig = Get-AuthenticodeSignature (Join-Path $dest 'x64\WinDivert64.sys')
"Driver signature: $($sig.Status) ($($sig.SignerCertificate.Subject))"
