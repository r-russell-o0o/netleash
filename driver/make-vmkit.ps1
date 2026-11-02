# Put together driver\out\vmkit: the test-signed driver, its certificate,
# NetLeash itself and the two test scripts. Copy that folder into a test VM.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
& (Join-Path $here 'build.ps1') -Sign
if ($LASTEXITCODE) { throw 'driver build failed' }

$root = Split-Path $here
Push-Location $root
try {
    cargo build --release --target-dir target\pkg
    if ($LASTEXITCODE) { throw 'NetLeash build failed' }
} finally { Pop-Location }

$kit = Join-Path $here 'out\vmkit'
Remove-Item $kit -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $kit | Out-Null
Copy-Item (Join-Path $here 'out\netleashlim.sys'), (Join-Path $here 'out\NetLeashTestDriver.cer'), `
    (Join-Path $root 'target\pkg\release\netleash.exe'), (Join-Path $here 'vmtest\*') $kit
Write-Host "VM kit ready: $kit"
Get-ChildItem $kit | Format-Table Name, Length -AutoSize
