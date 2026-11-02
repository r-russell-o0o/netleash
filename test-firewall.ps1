# Check the real WFP filters (needs admin and an internet connection):
# a copy of curl must reach a local address but not the internet when
# blocked "internet only", and neither when fully blocked.
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`""
    exit
}
Set-Location $PSScriptRoot
cargo test --quiet wfp::tests::real_filters -- --ignored --nocapture
if ($LASTEXITCODE) { Write-Host 'FIREWALL TEST FAILED' -ForegroundColor Red } else { Write-Host 'Firewall test passed.' -ForegroundColor Green }
Read-Host 'Press Enter to close' | Out-Null
