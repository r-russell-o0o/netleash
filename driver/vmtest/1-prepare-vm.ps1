# Run INSIDE the test VM, as Administrator, once. Never on your own PC.
# Lets Windows load the test-signed NetLeash driver, then asks to reboot.
#   -Verifier  also watch the driver with Driver Verifier (catches driver bugs
#              early, at the cost of a bluescreen in the VM if it finds one)
param([switch]$Verifier)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from an Administrator PowerShell.' }
if ((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'VMware|Virtual|KVM|HVM') {
    throw 'This does not look like a virtual machine. Test signing is for test VMs only.'
}
try { if (Confirm-SecureBootUEFI) { throw 'Secure Boot is on: turn it off in the VM settings first.' } } catch [System.PlatformNotSupportedException] {}

# Trust the test certificate the driver is signed with.
$cer = Join-Path $here 'NetLeashTestDriver.cer'
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null

bcdedit /set testsigning on | Out-Null
if ($LASTEXITCODE) { throw 'bcdedit failed' }
if ($Verifier) {
    verifier /standard /driver netleashlim.sys | Out-Null
    Write-Host 'Driver Verifier will watch netleashlim.sys.'
}
Write-Host 'Test signing is on. Reboot the VM, then run 2-test-driver.ps1.' -ForegroundColor Green
