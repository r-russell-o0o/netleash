# Remove NetLeash. Rules and usage history in %ProgramData%\NetLeash are kept
# unless -RemoveData is given.

[CmdletBinding()]
param(
    [switch]$RemoveData
)

$ErrorActionPreference = 'Continue'
$TaskName = 'NetLeash'
$InstallDir = $PSScriptRoot
$DataDir = Join-Path $env:ProgramData 'NetLeash'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($RemoveData) { $argList += '-RemoveData' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Write-Host 'Stopping NetLeash...'
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Get-Process netleash -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2

# Its WFP filters and WinDivert handles vanished with the process. Clean up
# the two things that can outlive it until the next reboot.
logman stop NetLeash-KernelNetwork -ets 2>$null | Out-Null
Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'NetLeash-*' } |
    ForEach-Object { Remove-NetQosPolicy -Name $_.Name -PolicyStore ActiveStore -Confirm:$false }
sc.exe stop WinDivert 2>$null | Out-Null   # fails harmlessly if another program still uses it

$wd = Join-Path $InstallDir 'windivert'
if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) {
    Remove-MpPreference -ExclusionPath $wd -ErrorAction SilentlyContinue
}
Remove-Item (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\NetLeash.url') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:PUBLIC 'Desktop\NetLeash.url') -ErrorAction SilentlyContinue
Remove-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetLeash' -Recurse -ErrorAction SilentlyContinue

Write-Host "Removing $InstallDir"
Set-Location $env:TEMP
Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
if (Test-Path $InstallDir) {
    Write-Host 'Some files were in use; they will be removed at the next reboot.' -ForegroundColor Yellow
}

if ($RemoveData) {
    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "Removed rules and history ($DataDir)."
} else {
    Write-Host "Kept rules and history in $DataDir (use -RemoveData to delete them)."
}
Write-Host 'NetLeash removed.' -ForegroundColor Green
if ($Host.Name -eq 'ConsoleHost') { Read-Host 'Press Enter to close' | Out-Null }
