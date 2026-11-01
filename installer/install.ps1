# NetLeash installer. Run from the unpacked package (Install.cmd does this).
#
#  - copies netleash.exe to Program Files
#  - optionally installs the WinDivert driver (needed for bandwidth limits)
#  - registers a scheduled task that starts NetLeash at boot as SYSTEM and
#    restarts it within 5 minutes if it ever stops
#  - adds a Start-menu link to the UI and an entry in Installed apps
#
# Re-running it upgrades in place; rules and history in %ProgramData%\NetLeash are kept.

[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'NetLeash'),
    [int]$Port = 5199,
    # Install WinDivert without asking (you add its Defender exclusion yourself first).
    [switch]$WinDivert,
    # Skip WinDivert: blocking and upload limits still work, download limits don't.
    [switch]$NoWinDivert,
    # Use this WinDivert-2.2.2-A.zip instead of downloading it (offline install).
    [string]$WinDivertZip
)

$ErrorActionPreference = 'Stop'
$TaskName = 'NetLeash'
$DataDir = Join-Path $env:ProgramData 'NetLeash'
$WinDivertUrl = 'https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'
$WinDivertSha256 = '63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15'

# --- elevate ---------------------------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [switch]) { if ($kv.Value) { $argList += "-$($kv.Key)" } }
        else { $argList += "-$($kv.Key)", "`"$($kv.Value)`"" }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
$src = $PSScriptRoot
if (-not (Test-Path (Join-Path $src 'netleash.exe'))) { throw "netleash.exe not found next to install.ps1" }
$version = (Get-Item (Join-Path $src 'netleash.exe')).VersionInfo.ProductVersion
if (-not $version) { $version = (Get-Content (Join-Path $src 'VERSION') -ErrorAction SilentlyContinue) }

try {
    # --- stop a running copy -------------------------------------------------------
    Step 'Stopping any running NetLeash'
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Get-Process netleash -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    # --- files -----------------------------------------------------------------------
    Step "Copying files to $InstallDir"
    New-Item -ItemType Directory -Force $InstallDir | Out-Null
    foreach ($f in 'netleash.exe', 'netleash.ico', 'uninstall.ps1', 'README.txt', 'VERSION') {
        $p = Join-Path $src $f
        if (Test-Path $p) { Copy-Item $p $InstallDir -Force }
    }

    # Rules decide what gets blocked, so only Administrators/SYSTEM may change them.
    New-Item -ItemType Directory -Force $DataDir | Out-Null
    icacls $DataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

    # --- WinDivert -----------------------------------------------------------------
    $wd = Join-Path $InstallDir 'windivert'
    $haveWd = (Test-Path (Join-Path $wd 'WinDivert.dll')) -and (Test-Path (Join-Path $wd 'WinDivert64.sys'))
    if ($NoWinDivert) {
        Step 'Skipping WinDivert (download limits will be off)'
    } elseif ($haveWd) {
        Step 'WinDivert already installed, keeping it'
    } else {
        Step 'WinDivert (needed for upload/download limits)'
        # The folder is created first so it can be picked in Windows Security.
        # This installer never changes Defender settings itself: that is the
        # user's decision, made in Windows Security.
        New-Item -ItemType Directory -Force $wd | Out-Null
        $howTo = @"
Microsoft Defender flags WinDivert as "potentially unwanted" (malware uses it
too) and deletes it unless YOU exclude this one folder. This installer will
not change Defender settings for you.

    $wd

  1. Open Windows Security (press O below to open it)
  2. Virus & threat protection > Manage settings (under "settings")
  3. Exclusions > Add or remove exclusions > Add an exclusion > Folder
  4. Choose the folder above
"@
        $go = $WinDivert
        if (-not $go) {
            Write-Host "Bandwidth limits use the open-source WinDivert driver (github.com/basil00/WinDivert)."
            Write-Host $howTo
            Write-Host "Without WinDivert, blocking and upload limits (via Windows QoS) still work; download limits don't."
            while ($true) {
                $answer = Read-Host "`nY = exclusion added, install WinDivert   O = open Windows Security   N = skip"
                if ($answer -match '^o') { Start-Process 'windowsdefender://threatsettings'; continue }
                $go = $answer -match '^y'
                break
            }
        }
        # Interactive runs may retry after fixing the exclusion; -WinDivert runs try once.
        while ($go) {
            $go = $false
            $zip = Join-Path $wd 'WinDivert.zip'
            $tmp = Join-Path $wd 'extract'
            try {
                if ($WinDivertZip) { Copy-Item $WinDivertZip $zip -Force }
                else {
                    Write-Host "Downloading $WinDivertUrl"
                    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest $WinDivertUrl -OutFile $zip -UseBasicParsing
                }
                $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
                if ($hash -ne $WinDivertSha256) {
                    throw "the download has the wrong SHA-256 ($hash)"
                }
                Expand-Archive $zip -DestinationPath $tmp -Force
                $x64 = Join-Path $tmp 'WinDivert-2.2.2-A\x64'
                Copy-Item (Join-Path $x64 'WinDivert.dll'), (Join-Path $x64 'WinDivert64.sys') $wd -Force
                Copy-Item (Join-Path $tmp 'WinDivert-2.2.2-A\LICENSE') (Join-Path $wd 'LICENSE.txt') -Force
                $sig = Get-AuthenticodeSignature (Join-Path $wd 'WinDivert64.sys')
                Write-Host "Driver signature: $($sig.Status) ($($sig.SignerCertificate.Subject))"
                if ($sig.Status -ne 'Valid') {
                    Remove-Item (Join-Path $wd 'WinDivert*') -Force
                    throw 'the driver signature is not valid'
                }
                Write-Host 'WinDivert installed.' -ForegroundColor Green
            } catch {
                # Most likely Defender removed the files because the folder
                # isn't excluded yet. Everything but limits works without it.
                Write-Host "`nWinDivert not installed: $($_.Exception.Message)" -ForegroundColor Yellow
                $blocked = "$($_.Exception.Message)" -match 'virus|unwanted'
                if ($blocked) { Write-Host "Defender removed it: the folder isn't excluded yet.`n$howTo" }
                if (-not $WinDivert) {
                    while ($true) {
                        $answer = Read-Host "`nR = retry (after adding the exclusion)   O = open Windows Security   N = continue without it"
                        if ($answer -match '^o') { Start-Process 'windowsdefender://threatsettings'; continue }
                        $go = $answer -match '^r'
                        break
                    }
                }
            } finally {
                Remove-Item $tmp, $zip -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        if (-not (Test-Path (Join-Path $wd 'WinDivert64.sys'))) {
            Write-Host 'Continuing without WinDivert. Run Install.cmd again at any time to add it.'
        }
    }

    # --- start at boot ---------------------------------------------------------------
    Step 'Registering the startup task'
    $exe = Join-Path $InstallDir 'netleash.exe'
    $action = New-ScheduledTaskAction -Execute $exe -Argument "--port $Port" -WorkingDirectory $InstallDir
    # At boot, plus every 5 minutes: if NetLeash is running the repeat does
    # nothing (IgnoreNew); if it has died, it comes back within 5 minutes.
    $atBoot = New-ScheduledTaskTrigger -AtStartup
    $repeat = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $TaskName -Description 'NetLeash network monitor and firewall (UI: http://127.0.0.1:5199)' `
        -Action $action -Trigger $atBoot, $repeat -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName

    # --- desktop + Start menu shortcuts, Installed apps ---------------------------------
    # Links to the UI in the default browser, for every user of this PC. The
    # icon is netleash.ico (the exe itself carries no icon resource).
    $ico = Join-Path $InstallDir 'netleash.ico'
    $link = "[InternetShortcut]`r`nURL=http://127.0.0.1:$Port/`r`nIconFile=$ico`r`nIconIndex=0`r`n"
    foreach ($dir in (Join-Path $env:PUBLIC 'Desktop'), (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs')) {
        Set-Content (Join-Path $dir 'NetLeash.url') $link
    }
    $uninstKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NetLeash'
    New-Item -Force $uninstKey | Out-Null
    $uninstall = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
    @{ DisplayName = 'NetLeash'; DisplayVersion = "$version"; Publisher = 'NetLeash';
       InstallLocation = $InstallDir; DisplayIcon = $ico; UninstallString = $uninstall; NoModify = 1; NoRepair = 1
    }.GetEnumerator() | ForEach-Object {
        $type = if ($_.Value -is [int]) { 'DWord' } else { 'String' }
        New-ItemProperty -Path $uninstKey -Name $_.Key -Value $_.Value -PropertyType $type -Force | Out-Null
    }

    # --- check it is really running (not just that the task was registered) ------
    Step 'Checking that NetLeash is up'
    $state = $null
    for ($i = 0; $i -lt 30 -and -not $state; $i++) {
        Start-Sleep -Seconds 1
        try { $state = Invoke-RestMethod "http://127.0.0.1:$Port/api/state" -TimeoutSec 2 } catch {}
    }
    if ($state) {
        $state.status.PSObject.Properties | ForEach-Object { '  {0,-8} {1}' -f $_.Name, $_.Value }
        Write-Host "`nNetLeash is running. Open it from the NetLeash icon on the desktop or in the Start menu (http://127.0.0.1:$Port/)." -ForegroundColor Green
    } else {
        Write-Host "`nNetLeash did not answer on port $Port within 30 s." -ForegroundColor Yellow
        $log = Join-Path $DataDir 'netleash.log'
        if (Test-Path $log) { Write-Host 'Last log lines:'; Get-Content $log -Tail 15 }
    }
} catch {
    Write-Host "`nInstall failed: $_" -ForegroundColor Red
}
if ($Host.Name -eq 'ConsoleHost') { Read-Host "`nPress Enter to close" | Out-Null }
