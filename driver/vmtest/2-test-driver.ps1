# Run INSIDE the test VM, as Administrator, after 1-prepare-vm.ps1 and a reboot.
# Installs the driver, starts NetLeash with it, and checks that a download
# limit holds, that lifting it restores full speed, and that stopping NetLeash
# lifts everything. Writes results to results.txt next to this script.
param(
    [int]$LimitKB = 200,
    [string]$Url = 'https://speed.cloudflare.com/__down?bytes=30000000'
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$log = Join-Path $here 'results.txt'
$rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ReleaseId
Set-Content $log "NetLeash driver test, $(Get-Date -Format s), $([Environment]::OSVersion.VersionString), release $rel"
function Say($m, $color = 'Gray') { Write-Host $m -ForegroundColor $color; Add-Content $log $m }
$fail = 0
function Check($ok, $what) {
    if ($ok) { Say "PASS  $what" Green } else { Say "FAIL  $what" Red; $script:fail++ }
}

$sys = Join-Path $here 'netleashlim.sys'
$exe = Join-Path $here 'netleash.exe'
$port = 5197
$data = Join-Path $env:TEMP 'netleash-drivertest'

# 1. Driver service
sc.exe stop NetLeashLimiter 2>$null | Out-Null
sc.exe delete NetLeashLimiter 2>$null | Out-Null
sc.exe create NetLeashLimiter type= kernel start= demand binPath= "$sys" | Out-Null
sc.exe start NetLeashLimiter | Out-Null
$q = sc.exe query NetLeashLimiter | Out-String
Check ($q -match 'RUNNING') 'driver loads and runs'
if ($q -notmatch 'RUNNING') { Say $q; Say 'Stopping here.'; exit 1 }

# 2. Test program: a copy of curl, so the limit hits nothing else
# (Windows 10 before 1803 has no curl of its own; the kit brings one.)
$curl = Join-Path $env:TEMP 'nl-curl.exe'
$src = "$env:WINDIR\System32\curl.exe"
if (-not (Test-Path $src)) { $src = Join-Path $here 'curl.exe' }
Copy-Item $src $curl -Force
function Speed {
    $bps = & $curl -s -o NUL --max-time 25 -w '%{speed_download}' $Url
    [math]::Round([double]$bps / 1024)
}
$base = Speed
Say "unlimited before NetLeash: $base KB/s"

# 3. NetLeash with the driver backend
Remove-Item $data -Recurse -Force -ErrorAction SilentlyContinue
$errlog = Join-Path $here 'netleash-stderr.txt'
$p = Start-Process $exe -ArgumentList '--limiter', 'driver', '--port', $port, '--data-dir', $data -PassThru `
    -NoNewWindow -RedirectStandardOutput (Join-Path $here 'netleash-stdout.txt') -RedirectStandardError $errlog
$api = "http://127.0.0.1:$port"
$hdr = @{ 'X-NetLeash' = '1' }
$state = $null
for ($i = 0; $i -lt 30 -and -not $p.HasExited -and -not $state; $i++) {
    Start-Sleep 1
    try { $state = Invoke-RestMethod "$api/api/state" -TimeoutSec 2 } catch {}
}
if (-not $state) {
    Check $false 'NetLeash starts and answers'
    if ($p.HasExited) { Say "NetLeash exited with code $($p.ExitCode)" } else { Say 'NetLeash still running but not answering'; Stop-Process -Id $p.Id -Force }
    Say '--- NetLeash error output ---'; if (Test-Path $errlog) { Say (Get-Content $errlog -Raw) }
    Say '--- netleash.log ---'; $nl = Join-Path $data 'netleash.log'; if (Test-Path $nl) { Say (Get-Content $nl -Raw) }
    sc.exe stop NetLeashLimiter | Out-Null
    Say 'Stopping here. Send results.txt.'
    exit 1
}
Say "NetLeash: limiter = $($state.status.limiter); downloads = $($state.status.shaper)"
Check ($state.status.shaper -like 'ok (NetLeash driver)*') 'NetLeash uses the driver'

$rule = @{ path = $curl; down_limit = $LimitKB * 1024 } | ConvertTo-Json
Invoke-RestMethod "$api/api/rule" -Method Post -Body $rule -ContentType 'application/json' -Headers $hdr | Out-Null
Start-Sleep 1
$limited = Speed
Say "limited to $LimitKB KB/s: $limited KB/s"
Check ($limited -gt $LimitKB * 0.6 -and $limited -lt $LimitKB * 1.35) "download holds near $LimitKB KB/s"

$rule = @{ path = $curl; down_limit = $null } | ConvertTo-Json
Invoke-RestMethod "$api/api/rule" -Method Post -Body $rule -ContentType 'application/json' -Headers $hdr | Out-Null
Start-Sleep 1
$free = Speed
Say "limit removed: $free KB/s"
Check ($free -gt $LimitKB * 2) 'removing the limit restores speed'

# 4. Fail-open: limit again, kill NetLeash mid-way, speed must recover
$rule = @{ path = $curl; down_limit = $LimitKB * 1024 } | ConvertTo-Json
Invoke-RestMethod "$api/api/rule" -Method Post -Body $rule -ContentType 'application/json' -Headers $hdr | Out-Null
Stop-Process -Id $p.Id -Force
Start-Sleep 2
$after = Speed
Say "after killing NetLeash: $after KB/s"
Check ($after -gt $LimitKB * 2) 'killing NetLeash lifts the limit (fails open)'

# 5. Unload
sc.exe stop NetLeashLimiter | Out-Null
Start-Sleep 2
Check ((sc.exe query NetLeashLimiter | Out-String) -match 'STOPPED') 'driver unloads cleanly'
sc.exe delete NetLeashLimiter | Out-Null

Say ''
if ($fail) { Say "$fail check(s) failed. Send results.txt." Red } else { Say 'All checks passed. Send results.txt.' Green }
