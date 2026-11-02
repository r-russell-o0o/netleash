# Build netleashlim.sys with the Visual Studio Build Tools and the Windows
# Driver Kit, without a Visual Studio project. Also runs the compiler's static
# analysis (/analyze) and the user-mode tests of the token bucket.
#
#   .\build.ps1            build, analyze, test
#   .\build.ps1 -Sign      ... and test-sign with the "NetLeash Test Driver" certificate
#                          (created on first use in CurrentUser\My; for test-signing VMs only)
param([switch]$Sign)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'out'
New-Item -ItemType Directory -Force $out | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual Studio Build Tools with the C++ x64 compiler are not installed' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'

# The newest Windows Kit that has the kernel headers *and* libraries.
$kits = 'C:\Program Files (x86)\Windows Kits\10'
$ver = Get-ChildItem "$kits\Include" -Directory | Sort-Object Name -Descending |
    Where-Object { (Test-Path "$kits\Include\$($_.Name)\km\fwpsk.h") -and (Test-Path "$kits\Lib\$($_.Name)\km\x64\fwpkclnt.lib") } |
    Select-Object -First 1 -ExpandProperty Name
if (-not $ver) { throw 'No Windows Driver Kit with kernel headers and libraries found' }
$inc = "$kits\Include\$ver"
$lib = "$kits\Lib\$ver\km\x64"
Write-Host "Windows Kit $ver"

$defs = '/D_AMD64_ /D_WIN64 /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ' +
        '/DWINVER=0x0A00 /DNDIS_SUPPORT_NDIS6=1 /DNDIS630=1 /DPOOL_NX_OPTIN=1'
$cflags = "/nologo /c /kernel /Zi /W4 /WX /GS /Gy /Gw /O2 /analyze /analyze:WX- $defs " +
          "/I`"$inc\km`" /I`"$inc\km\crt`" /I`"$inc\shared`" /Fo`"$out\\`" /Fd`"$out\netleashlim.pdb`""
$lflags = "/nologo /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry /NODEFAULTLIB /RELEASE /DEBUG " +
          "/OPT:REF /OPT:ICF /MERGE:_TEXT=.text /INTEGRITYCHECK /LIBPATH:`"$lib`" " +
          "ntoskrnl.lib hal.lib fwpkclnt.lib ndis.lib wdmsec.lib BufferOverflowFastFailK.lib " +
          "/PDB:`"$out\netleashlim.pdb`" /OUT:`"$out\netleashlim.sys`""

# Through a .cmd file: PowerShell re-quotes arguments to native programs.
function Invoke-Cmd([string]$line) {
    $bat = Join-Path $out 'step.cmd'
    Set-Content $bat "@call `"$vcvars`" >nul`r`n$line`r`n@exit /b %ERRORLEVEL%" -Encoding ascii
    cmd /c $bat
}
Invoke-Cmd "cl $cflags `"$here\netleashlim.c`" && link $lflags `"$out\netleashlim.obj`""
if ($LASTEXITCODE) { throw "driver build failed ($LASTEXITCODE)" }
Write-Host "Built $out\netleashlim.sys"

# Token-bucket tests, as an ordinary console program.
Invoke-Cmd "cl /nologo /W4 /WX /O2 /Fe`"$out\bucket_test.exe`" /Fo`"$out\\`" `"$here\tests\bucket_test.c`""
if ($LASTEXITCODE) { throw 'bucket test build failed' }
& "$out\bucket_test.exe"
if ($LASTEXITCODE) { throw 'bucket tests failed' }

if ($Sign) {
    $subject = 'CN=NetLeash Test Driver'
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object Subject -eq $subject | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(3)
        Write-Host "Created test certificate $($cert.Thumbprint) in CurrentUser\My"
    }
    Export-Certificate -Cert $cert -FilePath "$out\NetLeashTestDriver.cer" | Out-Null
    $signtool = Get-ChildItem "$kits\bin\*\x64\signtool.exe" | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    & $signtool sign /q /fd SHA256 /sha1 $cert.Thumbprint "$out\netleashlim.sys"
    if ($LASTEXITCODE) { throw 'signing failed' }
    Write-Host "Test-signed; the VM needs $out\NetLeashTestDriver.cer and test signing on"
}
