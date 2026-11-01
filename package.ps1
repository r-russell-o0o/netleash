# Build the installable package: dist\NetLeash-<version>.zip
# The zip holds no WinDivert binaries (Defender would flag the zip); the
# installer downloads WinDivert and checks its SHA-256 when asked to.

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
try {
    cargo test --quiet
    if ($LASTEXITCODE) { throw 'tests failed' }
    # Own build folder, so a NetLeash running from target\release can't lock the exe.
    cargo build --release --target-dir target\pkg
    if ($LASTEXITCODE) { throw 'build failed' }
} finally { Pop-Location }

$version = (Select-String -Path (Join-Path $root 'Cargo.toml') -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
$commit = (git -C $root rev-parse --short HEAD 2>$null)
$name = "NetLeash-$version"
$dist = Join-Path $root 'dist'
$out = Join-Path $dist $name
Remove-Item $out, "$out.zip" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null

Copy-Item (Join-Path $root 'target\pkg\release\netleash.exe') $out
Copy-Item (Join-Path $root 'installer\*') $out
Set-Content (Join-Path $out 'VERSION') "$version ($commit)"

Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip"
$hash = (Get-FileHash "$out.zip" -Algorithm SHA256).Hash
Write-Host "`nPackage: $out.zip"
Write-Host "SHA-256: $hash"
