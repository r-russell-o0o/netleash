# Build NetLeash (release) and start it elevated in its own console window.
# Close that window or press Ctrl+C in it to stop; limits and blocks are removed on exit.
param([int]$Port = 5199)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Push-Location $root
try { cargo build --release } finally { Pop-Location }

$exe = Join-Path $root 'target\release\netleash.exe'
Start-Process -FilePath $exe -ArgumentList '--port', $Port, '--open' -Verb RunAs
