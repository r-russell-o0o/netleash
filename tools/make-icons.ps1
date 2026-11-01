# Build installer\netleash.ico from the SVG icons, using headless Chrome to
# render and .NET to scale. Small sizes come from assets\icon-small.svg
# (drawn for 16-48 px), large ones from the detailed assets\icon.svg.
#
#   .\tools\make-icons.ps1
param([string]$Chrome = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe")

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$root = Split-Path $PSScriptRoot
$tmp = Join-Path ([IO.Path]::GetTempPath()) "netleash-icons-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null

function Render-Svg([string]$svg, [int]$px) {
    $html = Join-Path $tmp "render.html"
    $src = 'file:///' + ((Resolve-Path $svg).Path -replace '\\', '/')
    Set-Content $html "<!doctype html><html><head><style>html,body{margin:0;background:transparent;overflow:hidden}img{display:block;width:${px}px;height:${px}px}</style></head><body><img src=`"$src`"></body></html>"
    $png = Join-Path $tmp ([IO.Path]::GetFileNameWithoutExtension($svg) + "-$px.png")
    & $Chrome --headless=new --disable-gpu --hide-scrollbars --default-background-color=00000000 `
        --window-size="$px,$px" --screenshot="$png" ('file:///' + ($html -replace '\\', '/')) 2>&1 | Out-Null
    for ($i = 0; $i -lt 50 -and -not (Test-Path $png); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path $png)) { throw "Chrome did not render $svg" }
    $png
}

function Get-ScaledPng([string]$png, [int]$size) {
    $src = [Drawing.Image]::FromFile($png)
    try {
        $bmp = [Drawing.Bitmap]::new($size, $size, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g = [Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
        $g.DrawImage($src, 0, 0, $size, $size)
        $g.Dispose()
        $ms = [IO.MemoryStream]::new()
        $bmp.Save($ms, [Drawing.Imaging.ImageFormat]::Png)
        $bmp.Dispose()
        , $ms.ToArray()
    } finally { $src.Dispose() }
}

$small = Render-Svg (Join-Path $root 'assets\icon-small.svg') 512
$large = Render-Svg (Join-Path $root 'assets\icon.svg') 1024
$images = foreach ($s in 16, 24, 32, 48, 64, 128, 256) {
    [pscustomobject]@{ Size = $s; Png = (Get-ScaledPng $(if ($s -le 48) { $small } else { $large }) $s) }
}

# ICO file: 6-byte header, one 16-byte entry per image, then the PNG data
# (PNG-compressed entries are supported since Windows Vista).
$out = Join-Path $root 'installer\netleash.ico'
$fs = [IO.File]::Create($out)
$w = [IO.BinaryWriter]::new($fs)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$images.Count)
$offset = 6 + 16 * $images.Count
foreach ($img in $images) {
    $dim = if ($img.Size -ge 256) { 0 } else { $img.Size }   # 0 means 256
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$img.Png.Length); $w.Write([uint32]$offset)
    $offset += $img.Png.Length
}
foreach ($img in $images) { $w.Write($img.Png) }
$w.Close()
Remove-Item $tmp -Recurse -Force
Write-Host ("installer\netleash.ico: {0} sizes, {1:N0} KB" -f $images.Count, ((Get-Item $out).Length / 1KB))
