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

# Windows resources, added after the build: the GNU toolchain has no resource
# compiler, but the Win32 UpdateResource API can write them into a finished exe.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
public static class ExeResources {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr BeginUpdateResource(string file, bool deleteExisting);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateResource(IntPtr h, IntPtr type, IntPtr name, ushort lang, byte[] data, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool EndUpdateResource(IntPtr h, bool discard);

    static void Put(IntPtr h, int type, int id, byte[] data) {
        if (!UpdateResource(h, (IntPtr)type, (IntPtr)id, 1033, data, (uint)data.Length))
            throw new System.ComponentModel.Win32Exception();
    }

    // An .ico file becomes one RT_ICON per image plus an RT_GROUP_ICON
    // directory, which is what Explorer shows; a manifest is RT_MANIFEST 1.
    public static void Set(string exe, string ico, string manifest) {
        byte[] f = File.ReadAllBytes(ico);
        int count = BitConverter.ToUInt16(f, 4);
        var group = new MemoryStream();
        group.Write(f, 0, 6);
        IntPtr h = BeginUpdateResource(exe, false);
        if (h == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
        try {
            for (int i = 0; i < count; i++) {
                int e = 6 + 16 * i;
                int size = BitConverter.ToInt32(f, e + 8), offset = BitConverter.ToInt32(f, e + 12);
                byte[] image = new byte[size];
                Array.Copy(f, offset, image, 0, size);
                Put(h, 3, i + 1, image);
                group.Write(f, e, 12);
                group.Write(BitConverter.GetBytes((ushort)(i + 1)), 0, 2);
            }
            Put(h, 14, 1, group.ToArray());
            // PowerShell passes $null for a string as "", hence IsNullOrEmpty.
            if (!string.IsNullOrEmpty(manifest)) Put(h, 24, 1, System.Text.Encoding.UTF8.GetBytes(manifest));
        } catch { EndUpdateResource(h, true); throw; }
        if (!EndUpdateResource(h, false)) throw new System.ComponentModel.Win32Exception();
    }
}
'@
# The installer asks for Administrator rights itself, so Explorer shows the
# shield on its icon and the prompt appears at once.
$adminManifest = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
</assembly>
'@
$ico = Join-Path $root 'installer\netleash.ico'
$bin = Join-Path $root 'target\pkg\release'
Copy-Item (Join-Path $bin 'netleash.exe'), (Join-Path $bin 'netleash-tray.exe') $out
Copy-Item (Join-Path $bin 'netleash-setup.exe') (Join-Path $out 'Install NetLeash.exe')
[ExeResources]::Set((Join-Path $out 'netleash.exe'), $ico, $null)
[ExeResources]::Set((Join-Path $out 'netleash-tray.exe'), $ico, $null)
[ExeResources]::Set((Join-Path $out 'Install NetLeash.exe'), $ico, $adminManifest)
Copy-Item (Join-Path $root 'installer\*') $out
Set-Content (Join-Path $out 'VERSION') "$version ($commit)"

Compress-Archive -Path (Join-Path $out '*') -DestinationPath "$out.zip"
$hash = (Get-FileHash "$out.zip" -Algorithm SHA256).Hash
Write-Host "`nPackage: $out.zip"
Write-Host "SHA-256: $hash"
