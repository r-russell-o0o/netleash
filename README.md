# NetLeash

A personal, auditable take on [NetLimiter](https://netlimiter.com/) for Windows:
see which applications use the network, block them, and cap their upload and
download rates.

It is under 3,000 lines in total (Rust plus one HTML page). Monitoring and
blocking use **only mechanisms built into Windows**. Rate limits use the
open-source [WinDivert](https://reqrypt.org/windivert.html) driver when it is
present. Without it, NetLeash falls back to Windows QoS, which can limit uploads only.

| Feature | How | Needs |
|---|---|---|
| Live per-app traffic (rates, totals, 60 s sparklines) | ETW provider `Microsoft-Windows-Kernel-Network` (`src/etw.rs`) | Admin |
| Per-app open connections | IP Helper `GetExtendedTcpTable` / `GetExtendedUdpTable` (`src/conns.rs`) | – |
| Block an app (in and out, IPv4 and IPv6) | Windows Filtering Platform filters on `FWPM_CONDITION_ALE_APP_ID` (`src/wfp.rs`) | Admin |
| Close a blocked app's open connections | `SetTcpEntry(DELETE_TCB)`, IPv4 TCP only (`src/conns.rs`) | Admin |
| Upload and download limits per app | WinDivert + token bucket (`src/shaper.rs`, `src/windivert.rs`) | Admin, WinDivert |
| Upload limit, fallback without WinDivert | Policy-based QoS (`New-NetQosPolicy -ThrottleRateActionBitsPerSecond`) (`src/qos.rs`) | Admin |
| Daily usage history | `usage.json`, 120 days (`src/state.rs`) | – |
| Web UI | `http://127.0.0.1:5199`, single file `ui/index.html` | – |

## Installing (this PC or others)

```powershell
.\package.ps1          # runs the tests, builds dist\NetLeash-<version>.zip
```

Copy the zip to any 64-bit Windows 10/11 PC, unzip it, and double-click `Install.cmd`.
The installer (`installer\install.ps1`):
- copies `netleash.exe` to `C:\Program Files\NetLeash`
- offers to install WinDivert. It creates `C:\Program Files\NetLeash\windivert`
  and asks you to exclude that folder in Windows Security first. The installer
  never changes Defender settings itself: an earlier version that did was flagged
  by Defender as `Trojan:PowerShell/Killav` (antivirus tampering), which is fair
  for any script that does that. The driver is downloaded and hash-checked, so the
  zip contains nothing for Defender to flag. Use `-WinDivertZip FILE` for offline PCs.
- registers the scheduled task **NetLeash**: it runs as SYSTEM at boot,
  before anyone logs in. A second trigger fires every 5 minutes and restarts
  NetLeash if it has stopped; while it's running that trigger does nothing.
- locks `C:\ProgramData\NetLeash` so only Administrators can edit the rules
- adds a **NetLeash** shortcut on the desktop and in the Start menu, and an
  entry in Installed apps
- checks that the UI actually answers, and shows the log if it doesn't

Running the installer again upgrades in place, and your rules are kept. To uninstall,
use Installed apps or `uninstall.ps1` (add `-RemoveData` to delete rules and history).
Afterwards, remove the WinDivert exclusion in Windows Security if you added one.

Log file: `C:\ProgramData\NetLeash\netleash.log` (1 MB, plus one older file).

## Running by hand (development)

```powershell
# Explore the UI without admin rights: synthetic traffic, nothing on the system changes
cargo run -- --demo --open

# The real thing (builds release, asks for UAC, opens the UI)
.\run-elevated.ps1
```

Options: `--port N`, `--data-dir DIR` (default `%ProgramData%\NetLeash`), `--open`, `--demo`,
`--windivert DIR`, `--check-windivert` (tests that WinDivert loads and its driver starts, then exits).

Rules live in `rules.json` in the data directory and are re-applied at start.
Each rule is per program (full `.exe` path) and can block outgoing connections,
incoming connections or both, and set upload and download limits. Rules apply
whether or not the program is running. Use **Add program…** for a program
that isn't running. Paths may contain `*` and `?` wildcards, for example a Store
app's version folder; they're re-checked every minute so updates stay covered.

### Importing from NetLimiter

**Import from NetLimiter…** reads `C:\ProgramData\Locktime\NetLimiter\5\nl_settings.xml`
and only reads it. It shows what it would import before you confirm (`src/nlimport.rs`).
Deny rules become blocks in the same direction. Enabled per-program limit rules become
limits. Everything else is listed with the reason it was skipped:
- Allow and Ask rules
- disabled rules
- zone rules such as "Internet" on its own or combined with a program
- rules with address or port conditions
- Store apps that NetLimiter identifies by package rather than path

On this machine (2026-11-01) that's 35 programs from 68 Deny rules. 22 of them
aren't on disk at the moment; those rules are kept and start working once the
file exists.

### WinDivert

WinDivert isn't committed to the repo. To get it:

1. Defender flags WinDivert as "potentially unwanted", because malware uses it too.
   In an Administrator PowerShell, add an exclusion for its folder only:
   `Add-MpPreference -ExclusionPath "S:\Projects\netleash\vendor\WinDivert-2.2.2-A"`
2. Run `.\fetch-windivert.ps1`. It downloads the official 2.2.2 release from
   `github.com/basil00/WinDivert` and refuses the file unless its SHA-256 is
   `63CB4176…5F3F15`, the hash of the copy reviewed when this was set up.
3. Run `netleash --check-windivert` from an elevated prompt.

NetLeash looks for `WinDivert.dll` + `WinDivert64.sys` in `--windivert DIR`, then
`<exe dir>\windivert`, then `vendor\WinDivert-2.2.2-A\x64` above the exe.

Provenance as checked on 2026-11-01:
- `WinDivert64.sys` has a valid Authenticode signature: EV certificate issued by
  Sectigo to 成都密思听科技有限公司 (a Chengdu company).
  This is the signer of the official release asset. The WinDivert author doesn't
  sign it personally.
- `WinDivert.dll` is not signed. The DLL is small and the source is public, so it can
  be rebuilt from source if you'd rather not trust the binary.
- `src/windivert.rs` binds only six functions. Their signatures, the constants and
  the `WINDIVERT_ADDRESS` layout were checked against `include\windivert.h` from the release.

### Toolchain note

This machine has no Visual Studio Build Tools, so `rust-toolchain.toml` pins
Rust's GNU toolchain, which links with its own bundled MinGW. If you install the
MSVC Build Tools later, you can delete `rust-toolchain.toml` and build with the
default MSVC toolchain instead. The code doesn't need changing.

## Safety properties (worth checking when you vet it)

- **Fail-open.** WFP filters are created in a *dynamic session*, so Windows
  deletes them when the process exits, even if it crashes or is killed. QoS
  policies go in the non-persistent `ActiveStore` and are removed on exit;
  in the worst case a reboot clears them. Nothing NetLeash does can outlive a reboot.
- **The shaper is fail-open too.** Packets are diverted only while at least one
  limit exists; removing the last limit closes the packet handle. Packets that
  can't be attributed to a process, and packets of apps without a limit, are
  re-injected at once and unchanged. If NetLeash dies, WinDivert stops diverting.
  Any packets still queued are lost, and TCP retransmits them. The driver
  unloads when its last handle closes.
- **Monitoring is observe-only.** ETW sees a copy of the kernel's accounting.
  It can't delay or drop a packet.
- **The UI only listens on 127.0.0.1.** Because the process is elevated, the API
  rejects any `Host` header except `127.0.0.1:PORT`/`localhost:PORT`. That stops
  DNS rebinding. Every write also needs an `X-NetLeash: 1` header, which a
  cross-origin web page can't send without a CORS preflight that the server never
  approves. Other programs running as you *can* call the API (see Roadmap).
- **Powershell input is quoted.** Paths are passed as single-quoted literals
  with `'` doubled, and paths that contain control characters are rejected
  (`qos.rs` has a test for this).
- **Small dependency surface:** `windows-sys` (Microsoft's raw bindings),
  `serde`/`serde_json`, `tiny_http`.

## Not yet verified on a real elevated run

The demo mode, the parsers and the rule logic have been tested (`cargo test`).
These parts only run elevated and haven't been exercised yet:

1. **ETW field order.** `etw::parse` assumes `daddr` = remote and `saddr` = local
   for both send and receive events. Check the Connections panel against
   `netstat -ano`. If remote and local are swapped for downloads, swap them in `parse`.
2. **WFP block.** Block a browser, confirm that pages stop loading, then unblock it.
3. **WinDivert limits.** Run `netleash --check-windivert` elevated. Then set a
   1000 KB/s download limit on a browser and run a speed test. Expect a result
   close to 8 Mbit/s, and check that other apps are unaffected. Repeat for upload.
   Remove the limits and confirm full speed returns. Watch for raised latency or
   CPU while a limit is active: every packet passes through user mode then.
4. **QoS throttle** (only used without WinDivert). Set a 100 KB/s upload limit on an app and run an upload
   speed test with it. Two known caveats:
   - On machines that aren't joined to a domain, Windows may ignore local QoS
     policies unless `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS`
     has the value `"Do not use NLA"="1"`. That's a system setting you would set by hand.
   - The limit applies only where the QoS Packet Scheduler is bound to the
     adapter. It is bound by default.
5. **Ctrl+C cleanup.** After you exit, `Get-NetQosPolicy -PolicyStore ActiveStore`
   should list no `NetLeash-*` policies, `logman query -ets` should not list
   `NetLeash-KernelNetwork`, and `sc query WinDivert` should report that the service doesn't exist.

## How the shaper works

While at least one limit exists, every non-loopback TCP/UDP packet is diverted
to user mode (`src/shaper.rs`):

1. **Attribution.** Each packet's local port is looked up in a port → PID table.
   WinDivert's FLOW layer fills that table as each connection opens. A miss
   re-reads the OS connection tables, at most four times a second. The PID
   gives the app path, and the path gives the app's limit.
2. **Token bucket per app and direction.** The burst is 100 ms of the rate
   (at least 3,000 bytes) and the queue holds at most 250 ms. A packet that
   fits the budget is re-injected at once. An over-budget packet waits in the
   queue. Past the queue cap, packets are dropped, which makes TCP slow down,
   the same way a congested link does.
3. A pacing thread releases queued packets every 2 ms.

Download limits work because delaying and dropping inbound packets makes the
sender's TCP back off. This is the same approach NetLimiter takes in its own
driver; ours does it in user space.

**Known limitations**
- Every packet takes a user-mode round trip while any limit is active. That's
  fine for home connections, but untested at multi-gigabit rates. The
  receive loop handles one packet at a time; WinDivert's batch API is the
  next step if throughput suffers.
- Attribution uses the local port, so traffic of a process listening on a
  port is shared by everything connected to it. That's still the same app.
- Limits apply to traffic seen after NetLeash starts. A connection opened
  earlier is attributed through the connection table, so it's still limited.

## Roadmap

- Batch receive/send in the shaper (`WinDivertRecvEx`), if throughput needs it
- Run as a Windows service, with the UI as an unprivileged client and an
  authenticated API (a token in an admin-only file)
- Map `svchost.exe` traffic to service names
- "Ask" mode: prompt when an unknown app first connects (WFP ALE callouts need a driver; a first version could poll ETW and block after the fact)
- Global and per-connection limits, and limit schedules
- Tray icon

## Layout

```
src/main.rs     startup, args, 1 s clock, shutdown
src/state.rs    counters, rules, usage history (no OS calls; unit-tested)
src/etw.rs      Kernel-Network ETW session + event parser
src/wfp.rs      WFP dynamic-session block filters
src/qos.rs      NetQosPolicy upload limits
src/enforce.rs  rules -> WFP + shaper (or QoS)
src/shaper.rs   WinDivert token-bucket limiter (unit-tested buckets)
src/windivert.rs  runtime-loaded WinDivert bindings + packet header parser
src/conns.rs    connection tables, closing connections
src/nlimport.rs NetLimiter 5 settings importer (read-only, unit-tested)
src/pathglob.rs wildcard program paths
src/sys.rs      elevation, time, PID -> path, Ctrl+C
src/web.rs      HTTP API + embedded UI
src/demo.rs     synthetic traffic for --demo
ui/index.html   the UI
```
