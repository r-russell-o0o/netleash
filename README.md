# NetLeash

A small, auditable, per-program network monitor, firewall and bandwidth
limiter for Windows 10 and 11, in the spirit of
[NetLimiter](https://netlimiter.com/). See which programs use the network, block
them outright or per direction, and cap their upload and download rates, all
from a web page served only to your own PC.

The whole program is about 4,200 lines, comments and tests included (Rust plus
one HTML page), and built to be read. Monitoring and blocking use **only mechanisms built into Windows**.
Bandwidth limits use the open-source [WinDivert](https://reqrypt.org/windivert.html)
driver when it's installed.

> NetLeash is an independent project. It isn't affiliated with or endorsed by
> Locktime Software, the makers of NetLimiter. It can import NetLimiter 5 rules
> but uses none of its code.

**Status: early (0.1).** It runs every day on its author's PC; see
[Testing status](#testing-status) for exactly what has and hasn't been verified.

## Features

| Feature | How |
|---|---|
| Live traffic per program: rates, totals, last 60 s | ETW provider `Microsoft-Windows-Kernel-Network` (`src/etw.rs`) |
| Open connections per program | IP Helper connection tables (`src/conns.rs`) |
| Block a program: outgoing, incoming or both, from everything or from the internet only; works whether or not it's running | Windows Filtering Platform (`src/wfp.rs`) |
| Upload and download limits per program | WinDivert + a token bucket (`src/shaper.rs`) |
| Upload limits without WinDivert | Windows Policy-based QoS (`src/qos.rs`) |
| **Find programs**: every program that uses the network, by name, without knowing its path | usage history + open sockets + Windows Firewall rules (`src/catalog.rs`) |
| Import NetLimiter 5 rules | read-only importer with a preview (`src/nlimport.rs`) |
| Import Windows Firewall block rules and simplewall's blocked programs | read-only importers with the same preview (`src/fwimport.rs`, `src/swimport.rs`) |
| **New-program alerts**: notified when a program uses the network for the first time; strict mode blocks it until you allow it | `src/watch.rs` |
| **Schedules** (a block or limit only at certain times) and **data quotas** (per day or month, then block or slow down) | `src/timed.rs` |
| Tray icon with live speed and notifications | `netleash-tray.exe` (`src/bin/netleash-tray.rs`), started at each user's logon |
| Wildcard paths, e.g. for Store apps whose folder changes with each update | `src/pathglob.rs` |
| Daily usage history (120 days) | `src/state.rs` |
| Starts at boot, restarts itself if it stops | scheduled task as SYSTEM (`installer/install.ps1`) |

## Install

1. Download `NetLeash-<version>.zip` from the
   [Releases](https://github.com/r-russell-o0o/netleash/releases) page and unzip it.
2. Double-click **`Install.cmd`** and approve the Administrator prompt.
3. Answer the WinDivert question. See the next section first if you want bandwidth limits.
4. Open NetLeash from the **NetLeash** icon on the desktop or in the Start menu,
   or go to <http://127.0.0.1:5199/> in any browser.

The installer:
- copies `netleash.exe` to `C:\Program Files\NetLeash`
- registers the scheduled task **NetLeash**. It runs as SYSTEM at boot, before
  anyone logs in, and fires again every 5 minutes. That second trigger restarts
  NetLeash if it has stopped, and does nothing while it's running.
- lets only Administrators change the rules in `C:\ProgramData\NetLeash`.
  Otherwise any program on the PC could unblock itself.
- adds shortcuts on the desktop and in the Start menu, and an entry in Installed apps
- checks that the UI actually answers, and shows the log if it doesn't

Running the installer again upgrades in place, and your rules are kept. Windows
SmartScreen may warn that `netleash.exe` comes from an unknown publisher,
because the program isn't code-signed.

## ⚠ Bandwidth limits need one manual step: a Defender exclusion

Monitoring, blocking, the rules and the NetLimiter import all work straight
after installing. Bandwidth limits need the WinDivert driver, and
**Microsoft Defender deletes WinDivert unless you exclude its folder
yourself**. Defender classes it as "potentially unwanted" because malware
uses it too.

**Do this once per PC, before or during the install:**

1. Open **Windows Security** (from the Start menu, or press **O** at the installer's prompt).
2. Go to **Virus & threat protection > Manage settings** (under "Virus & threat protection settings").
3. Scroll to **Exclusions > Add or remove exclusions > Add an exclusion > Folder**.
4. Choose **`C:\Program Files\NetLeash\windivert`**. The installer creates this
   folder, so it already exists when the installer asks.
5. Back in the installer, answer **Y**, or **R** to retry after a blocked download.
   If you've already finished installing, run `Install.cmd` again; your rules are kept.

It worked when the installer prints `WinDivert installed`. In the UI, the
**Download limits** chip turns green and the yellow "Download limits are off"
notice disappears.

**Why NetLeash doesn't do this for you:** no legitimate way exists. A program
that adds its own antivirus exclusion is behaving like malware, and Defender
treats it that way: an early installer that called `Add-MpPreference` was
blocked as `Trojan:PowerShell/Killav.VDA!MTB` (antivirus tampering). The other
"automatic" routes either hide the exclusion step from Defender or change the
driver files so Defender stops recognising them. Both are evasion, and neither
belongs in a tool you're meant to trust.

The exclusion covers that one folder only. The installer downloads WinDivert
from its official GitHub release and refuses it unless the SHA-256 matches
the reviewed copy. It also checks the driver's signature. The NetLeash zip
contains no WinDivert files, so there's nothing in it for Defender to flag.

## Using it

- **Applications** shows every program that used the network in the last
  15 minutes, plus every program that has a rule. Click a column title to sort,
  and a row to see its connections.
- **Firewall** per program: *Allow*, *Block outgoing* (connections the program
  makes), *Block incoming* (connections it accepts) or *Block all*, or the same
  for the **internet only**: the program can still reach the local network
  (printers, NAS, other PCs). A new block also closes the program's open IPv4
  TCP connections (internet ones only, for an internet-only block).
  **Limitation:** "local network" means the private address ranges (10.x,
  172.16-31.x, 192.168.x, link-local, loopback, multicast; fc00::/7, fe80::/10).
  A local network that uses public addresses counts as internet.
- **Limits** are in KB/s (1 KB = 1024 bytes) for upload (↑) and download (↓).
- **Schedules and quotas**: click a program's row. *Only apply the block and
  limits on* chosen days and times (a range past midnight, such as 22:00 to
  07:00, runs into the next morning). A *data allowance* counts upload +
  download per day or per calendar month, then blocks the program or slows it
  to a set speed until the next day or month. The row shows the state (*resting
  now*, *2.1 GB of 5 GB per month*, *blocked*). **Limitations:** checked every
  10 seconds, so a quota can overshoot by that much traffic; times are the PC's
  local time. Demo mode shows the states but doesn't simulate them in its traffic.
- **Find programs…** lists every program with evidence of network use, by its
  real name ("Google Chrome · Google LLC") and why it's listed: running now,
  used recently, or named in a Windows Firewall rule. Block or limit it right
  there. A program that isn't listed can be added by typing its path.
- **New programs**: the panel above the list shows programs that used the
  network for the first time, with **Allow** and **Block**. Choose *Notify me*,
  *Block them until I allow them* (strict mode) or *Don't watch*. The tray icon
  notifies you too. On the first start, programs already in use are learned
  quietly for 10 minutes. **Limitation:** a program is noticed on its first
  network activity, so in strict mode its very first packets may already have
  gone out. Asking *before* the first connection needs a kernel driver of our own.
- **Import from NetLimiter…** reads NetLimiter 5's settings, only reads them,
  and previews the result before importing. Deny rules become blocks in the
  same direction, and enabled per-program limits become limits. A Deny rule on a
  program combined with the "Internet" zone becomes an internet-only block.
  Everything else is listed with the reason it can't be expressed: Allow and Ask
  rules, disabled rules, other zone rules, rules with address or port conditions,
  limits on internet traffic only, and Store apps identified by package.
- **Import from… Windows Firewall** reads Windows Defender Firewall's rules
  (only reads them; this also covers rules made with Windows Firewall Control)
  and previews the result. Enabled per-program Block rules become blocks in the
  same direction; a Block rule whose remote address is the "Internet" keyword
  becomes an internet-only block, and a TCP + UDP pair of otherwise identical
  rules (what Windows' "allow access?" prompt creates) counts as any protocol.
  Listed with the reason instead: Allow rules, disabled rules, rules without a
  program, and rules only for certain protocols, ports, addresses, services,
  users, interfaces or network profiles (Domain/Private/Public), and Store apps.
- **Import from… simplewall** reads simplewall's `profile.xml` (found in each
  user's `%APPDATA%\Henry++\simplewall`, or give the path of a portable copy).
  simplewall blocks every program it doesn't allow; NetLeash allows by default,
  so programs the profile lists as blocked (unchecked) become blocks, in the
  directions simplewall blocks (its `simplewall.ini` settings), and enabled
  Block rules for programs without address, port, protocol or IP-version
  conditions become blocks. Programs never listed in the profile, allowed
  programs, blocked programs that an Allow rule opens up partly, rules with
  conditions, built-in rules, services and Store apps are listed with the
  reason. Only plain-XML profiles can be read (simplewall can also save them
  compressed or encrypted).

Files: rules in `C:\ProgramData\NetLeash\rules.json`, usage history in `usage.json`,
and a log in `netleash.log` (1 MB, plus one older file).

## Uninstall

Use Settings > Apps > Installed apps > **NetLeash**, or run `uninstall.ps1`
from `C:\Program Files\NetLeash`. Add `-RemoveData` to also delete your rules
and history. Afterwards, remove the WinDivert exclusion in Windows Security if
you added one.

## How it works, and why it's safe to run

- **Fail-open.** WFP block filters live in a *dynamic session*, so Windows
  deletes them when NetLeash exits, even if it crashes or is killed. QoS
  policies go in the non-persistent `ActiveStore`. Nothing NetLeash does to
  your traffic outlives a reboot.
- **The limiter is fail-open too.** Packets are diverted only while at least
  one limit exists; removing the last limit closes the packet handle. Packets
  NetLeash can't attribute to a program, and packets of programs without a
  limit, are passed on at once and unchanged. If NetLeash dies, WinDivert
  stops diverting.
- **Monitoring is observe-only.** ETW reports a copy of the kernel's accounting.
  It can't delay or drop a packet.
- **The UI only listens on 127.0.0.1.** NetLeash runs elevated, so the API
  rejects any `Host` header except `127.0.0.1:PORT` or `localhost:PORT`, which
  stops DNS rebinding. Every change also needs an `X-NetLeash: 1` header, which
  a web page from another site can't send. Note that **other programs running
  on your PC can use the API**. A token-protected API is on the roadmap.
- **PowerShell input is quoted.** Paths passed to the QoS cmdlets are
  single-quoted literals, and paths containing control characters are rejected.
- **The installer never touches Defender settings.**
- **Few dependencies:** `windows-sys` (Microsoft's raw bindings),
  `serde`/`serde_json`, `tiny_http` and `roxmltree`.

### The limiter

While at least one limit exists, every non-loopback TCP/UDP packet passes
through user mode (`src/shaper.rs`):

1. **Attribution.** Each packet's local port is looked up in a port → process
   table. WinDivert's FLOW layer fills that table as each connection opens. A
   miss re-reads the OS connection tables, at most four times a second.
2. **A token bucket per program and direction.** The burst is 100 ms of the
   rate, and the queue holds at most 250 ms. Packets within budget go at once,
   over-budget packets wait, and anything past the queue is dropped. That makes
   TCP slow down, the same way a congested link does.
3. A pacing thread releases queued packets every 2 ms.

Download limits work because delayed and dropped inbound packets make the
sender's TCP back off.

**Limitations:**
- Every packet takes a user-mode round trip while any limit is active. That's
  fine for home connections, but untested at multi-gigabit rates.
- A port's traffic counts towards the process that owns the port.
- `svchost.exe` traffic isn't split by Windows service yet.

## Testing status

The unit tests cover the parsers, the rule logic, the token bucket, the
importers (NetLimiter, Windows Firewall, simplewall), wildcard paths and the
program catalog (`cargo test`).
Demo mode (`netleash --demo`) exercises the UI without Administrator rights.

Verified on a real, elevated installation (Windows 11):
- per-program traffic monitoring, with programs matched to their real paths
- the WinDivert driver loading (`netleash --check-windivert`)
- upload and download limits on a browser, through WinDivert
- the installer, the startup task, the desktop shortcut and the NetLimiter import

Not yet verified on a real installation:
- **Blocking:** block a browser, check that pages stop loading, then unblock it.
- **Connections panel:** whether local and remote addresses are shown the right
  way round. `etw::parse` assumes `daddr` is the remote end for both send and
  receive; compare with `netstat -ano`.
- **QoS fallback** (used only without WinDivert). On PCs that aren't joined to a
  domain, Windows may ignore local QoS policies unless
  `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS` has `"Do not use NLA"="1"`.
- **Clean-up after uninstalling:** `sc.exe query WinDivert` should report that the
  service isn't running or doesn't exist. Use `sc.exe` in PowerShell; plain `sc` is `Set-Content` there.
- **Starting at boot after a restart.**
- **simplewall import** against a profile saved by simplewall itself. The
  parser follows simplewall's source (3.x, profile version 3 to 6) and is tested
  with sample data; the Windows Firewall import has been previewed against a
  real rule store, but not yet applied.

Reports from other PCs are welcome. Please open an issue.

## Building from source

Requires Rust (<https://rustup.rs>). `rust-toolchain.toml` pins the GNU toolchain,
which links with its own bundled MinGW, so you don't need Visual Studio Build Tools.

```powershell
cargo test
cargo run -- --demo --open      # the UI with synthetic traffic, no Administrator rights needed
.\run-elevated.ps1              # the real thing: builds, asks for UAC, opens the UI
.\package.ps1                   # tests, then builds dist\NetLeash-<version>.zip
```

Options: `--port N` (default 5199), `--data-dir DIR` (default `%ProgramData%\NetLeash`),
`--windivert DIR`, `--open`, `--demo`, and `--check-windivert`, which tests that
WinDivert loads and its driver starts, then exits.

**WinDivert for development builds.** WinDivert isn't in the repository. To run
with it from the source folder:

1. Exclude `<repo>\vendor\WinDivert-2.2.2-A` in Windows Security, as described above.
2. Run `.\fetch-windivert.ps1`. It downloads the official 2.2.2 release and
   refuses it unless its SHA-256 is `63CB4176…5F3F15`.
3. Run `netleash --check-windivert` from an elevated prompt.

NetLeash looks for `WinDivert.dll` and `WinDivert64.sys` in `--windivert DIR`,
then `<exe dir>\windivert`, then `vendor\WinDivert-2.2.2-A\x64` above the exe.

**WinDivert provenance**, checked for 2.2.2:
- `WinDivert64.sys` has a valid Authenticode signature: an EV certificate issued
  by Sectigo to 成都密思听科技有限公司, a company in Chengdu. That's the signer
  of the official release asset; the WinDivert author doesn't sign it personally.
- `WinDivert.dll` isn't signed. Its source is public if you'd rather build it yourself.
- `src/windivert.rs` binds only six functions. Their signatures, the constants and
  the `WINDIVERT_ADDRESS` layout were checked against the release's `windivert.h`.

### Source layout

```
src/main.rs       startup, arguments, 1 s clock, shutdown
src/state.rs      counters, rules, usage history (no OS calls)
src/etw.rs        Kernel-Network ETW session and event parser
src/wfp.rs        WFP dynamic-session block filters
src/shaper.rs     WinDivert token-bucket limiter
src/windivert.rs  runtime-loaded WinDivert bindings, packet header parser
src/qos.rs        NetQosPolicy upload limits (fallback)
src/enforce.rs    rules -> WFP + limiter (or QoS)
src/catalog.rs    "Find programs": history + open sockets + firewall rules, version-info names
src/nlimport.rs   NetLimiter 5 settings importer, shared import plan and merge
src/fwimport.rs   Windows Firewall block rule importer
src/swimport.rs   simplewall profile importer
src/pathglob.rs   wildcard program paths
src/conns.rs      connection tables, closing connections
src/sys.rs        elevation, time, process paths, Ctrl+C
src/web.rs        HTTP API and the embedded UI
src/demo.rs       synthetic traffic for --demo
ui/index.html     the UI
installer/        install.ps1, uninstall.ps1, Install.cmd, README.txt
```

## Roadmap

- A token-protected API, and running as a Windows service with the UI as an unprivileged client
- Splitting `svchost.exe` traffic by Windows service
- An "ask" mode that prompts when an unknown program first connects
- Global limits, per-connection limits and schedules
- Batched packet I/O in the limiter, if throughput needs it
- A tray icon

## Licence

NetLeash is released under the [MIT licence](LICENSE).

WinDivert isn't part of NetLeash and isn't distributed with it. The installer
downloads it from its official release if you choose to install it. WinDivert
was written by basil ([reqrypt.org](https://reqrypt.org/windivert.html)) and is
dual-licensed under LGPL-3.0 or GPL-2.0. Its licence is installed next to it.
