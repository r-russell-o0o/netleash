NetLeash - per-program network monitor, firewall and bandwidth limiter
=====================================================================

INSTALL
  1. Double-click Install.cmd and approve the Administrator prompt.
  2. Answer the WinDivert question (see below).
  NetLeash then starts automatically at every boot (before anyone logs in)
  and restarts itself within 5 minutes if it ever stops.

DOWNLOAD LIMITS NEED ONE MANUAL STEP: A DEFENDER EXCLUSION
  Monitoring, blocking and rules work without this. Upload/download limits
  need the open-source WinDivert driver, and Microsoft Defender deletes it
  (as "potentially unwanted", because malware uses it too) unless YOU
  exclude its folder. NetLeash will not change Defender settings for you:
  a program that adds its own antivirus exclusion is behaving like malware.

  When the installer asks about WinDivert:
    1. Press O to open Windows Security (or open it from the Start menu)
    2. Virus & threat protection > Manage settings
    3. Exclusions > Add or remove exclusions > Add an exclusion > Folder
    4. Choose:  C:\Program Files\NetLeash\windivert
       (the installer has already created it)
    5. Back in the installer, press Y. If you forgot and Defender removed
       the download, add the exclusion now and press R to retry.

  It worked if the installer prints "WinDivert installed". In the UI,
  the "Download limits" chip turns green.
  Skipped it? Add the exclusion and run Install.cmd again at any time.
  Your rules are kept.

  Options (run install.ps1 from an Administrator PowerShell):
    -WinDivert          install WinDivert without asking (exclusion added first)
    -NoWinDivert        never install WinDivert
    -WinDivertZip FILE  use a downloaded WinDivert-2.2.2-A.zip (offline PCs)
    -Port N             UI port (default 5199)

USE
  Double-click the NetLeash icon on the desktop (also in the Start menu),
  or open http://127.0.0.1:5199/ in any browser.
  "Import from NetLimiter..." copies NetLimiter 5 block rules and limits, if
  installed. "Import from..." does the same for Windows Firewall block rules
  and simplewall's blocked programs. Each shows a preview first. Windows
  Firewall rules meant for some network types only (e.g. Public) block on
  every network in NetLeash; the preview lists them.
  Click a program's row for its connections, a schedule (block or limit only
  at certain times) and a data allowance per day or month.
  New programs that use the network show up above the list and in the tray
  icon; choose "Block them until I allow them" to be stricter.

FILES
  Program:   C:\Program Files\NetLeash
  Rules, usage history, log (netleash.log):  C:\ProgramData\NetLeash

UNINSTALL
  Settings > Apps > Installed apps > NetLeash > Uninstall,
  or run uninstall.ps1 (add -RemoveData to delete rules and history too).
  Afterwards, remove the WinDivert exclusion in Windows Security
  (same place as step 3 above) if you added one.
