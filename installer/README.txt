NetLeash - per-program network monitor, firewall and bandwidth limiter
=====================================================================

INSTALL
  Double-click Install.cmd and approve the Administrator prompt.
  NetLeash then starts automatically at every boot (before anyone logs in)
  and restarts itself within 5 minutes if it ever stops.

  The installer asks whether to install WinDivert, the driver used for
  upload/download limits. It is open source, but Microsoft Defender flags it
  as "potentially unwanted" and deletes it unless you exclude its folder.
  The installer does not change Defender settings itself; when it asks, add
  the exclusion in Windows Security:
    Virus & threat protection > Manage settings > Exclusions >
    Add an exclusion > Folder > C:\Program Files\NetLeash\windivert
  Without WinDivert, blocking and upload limits still work; download limits
  don't. Run Install.cmd again at any time to add it.

  Options (run install.ps1 from an Administrator PowerShell):
    -WinDivert          install WinDivert without asking (exclusion added first)
    -NoWinDivert        never install WinDivert
    -WinDivertZip FILE  use a downloaded WinDivert-2.2.2-A.zip (offline PCs)
    -Port N             UI port (default 5199)

USE
  Double-click the NetLeash icon on the desktop (also in the Start menu),
  or open http://127.0.0.1:5199/ in any browser.
  "Import from NetLimiter..." copies NetLimiter 5 block rules, if installed.

FILES
  Program:   C:\Program Files\NetLeash
  Rules, usage history, log (netleash.log):  C:\ProgramData\NetLeash

UNINSTALL
  Settings > Apps > Installed apps > NetLeash > Uninstall,
  or run uninstall.ps1 (add -RemoveData to delete rules and history too).
  Afterwards, remove the WinDivert exclusion in Windows Security if you added one.
