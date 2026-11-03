# Changelog

## 0.2.0 (2026-11-03)

Updating keeps your rules: run **Install NetLeash.exe** from the new download.

**Download limits that hold.** A 200 KB/s limit now gives 200 KB/s, also
with a browser speed test that opens dozens of connections. Before, the
same test got 20 to 70 KB/s.
- Each connection waits in its own queue and the queues take turns, so a
  busy download can't hold up a small one.
- Packets wait (up to a second) instead of being dropped. When a queue is
  full, the connection holding the most loses a packet, not one that has
  only a packet or two in flight.
- Acknowledgements are never held back, so a download limit no longer
  slows the same program's uploads.
- A busy PC no longer makes a limit undershoot: time the limiter missed is
  made up.
- `netleash.log` shows every 10 seconds what each limit let through.

**Blocking a browser no longer locks you out of NetLeash.** Connections
to the PC itself (127.0.0.1) always stay open, so the NetLeash page keeps
working in a blocked browser. If a change can't be saved, the page now
says so and shows the setting that is really in force.

**Installer.**
- The download now opens with **Install NetLeash.exe** (with the NetLeash
  icon) and README.txt; everything else is in the `files` folder.
- An update no longer fails when a NetLeash file is still in use, and a
  failed update starts NetLeash again instead of leaving the PC without
  its rules.
- The page header shows the version you run.

## 0.1.0 (2026-11-01)

First release.
