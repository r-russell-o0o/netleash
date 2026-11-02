NetLeash driver test kit (for a test VM only, never your own PC)
==============================================================

The driver is signed with a home-made test certificate, which Windows only
accepts with "test signing" on. That setting belongs in a throwaway VM.

1. In VMware, take a snapshot of the "Windows 10 x64" VM first, so you can
   go back to it at any time.
2. Start the VM and copy this whole folder into it, e.g. to C:\nltest.
3. In the VM, open PowerShell as Administrator and run:

     Set-ExecutionPolicy -Scope Process Bypass
     C:\nltest\1-prepare-vm.ps1

   Reboot the VM when it says so. (Add -Verifier to also run Microsoft's
   Driver Verifier on the driver: stricter, and a bluescreen in the VM if
   it finds a bug, which is exactly what the VM is for.)
4. After the reboot, again as Administrator:

     Set-ExecutionPolicy -Scope Process Bypass
     C:\nltest\2-test-driver.ps1

   It takes about two minutes and needs the VM's internet connection. It
   prints PASS/FAIL lines and writes results.txt. Send me results.txt.

If the VM bluescreens: restart it and send the newest file in
C:\Windows\Minidump (and results.txt if there is one).

To undo everything, revert to the snapshot.
