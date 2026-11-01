# Releasing NetLeash

## Before the first public release

Done:
- [x] MIT licence (`LICENSE`), with the licence and repository in `Cargo.toml`
- [x] README written for people who've never seen NetLeash, with no personal
      paths or machine-specific notes (the git history has none either)
- [x] Third-party notes: WinDivert's licence, and the NetLimiter trademark disclaimer

Still to decide or do:
- [ ] **Name.** A US trademark "NETLEASH" exists for computer software
      (serial 85277613, filed around 2011, for recovering lost or stolen phones).
      Check its status at <https://tsdr.uspto.gov/#caseNumber=85277613&caseType=SERIAL_NO&searchType=statusSearch>.
      If it's live, rename before publishing; that's far cheaper now than later.
- [ ] **Finish the testing status** in the README: blocking, the connections
      panel, clean-up after uninstalling, and starting at boot after a restart.
- [ ] **Code signing (optional).** Without it, SmartScreen warns about an unknown
      publisher. Options: leave it unsigned and say so (the README does);
      Azure Trusted Signing (a monthly fee, identity check required); or an
      OV/EV code-signing certificate. Sign `netleash.exe` and the `.ps1` files.
- [ ] **Security contact.** Enable GitHub's private vulnerability reporting:
      Settings > Code security > Private vulnerability reporting. That needs no email address.
- [ ] **Make the repo public:**
      `gh repo edit r-russell-o0o/netleash --visibility public --accept-visibility-change-consequences`
- [ ] **Domain (optional).** netleash.com is taken. netleash.app, .dev and .org had
      no DNS records on 2026-11-01. Point it at the GitHub repo, or at GitHub Pages.
- [ ] **Optional:** report the WinDivert detection to Microsoft as a false positive
      at <https://www.microsoft.com/wdsi/filesubmission>.

## Every release

1. Bump `version` in `Cargo.toml`.
2. `.\package.ps1`: runs the tests, builds `dist\NetLeash-<version>.zip` and prints its SHA-256.
3. Install the zip on a real PC, run through the README's testing list, and
   update the testing status if anything changed.
4. Commit, then tag and publish. Put the SHA-256 in the release notes:

   ```powershell
   git tag v<version>; git push origin v<version>
   gh release create v<version> dist\NetLeash-<version>.zip --title "NetLeash <version>" --notes "SHA-256: <hash>"
   ```

If WinDivert is ever updated, change the URL and hash in `installer/install.ps1`
and `fetch-windivert.ps1`. Then re-check the new `windivert.h` against `src/windivert.rs`.
