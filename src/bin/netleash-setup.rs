//! "Install NetLeash.exe" in the package: runs files\install.ps1 next to it.
//! It does exactly what a batch file would, but an .exe can carry the
//! NetLeash icon and ask for Administrator rights itself (package.ps1 adds the
//! icon and a requireAdministrator manifest), so buyers see at a glance which
//! file installs NetLeash.
//!
//!   "Install NetLeash.exe" [install.ps1 options, e.g. -WinDivert]

use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let script = std::env::current_exe()
        .ok()
        .and_then(|p| Some(p.parent()?.join("files").join("install.ps1")));
    let problem = match script {
        Some(s) if s.exists() => match Command::new("powershell.exe")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&s)
            .args(std::env::args_os().skip(1))
            .status()
        {
            Ok(st) => return ExitCode::from(st.code().unwrap_or(1) as u8),
            Err(e) => format!("Could not start PowerShell: {e}"),
        },
        _ => "files\\install.ps1 is missing. Unzip the whole NetLeash download \
              (including the files folder) and run Install NetLeash.exe from there."
            .into(),
    };
    eprintln!("{problem}");
    eprintln!("\nPress Enter to close.");
    let _ = std::io::stdin().read_line(&mut String::new());
    ExitCode::from(1)
}
