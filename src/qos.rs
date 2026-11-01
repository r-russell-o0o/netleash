//! Upload limiting via Windows Policy-based QoS (the `NetQosPolicy` cmdlets),
//! which throttles outbound traffic per executable in the built-in
//! QoS Packet Scheduler. No driver of ours is involved.
//!
//! Policies go in the `ActiveStore`, which is not persisted: a reboot clears
//! them even if NetLeash never got the chance to.

use crate::state::Rule;
use std::process::Command;

const PREFIX: &str = "NetLeash-";

/// Quote a value as a PowerShell single-quoted literal.
fn ps_quote(s: &str) -> Result<String, String> {
    if s.chars().any(|c| c.is_control()) {
        return Err(format!("refusing path with control characters: {s:?}"));
    }
    Ok(format!("'{}'", s.replace('\'', "''")))
}

/// The PowerShell script that replaces all our policies with `rules`' limits.
pub fn script(rules: &[Rule]) -> Result<String, String> {
    let mut s = format!(
        "$ErrorActionPreference = 'Stop'\n\
         Get-NetQosPolicy -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.Name -like '{PREFIX}*' }} | \
         ForEach-Object {{ Remove-NetQosPolicy -Name $_.Name -PolicyStore ActiveStore -Confirm:$false }}\n"
    );
    for (i, r) in rules.iter().enumerate() {
        let Some(bytes) = r.up_limit else { continue };
        if r.blocks_all() {
            continue; // blocked outright; a throttle would be redundant
        }
        let bits = bytes.saturating_mul(8).max(8);
        s += &format!(
            "New-NetQosPolicy -Name '{PREFIX}{i}' -AppPathNameMatchCondition {} \
             -ThrottleRateActionBitsPerSecond {bits} -PolicyStore ActiveStore -Confirm:$false | Out-Null\n",
            ps_quote(&r.path)?
        );
    }
    Ok(s)
}

fn run(script: &str) -> Result<(), String> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "-",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(script.as_bytes())?;
            child.wait_with_output()
        })
        .map_err(|e| format!("could not run powershell: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "NetQosPolicy: {}",
            err.trim().lines().next().unwrap_or("failed")
        ))
    }
}

pub fn apply(rules: &[Rule]) -> Result<(), String> {
    run(&script(rules)?)
}

pub fn clear() -> Result<(), String> {
    apply(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_quotes_paths_and_skips_blocked() {
        let rules = vec![
            Rule {
                path: r"C:\Bob's Apps\up.exe".into(),
                up_limit: Some(125_000),
                ..Default::default()
            },
            Rule {
                path: r"C:\x.exe".into(),
                block_in: true,
                block_out: true,
                up_limit: Some(1),
                ..Default::default()
            },
        ];
        let s = script(&rules).unwrap();
        assert!(s.contains(r"-AppPathNameMatchCondition 'C:\Bob''s Apps\up.exe'"));
        assert!(s.contains("-ThrottleRateActionBitsPerSecond 1000000"));
        assert!(!s.contains(r"C:\x.exe"));
        let bad = Rule {
            path: "C:\\a.exe'\n; Remove-Item C:\\".into(),
            up_limit: Some(1),
            ..Default::default()
        };
        assert!(script(&[bad]).is_err());
    }
}
