//! Wildcard program paths, as NetLimiter allows them, e.g.
//! `C:\Program Files\WindowsApps\Adobe.Lightroom_*_x64__ynb6jyjzte8ga\lightroom.exe`,
//! where `*` stands for a version that changes with each update.
//!
//! Windows can only block a concrete file, so a pattern is expanded to the
//! files that match it right now; callers re-expand periodically to pick up
//! updates. `*` matches any run of characters within one path component, `?`
//! one character; matching is case-insensitive like the file system.

use std::path::PathBuf;

/// Stop runaway patterns such as `C:\*\*\*.exe`.
const MAX_MATCHES: usize = 256;

pub fn has_wildcard(p: &str) -> bool {
    p.contains(['*', '?'])
}

/// Does `name` match `pattern` (one path component)?
pub fn matches(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    // Iterative wildcard match with backtracking to the last '*'.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

/// Existing files matching `pattern`. A path without wildcards is returned
/// as-is, whether or not it exists, so errors about it stay visible.
pub fn expand(pattern: &str) -> Vec<String> {
    if !has_wildcard(pattern) {
        return vec![pattern.to_string()];
    }
    let mut parts = pattern.split(['\\', '/']);
    let drive = parts.next().unwrap_or("");
    if drive.is_empty() || has_wildcard(drive) {
        return Vec::new(); // UNC or relative patterns are not supported
    }
    let parts: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();
    let mut current = vec![PathBuf::from(format!("{drive}\\"))];
    for (i, part) in parts.iter().enumerate() {
        let last = i + 1 == parts.len();
        let mut next = Vec::new();
        for base in &current {
            if has_wildcard(part) {
                let Ok(entries) = std::fs::read_dir(base) else {
                    continue;
                };
                for e in entries.flatten() {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if matches(part, &name) {
                        next.push(base.join(name));
                    }
                }
            } else {
                let p = base.join(part);
                if (last && p.is_file()) || (!last && p.is_dir()) {
                    next.push(p);
                }
            }
            if next.len() >= MAX_MATCHES {
                break;
            }
        }
        current = next;
    }
    let mut out: Vec<String> = current
        .into_iter()
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching() {
        assert!(matches(
            "adobe.lightroom_*_x64__ynb",
            "Adobe.Lightroom_8.1.0_x64__YNB"
        ));
        assert!(matches("*.exe", "a.exe"));
        assert!(matches("a?c", "abc"));
        assert!(matches("*", ""));
        assert!(!matches("*.exe", "a.dll"));
        assert!(!matches("a?c", "ac"));
        assert!(matches("*a*b", "xxaxxbxb"));
    }

    #[test]
    fn expands_against_the_file_system() {
        let root = std::env::temp_dir().join(format!("netleash-glob-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for v in ["App_1.0_x64", "App_2.0_x64", "Other_1.0_x64"] {
            std::fs::create_dir_all(root.join(v)).unwrap();
            std::fs::write(root.join(v).join("run.exe"), b"").unwrap();
        }
        let pattern = format!("{}\\app_*_x64\\RUN.exe", root.display());
        let got = expand(&pattern);
        assert_eq!(got.len(), 2, "{got:?}");
        // Wildcard parts take the real directory name; literal parts keep the
        // pattern's spelling (Windows paths are case-insensitive).
        assert!(
            got.iter()
                .all(|p| p.contains("App_") && p.ends_with("RUN.exe"))
        );
        assert!(expand(&format!("{}\\nothing_*\\run.exe", root.display())).is_empty());
        let plain = r"C:\does\not\exist.exe";
        assert_eq!(expand(plain), vec![plain.to_string()]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
