//! The program catalog: every program with some evidence of using the
//! network, so the user can block or limit one without knowing its path.
//!
//! Sources, each read-only:
//! - **history**: programs in NetLeash's own usage history (up to 120 days)
//! - **running**: processes that own a TCP/UDP socket right now
//! - **firewall**: programs named in Windows Firewall rules (most network
//!   programs register one when installed, so this finds programs that
//!   haven't run since NetLeash was installed)
//!
//! Each program is labelled with the description and company from its
//! version resource ("Google Chrome", "Google LLC").

use crate::conns;
use crate::state::{Rule, State, app_key, file_name};
use crate::sys::{ProcessNames, wide};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegCloseKey, RegEnumValueW, RegOpenKeyExW,
};

// ---- version information ---------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize)]
pub struct VerInfo {
    pub description: Option<String>,
    pub company: Option<String>,
}

fn ver_string(block: &[u8], lang: &str, name: &str) -> Option<String> {
    let query = wide(&format!("\\StringFileInfo\\{lang}\\{name}"));
    let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            block.as_ptr() as *const _,
            query.as_ptr(),
            &mut ptr,
            &mut len,
        )
    };
    if ok == 0 || ptr.is_null() || len == 0 {
        return None;
    }
    // `len` counts UTF-16 characters, including the terminator.
    let s = unsafe { std::slice::from_raw_parts(ptr as *const u16, len as usize) };
    let s = String::from_utf16_lossy(s);
    let s = s.trim_end_matches('\0').trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Read FileDescription and CompanyName from an executable's version resource.
fn read_ver_info(path: &str) -> VerInfo {
    let w = wide(path);
    let mut handle = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(w.as_ptr(), &mut handle) };
    if size == 0 {
        return VerInfo::default();
    }
    let mut block = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(w.as_ptr(), 0, size, block.as_mut_ptr() as *mut _) } == 0 {
        return VerInfo::default();
    }
    // The file says which language/codepage its strings are in; fall back to
    // the two most common US-English tables.
    let mut langs = Vec::new();
    let query = wide("\\VarFileInfo\\Translation");
    let mut ptr: *mut core::ffi::c_void = std::ptr::null_mut();
    let mut len = 0u32;
    if unsafe {
        VerQueryValueW(
            block.as_ptr() as *const _,
            query.as_ptr(),
            &mut ptr,
            &mut len,
        )
    } != 0
        && !ptr.is_null()
        && len >= 4
    {
        let pairs = unsafe { std::slice::from_raw_parts(ptr as *const u16, (len / 2) as usize) };
        for p in pairs.as_chunks::<2>().0 {
            langs.push(format!("{:04x}{:04x}", p[0], p[1]));
        }
    }
    langs.extend(["040904b0".into(), "040904e4".into()]);
    let pick = |name| langs.iter().find_map(|l| ver_string(&block, l, name));
    VerInfo {
        description: pick("FileDescription").or_else(|| pick("ProductName")),
        company: pick("CompanyName"),
    }
}

static VER_CACHE: OnceLock<Mutex<HashMap<String, VerInfo>>> = OnceLock::new();

/// Cached `read_ver_info`. Executables rarely change their description, and a
/// stale one after an update is harmless.
pub fn ver_info(path: &str) -> VerInfo {
    let key = app_key(path);
    let cache = VER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&key) {
        return v.clone();
    }
    let v = if path.contains(['\\', '/']) {
        read_ver_info(path)
    } else {
        VerInfo::default()
    };
    cache.lock().unwrap().insert(key, v.clone());
    v
}

// ---- Windows Firewall rules ------------------------------------------------------

pub fn expand_env(s: &str) -> String {
    if !s.contains('%') {
        return s.to_string();
    }
    let src = wide(s);
    let mut buf = vec![0u16; 1024];
    let n = unsafe { ExpandEnvironmentStringsW(src.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize > buf.len() {
        return s.to_string();
    }
    String::from_utf16_lossy(&buf[..n as usize - 1])
}

/// From one stored firewall rule (`v2.33|Action=Allow|Dir=In|App=C:\x.exe|...`),
/// the program path and a short label such as "Allow In".
pub fn parse_firewall_rule(rule: &str) -> Option<(String, String)> {
    let mut app = None;
    let (mut action, mut dir) = ("", "");
    for field in rule.split('|') {
        match field.split_once('=') {
            Some(("App", v)) => app = Some(v),
            Some(("Action", v)) => action = v,
            Some(("Dir", v)) => dir = v,
            _ => {}
        }
    }
    let app = app?.trim();
    if !app.to_lowercase().ends_with(".exe") {
        return None; // "System" and service-only rules have no program file
    }
    Some((
        app.to_string(),
        format!("{action} {dir}").trim().to_string(),
    ))
}

/// Every rule stored in Windows Firewall's registry key, as raw
/// `v2.33|Action=...|` strings. Reading the key needs Administrator rights.
pub fn firewall_rule_strings() -> Result<Vec<String>, String> {
    let sub = wide(
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
    );
    let mut key: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) };
    if rc != 0 {
        return Err(format!(
            "could not open Windows Firewall's rules in the registry (error {rc}; needs Administrator rights)"
        ));
    }
    let mut out = Vec::new();
    let mut name = vec![0u16; 512];
    let mut data = vec![0u8; 16 * 1024];
    for index in 0.. {
        let mut name_len = name.len() as u32;
        let mut data_len = data.len() as u32;
        let mut ty = 0u32;
        let rc = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if rc == 234 {
            continue; // ERROR_MORE_DATA: an unusually long rule; skip it
        }
        if rc != 0 {
            break; // ERROR_NO_MORE_ITEMS or a real error
        }
        if ty != REG_SZ {
            continue;
        }
        let units: Vec<u16> = data[..data_len as usize]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        out.push(
            String::from_utf16_lossy(&units)
                .trim_end_matches('\0')
                .to_string(),
        );
    }
    unsafe { RegCloseKey(key) };
    Ok(out)
}

/// Program paths in Windows Firewall rules, with their rule labels.
/// Without Administrator rights this is empty.
fn firewall_programs() -> HashMap<String, (String, Vec<String>)> {
    let mut out: HashMap<String, (String, Vec<String>)> = HashMap::new();
    for text in firewall_rule_strings().unwrap_or_default() {
        if let Some((app, label)) = parse_firewall_rule(&text) {
            let path = expand_env(&app);
            let e = out
                .entry(app_key(&path))
                .or_insert_with(|| (path, Vec::new()));
            if !label.is_empty() && !e.1.contains(&label) {
                e.1.push(label);
            }
        }
    }
    out
}

// ---- the catalog -----------------------------------------------------------------

#[derive(Serialize, Default)]
pub struct Program {
    pub key: String,
    pub path: String,
    pub file: String,
    #[serde(flatten)]
    pub info: VerInfo,
    /// Last day in the usage history, and bytes over the whole history.
    pub seen_day: Option<String>,
    pub seen_bytes: u64,
    pub running: bool,
    /// e.g. ["Allow In", "Block Out"]
    pub firewall: Vec<String>,
    pub exists: bool,
    pub rule: Option<Rule>,
}

/// Build the catalog. Takes a moment the first time (reading version
/// resources), then it's mostly cached.
/// The catalog entry for `path`, created if new. `None` for anything that
/// isn't a real path: "System", "Idle" or "x.exe (pid 5, path hidden)".
fn entry<'m>(map: &'m mut BTreeMap<String, Program>, path: &str) -> Option<&'m mut Program> {
    if !path.contains('\\') || path.contains("(pid ") {
        return None;
    }
    let key = app_key(path);
    Some(map.entry(key.clone()).or_insert_with(|| Program {
        key,
        path: path.to_string(),
        file: file_name(path),
        ..Default::default()
    }))
}

pub fn build(state: &State, names: &ProcessNames) -> Vec<Program> {
    let mut map: BTreeMap<String, Program> = BTreeMap::new();
    for (path, day, bytes) in state.usage_paths() {
        if let Some(p) = entry(&mut map, &path) {
            p.seen_day = Some(day);
            p.seen_bytes = bytes;
        }
    }
    let mut pids: Vec<u32> = conns::port_owners()
        .into_iter()
        .map(|(_, _, pid)| pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    for pid in pids {
        let path = names.resolve(pid);
        if let Some(p) = entry(&mut map, &path) {
            p.path = path; // a running process has the exact spelling
            p.running = true;
        }
    }
    for (_, (path, labels)) in firewall_programs() {
        if let Some(p) = entry(&mut map, &path) {
            p.firewall = labels;
        }
    }
    // Programs with rules are part of the catalog too, so it shows their state.
    for r in state.rules() {
        if let Some(p) = entry(&mut map, &r.path) {
            p.rule = Some(r);
        }
    }

    let mut out: Vec<Program> = map.into_values().collect();
    for p in &mut out {
        p.exists = Path::new(&p.path).is_file();
        if p.exists {
            p.info = ver_info(&p.path);
        }
        if p.rule.is_none() {
            p.rule = state.rule_for(&p.key);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_firewall_rules() {
        let r = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=%ProgramFiles%\\Steam\\steam.exe|Name=Steam|";
        assert_eq!(
            parse_firewall_rule(r),
            Some((r"%ProgramFiles%\Steam\steam.exe".into(), "Allow In".into()))
        );
        assert_eq!(
            parse_firewall_rule("v2.33|Action=Allow|App=System|Name=x|"),
            None
        );
        assert_eq!(
            parse_firewall_rule("v2.33|Action=Block|Dir=Out|Name=no app|"),
            None
        );
    }

    #[test]
    fn reads_version_info_of_a_windows_exe() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let v = read_ver_info(&format!(r"{root}\System32\notepad.exe"));
        assert!(v.description.is_some(), "{v:?}");
        assert!(
            v.company
                .as_deref()
                .is_some_and(|c| c.contains("Microsoft")),
            "{v:?}"
        );
        assert!(
            read_ver_info(r"C:\does\not\exist.exe")
                .description
                .is_none()
        );
    }

    #[test]
    fn expands_environment_variables() {
        let pf = std::env::var("ProgramFiles").unwrap();
        assert_eq!(expand_env(r"%ProgramFiles%\x.exe"), format!(r"{pf}\x.exe"));
        assert_eq!(expand_env(r"C:\plain.exe"), r"C:\plain.exe");
    }
}
