//! Small Win32 helpers: elevation check, local time, process image paths,
//! and Ctrl+C handling.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, SYSTEMTIME};
use windows_sys::Win32::Security::{
    GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
};
use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        );
        CloseHandle(token);
        ok != 0 && elev.TokenIsElevated != 0
    }
}

fn local_time() -> SYSTEMTIME {
    let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    t
}

/// Local date as `YYYY-MM-DD`, used as the usage-history key.
pub fn local_date() -> String {
    let t = local_time();
    format!("{:04}-{:02}-{:02}", t.wYear, t.wMonth, t.wDay)
}

/// Local weekday and time, for schedules and quotas.
pub fn local_now() -> crate::timed::Now {
    let t = local_time();
    crate::timed::Now {
        weekday: ((t.wDayOfWeek + 6) % 7) as u8, // Windows: 0 = Sunday
        minute: t.wHour * 60 + t.wMinute,
        today: format!("{:04}-{:02}-{:02}", t.wYear, t.wMonth, t.wDay),
    }
}

pub fn local_time_hms() -> String {
    let t = local_time();
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

/// Full image path of a process, or `None` if it has exited or is inaccessible.
pub fn process_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Executable file name (no path) from the system process list. Works for
/// processes we may not open, e.g. services when running without elevation.
fn process_exe_name(pid: u32) -> Option<String> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap.is_null() || snap as isize == -1 {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            if e.th32ProcessID == pid {
                let len = e
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(e.szExeFile.len());
                found = Some(String::from_utf16_lossy(&e.szExeFile[..len]));
                break;
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        found
    }
}

/// PID -> image path, cached briefly. Lookups happen for every network event,
/// so this must be cheap; the TTL bounds the damage of PID reuse.
pub struct ProcessNames {
    cache: Mutex<HashMap<u32, (String, Instant)>>,
}

const NAME_TTL: Duration = Duration::from_secs(30);

impl ProcessNames {
    pub fn new() -> Self {
        ProcessNames {
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn resolve(&self, pid: u32) -> String {
        match pid {
            0 => return "Idle".into(),
            4 => return "System".into(),
            _ => {}
        }
        let now = Instant::now();
        if let Some((p, at)) = self.cache.lock().unwrap().get(&pid)
            && now.duration_since(*at) < NAME_TTL
        {
            return p.clone();
        }
        let path = process_path(pid)
            .or_else(|| process_exe_name(pid).map(|n| format!("{n} (pid {pid}, path hidden)")))
            .unwrap_or_else(|| format!("pid {pid} (exited)"));
        let mut c = self.cache.lock().unwrap();
        if c.len() > 4096 {
            c.retain(|_, (_, at)| now.duration_since(*at) < NAME_TTL);
        }
        c.insert(pid, (path.clone(), now));
        path
    }
}

static ON_EXIT: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

unsafe extern "system" fn ctrl_handler(_ctrl_type: u32) -> i32 {
    if let Some(f) = ON_EXIT.get() {
        f();
    }
    std::process::exit(0);
}

/// Run `f` on Ctrl+C, Ctrl+Break, console close, logoff or shutdown, then exit.
pub fn on_exit(f: impl Fn() + Send + Sync + 'static) {
    let _ = ON_EXIT.set(Box::new(f));
    unsafe { SetConsoleCtrlHandler(Some(ctrl_handler), 1) };
}
