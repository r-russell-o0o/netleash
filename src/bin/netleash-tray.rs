//! NetLeash tray helper: an icon in the notification area with the current
//! speeds as its tooltip, and a notification when a program uses the network
//! for the first time. Left click opens NetLeash; right click shows a menu.
//!
//! The NetLeash service runs as SYSTEM and can't draw on anyone's desktop, so
//! this small program runs in each user's session (started at logon by the
//! installer). It only reads http://127.0.0.1:<port>/api/tray and changes
//! nothing; opening the UI is left to the browser.
//!
//!   netleash-tray.exe [--port 5199]

#![windows_subsystem = "windows"]

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const WM_TRAY: u32 = WM_APP + 1;
const POLL_TIMER: usize = 1;
const POLL_MS: u32 = 2000;
const CMD_OPEN: usize = 1;
const CMD_EXIT: usize = 2;

struct Tray {
    hwnd: HWND,
    icon: HICON,
    port: u16,
    /// Last alert sequence number seen; None until the first poll.
    seq: Option<u64>,
    taskbar_created: u32,
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copy text into a fixed UTF-16 buffer, truncated and NUL-terminated.
fn fill(buf: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(buf.len() - 1).collect();
    buf[..w.len()].copy_from_slice(&w);
    buf[w.len()] = 0;
}

fn fmt_rate(bytes: f64) -> String {
    let units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let (mut v, mut i) = (bytes, 0);
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{v:.0} {}", units[i])
    } else if v < 10.0 {
        format!("{v:.1} {}", units[i])
    } else {
        format!("{v:.0} {}", units[i])
    }
}

/// GET /api/tray from the local service. Plain HTTP over loopback, no TLS.
fn fetch(port: u16, since: u64) -> Option<serde_json::Value> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(s, "GET /api/tray?since={since} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").ok()?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n")?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return None;
    }
    serde_json::from_str(body).ok()
}

fn base_data(t: &Tray) -> NOTIFYICONDATAW {
    let mut d: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    d.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    d.hWnd = t.hwnd;
    d.uID = 1;
    d
}

fn add_icon(t: &Tray) {
    let mut d = base_data(t);
    d.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
    d.uCallbackMessage = WM_TRAY;
    d.hIcon = t.icon;
    fill(&mut d.szTip, "NetLeash");
    unsafe {
        Shell_NotifyIconW(NIM_ADD, &d);
        d.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &d);
    }
}

fn set_tip(t: &Tray, tip: &str) {
    let mut d = base_data(t);
    d.uFlags = NIF_TIP | NIF_SHOWTIP;
    fill(&mut d.szTip, tip);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

fn notify(t: &Tray, title: &str, text: &str) {
    let mut d = base_data(t);
    d.uFlags = NIF_INFO;
    d.dwInfoFlags = NIIF_USER;
    d.hBalloonIcon = t.icon;
    fill(&mut d.szInfoTitle, title);
    fill(&mut d.szInfo, text);
    unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
}

fn open_ui(port: u16, anchor: &str) {
    let url = wide(&format!("http://127.0.0.1:{port}/{anchor}"));
    let verb = wide("open");
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            url.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
}

fn poll(t: &mut Tray) {
    let Some(v) = fetch(t.port, t.seq.unwrap_or(u64::MAX)) else {
        set_tip(t, "NetLeash\nService not running");
        return;
    };
    let rate = |k: &str| v[k].as_f64().unwrap_or(0.0);
    let open = v["open_alerts"].as_u64().unwrap_or(0);
    let mut tip = format!(
        "NetLeash\n↓ {}   ↑ {}",
        fmt_rate(rate("down_rate")),
        fmt_rate(rate("up_rate"))
    );
    if open > 0 {
        tip += &format!(
            "\n{open} new program{} to review",
            if open == 1 { "" } else { "s" }
        );
    }
    set_tip(t, &tip);

    let seq = v["seq"].as_u64().unwrap_or(0);
    match t.seq {
        // First poll after logon: one summary instead of replaying old alerts.
        None if open > 0 => notify(
            t,
            "NetLeash",
            &format!(
                "{open} new program{} waiting for your decision. Click to review.",
                if open == 1 { " is" } else { "s are" }
            ),
        ),
        Some(prev) if seq > prev => {
            let new = v["new"].as_array().cloned().unwrap_or_default();
            let blocked = new
                .iter()
                .any(|a| a["auto_blocked"].as_bool() == Some(true));
            let names: Vec<String> = new
                .iter()
                .filter_map(|a| a["name"].as_str().map(String::from))
                .collect();
            let what = match names.as_slice() {
                [one] => format!("{one} started using the network."),
                [] => "A new program started using the network.".into(),
                many => format!(
                    "{} and {} more started using the network.",
                    many[0],
                    many.len() - 1
                ),
            };
            let then = if blocked {
                " Blocked until you allow it. Click to review."
            } else {
                " Click to review."
            };
            notify(t, "New program on the network", &(what + then));
        }
        _ => {}
    }
    t.seq = Some(seq);
}

fn show_menu(t: &Tray) {
    unsafe {
        let menu = CreatePopupMenu();
        let open = wide("Open NetLeash");
        let exit = wide("Exit tray icon");
        AppendMenuW(menu, MF_STRING, CMD_OPEN, open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_EXIT, exit.as_ptr());
        SetMenuDefaultItem(menu, CMD_OPEN as u32, 0);
        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        SetForegroundWindow(t.hwnd); // so the menu closes when clicking elsewhere
        TrackPopupMenu(
            menu,
            TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            t.hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let handled = TRAY.with(|cell| {
        let mut guard = cell.borrow_mut();
        let t = guard.as_mut()?;
        match msg {
            WM_TIMER if wp == POLL_TIMER => poll(t),
            WM_TRAY => match (lp as u32) & 0xFFFF {
                NIN_SELECT | WM_LBUTTONUP => open_ui(t.port, ""),
                NIN_BALLOONUSERCLICK => open_ui(t.port, "#alerts"),
                WM_CONTEXTMENU | WM_RBUTTONUP => show_menu(t),
                _ => {}
            },
            WM_COMMAND => match wp & 0xFFFF {
                CMD_OPEN => open_ui(t.port, ""),
                CMD_EXIT => unsafe {
                    DestroyWindow(hwnd);
                },
                _ => {}
            },
            WM_DESTROY => {
                let d = base_data(t);
                unsafe {
                    Shell_NotifyIconW(NIM_DELETE, &d);
                    PostQuitMessage(0);
                }
            }
            // Explorer restarted: the notification area forgot our icon.
            m if m == t.taskbar_created && m != 0 => add_icon(t),
            _ => return None,
        }
        Some(0)
    });
    handled.unwrap_or_else(|| unsafe { DefWindowProcW(hwnd, msg, wp, lp) })
}

fn main() {
    let mut port = 5199u16;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--port" {
            port = args.next().and_then(|v| v.parse().ok()).unwrap_or(port);
        }
    }
    unsafe {
        // One tray icon per user session.
        let name = wide("Local\\NetLeashTray");
        CreateMutexW(std::ptr::null(), 0, name.as_ptr());
        if GetLastError() == ERROR_ALREADY_EXISTS {
            return;
        }

        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("NetLeashTrayWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinst,
            lpszClassName: class.as_ptr(),
            ..std::mem::zeroed()
        };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );

        // netleash.ico sits next to this program; fall back to a stock icon.
        let ico = std::env::current_exe()
            .map(|p| p.with_file_name("netleash.ico"))
            .unwrap_or_default();
        let ico_w = wide(&ico.display().to_string());
        let mut icon = LoadImageW(
            std::ptr::null_mut(),
            ico_w.as_ptr(),
            IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON),
            LR_LOADFROMFILE,
        ) as HICON;
        if icon.is_null() {
            icon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
        }
        let taskbar_created = RegisterWindowMessageW(wide("TaskbarCreated").as_ptr());

        let tray = Tray {
            hwnd,
            icon,
            port,
            seq: None,
            taskbar_created,
        };
        add_icon(&tray);
        TRAY.with(|c| *c.borrow_mut() = Some(tray));
        TRAY.with(|c| poll(c.borrow_mut().as_mut().unwrap()));
        SetTimer(hwnd, POLL_TIMER, POLL_MS, None);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_and_text_buffers() {
        assert_eq!(fmt_rate(512.0), "512 B/s");
        assert_eq!(fmt_rate(1536.0), "1.5 KB/s");
        assert_eq!(fmt_rate(50.0 * 1024.0 * 1024.0), "50 MB/s");
        let mut buf = [0u16; 5];
        fill(&mut buf, "abcdefgh");
        assert_eq!(&buf, &[97, 98, 99, 100, 0]);
    }
}
