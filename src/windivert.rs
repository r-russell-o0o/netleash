//! Minimal hand-written bindings to WinDivert 2.2 (https://reqrypt.org/windivert.html),
//! loaded at runtime from WinDivert.dll so NetLeash still runs without it.
//! Only the six functions we call are bound.
//!
//! WinDivert.dll installs and starts its signed kernel driver (WinDivert64.sys,
//! from the same folder) on first open. The driver unloads itself when the
//! last handle closes, so nothing stays resident after NetLeash exits.

use crate::sys::wide;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

pub const LAYER_NETWORK: i32 = 0;
pub const LAYER_FLOW: i32 = 2;
pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_RECV_ONLY: u64 = 0x0004;
pub const EVENT_FLOW_ESTABLISHED: u8 = 1;
const SHUTDOWN_BOTH: i32 = 3;
const PARAM_QUEUE_LENGTH: i32 = 0;
const PARAM_QUEUE_SIZE: i32 = 2;
/// Largest packet WinDivert can return (WINDIVERT_MTU_MAX).
pub const MTU_MAX: usize = 40 + 0xFFFF;

/// WINDIVERT_ADDRESS: 8-byte timestamp, a 32-bit field of bitfields, a reserved
/// word, then a 64-byte union whose meaning depends on the layer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    bits: u32,
    reserved: u32,
    data: [u8; 64],
}
const _: () = assert!(size_of::<Address>() == 80);

impl Address {
    pub fn zeroed() -> Self {
        Address {
            timestamp: 0,
            bits: 0,
            reserved: 0,
            data: [0; 64],
        }
    }
    pub fn event(&self) -> u8 {
        (self.bits >> 8) as u8
    }
    pub fn outbound(&self) -> bool {
        self.bits >> 17 & 1 == 1
    }
    // WINDIVERT_DATA_FLOW: EndpointId u64, ParentEndpointId u64, ProcessId u32,
    // LocalAddr u32[4], RemoteAddr u32[4], LocalPort u16, RemotePort u16, Protocol u8.
    // Ports are in host byte order.
    pub fn flow_pid(&self) -> u32 {
        u32::from_ne_bytes(self.data[16..20].try_into().unwrap())
    }
    pub fn flow_local_port(&self) -> u16 {
        u16::from_ne_bytes([self.data[52], self.data[53]])
    }
    pub fn flow_protocol(&self) -> u8 {
        self.data[56]
    }
}

type OpenFn = unsafe extern "C" fn(*const u8, i32, i16, u64) -> HANDLE;
type RecvFn = unsafe extern "C" fn(HANDLE, *mut u8, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(HANDLE, *const u8, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(HANDLE, i32) -> i32;
type CloseFn = unsafe extern "C" fn(HANDLE) -> i32;
type SetParamFn = unsafe extern "C" fn(HANDLE, i32, u64) -> i32;

pub struct Api {
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    set_param: SetParamFn,
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

/// Folders searched for WinDivert.dll + WinDivert64.sys, in order.
pub fn candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = explicit.map(Path::to_path_buf).into_iter().collect();
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        out.push(exe_dir.join("windivert"));
        // Running from target\{debug,release}: use the project's vendor folder.
        for dir in exe_dir.ancestors() {
            out.push(dir.join(r"vendor\WinDivert-2.2.2-A\x64"));
        }
    }
    out
}

pub fn load(explicit: Option<&Path>) -> Result<&'static Api, String> {
    API.get_or_init(|| {
        let dir = candidates(explicit)
            .into_iter()
            .find(|d| d.join("WinDivert.dll").is_file() && d.join("WinDivert64.sys").is_file())
            .ok_or("WinDivert.dll / WinDivert64.sys not found")?;
        let dll = wide(&dir.join("WinDivert.dll").to_string_lossy());
        unsafe {
            let m = LoadLibraryW(dll.as_ptr());
            if m.is_null() {
                return Err(format!(
                    "LoadLibrary({}) failed (error {})",
                    dir.display(),
                    GetLastError()
                ));
            }
            // Each export is looked up by name and cast to its declared C signature.
            macro_rules! sym {
                ($name:literal, $ty:ty) => {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(
                        GetProcAddress(m, concat!($name, "\0").as_ptr())
                            .ok_or(concat!("missing ", $name))?,
                    )
                };
            }
            Ok(Api {
                open: sym!("WinDivertOpen", OpenFn),
                recv: sym!("WinDivertRecv", RecvFn),
                send: sym!("WinDivertSend", SendFn),
                shutdown: sym!("WinDivertShutdown", ShutdownFn),
                close: sym!("WinDivertClose", CloseFn),
                set_param: sym!("WinDivertSetParam", SetParamFn),
            })
        }
    })
    .as_ref()
    .map_err(Clone::clone)
}

fn explain(err: u32) -> &'static str {
    match err {
        2 => "driver file not found next to WinDivert.dll",
        5 => "access denied (not elevated?)",
        87 => "invalid filter or parameter",
        577 => "driver signature rejected (Defender, HVCI or Secure Boot policy?)",
        654 => "an incompatible WinDivert driver version is already loaded",
        1060 => "driver service could not be created",
        1275 => "driver blocked from loading (check Defender / Core Isolation)",
        1753 => "Base Filtering Engine service is not running",
        _ => "",
    }
}

pub struct Handle {
    api: &'static Api,
    h: HANDLE,
}

// WinDivert handles may be used from several threads at once.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    pub fn open(
        api: &'static Api,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> Result<Self, String> {
        let f: Vec<u8> = filter.bytes().chain(std::iter::once(0)).collect();
        let h = unsafe { (api.open)(f.as_ptr(), layer, priority, flags) };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            let e = unsafe { GetLastError() };
            return Err(format!("WinDivertOpen failed (error {e}) {}", explain(e)));
        }
        Ok(Handle { api, h })
    }

    /// Raise WinDivert's own queue limits so bursts are not dropped before we see them.
    pub fn enlarge_queues(&self) {
        unsafe {
            (self.api.set_param)(self.h, PARAM_QUEUE_LENGTH, 16384);
            (self.api.set_param)(self.h, PARAM_QUEUE_SIZE, 32 * 1024 * 1024);
        }
    }

    /// Next packet (or event). `None` once the handle has been shut down.
    pub fn recv(&self, buf: &mut [u8], addr: &mut Address) -> Option<usize> {
        let mut len = 0u32;
        let ok =
            unsafe { (self.api.recv)(self.h, buf.as_mut_ptr(), buf.len() as u32, &mut len, addr) };
        (ok != 0).then_some(len as usize)
    }

    /// Re-inject a packet exactly as it was captured.
    pub fn send(&self, packet: &[u8], addr: &Address) -> bool {
        let mut sent = 0u32;
        unsafe {
            (self.api.send)(
                self.h,
                packet.as_ptr(),
                packet.len() as u32,
                &mut sent,
                addr,
            ) != 0
        }
    }

    /// Wake any thread blocked in `recv` and stop capturing.
    pub fn shutdown(&self) {
        unsafe { (self.api.shutdown)(self.h, SHUTDOWN_BOTH) };
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.h) };
    }
}

/// Protocol number and the two ports of an IPv4/IPv6 TCP or UDP packet:
/// `(protocol, source port, destination port)`. Fragments and other
/// protocols return `None` and are passed through untouched.
pub fn ports(p: &[u8]) -> Option<(u8, u16, u16)> {
    let (mut proto, mut off) = match p.first()? >> 4 {
        4 => {
            let ihl = (p[0] & 0x0F) as usize * 4;
            let frag_offset = u16::from_be_bytes([*p.get(6)?, *p.get(7)?]) & 0x1FFF;
            if frag_offset != 0 {
                return None;
            }
            (*p.get(9)?, ihl)
        }
        6 => (*p.get(6)?, 40),
        _ => return None,
    };
    // Skip IPv6 extension headers: hop-by-hop, routing, destination options, fragment.
    while matches!(proto, 0 | 43 | 60 | 44) {
        let next = *p.get(off)?;
        if proto == 44 {
            let frag_offset = u16::from_be_bytes([*p.get(off + 2)?, *p.get(off + 3)?]) >> 3;
            if frag_offset != 0 {
                return None;
            }
            off += 8;
        } else {
            off += (*p.get(off + 1)? as usize + 1) * 8;
        }
        proto = next;
    }
    if proto != 6 && proto != 17 {
        return None;
    }
    let sport = u16::from_be_bytes([*p.get(off)?, *p.get(off + 1)?]);
    let dport = u16::from_be_bytes([*p.get(off + 2)?, *p.get(off + 3)?]);
    Some((proto, sport, dport))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_and_skips_fragments() {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[9] = 6;
        p[20..22].copy_from_slice(&443u16.to_be_bytes());
        p[22..24].copy_from_slice(&50000u16.to_be_bytes());
        assert_eq!(ports(&p), Some((6, 443, 50000)));
        p[7] = 1; // non-first fragment
        assert_eq!(ports(&p), None);
    }

    #[test]
    fn parses_ipv6_udp_after_extension_header() {
        let mut p = vec![0u8; 40 + 8 + 8];
        p[0] = 0x60;
        p[6] = 0; // hop-by-hop
        p[40] = 17; // next: UDP
        p[41] = 0; // length 8
        p[48..50].copy_from_slice(&53u16.to_be_bytes());
        p[50..52].copy_from_slice(&61000u16.to_be_bytes());
        assert_eq!(ports(&p), Some((17, 53, 61000)));
        assert_eq!(ports(&p[..45]), None, "truncated");
    }
}
