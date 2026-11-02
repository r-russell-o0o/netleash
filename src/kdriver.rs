//! Download limits through NetLeash's own driver (`driver/netleashlim.sys`),
//! the opt-in alternative to WinDivert (`--limiter driver`). Uploads go
//! through Windows' built-in QoS (`qos.rs`), so no packet ever passes
//! through NetLeash itself.
//!
//! The driver registers WFP callouts; this module adds the matching callout
//! objects and filters in a *dynamic* WFP session, and tells the driver which
//! programs may download how fast. Both undo themselves when NetLeash stops:
//! the session's filters vanish, and closing the device handle makes the
//! driver drop every limit. See `driver/nlshared.h` for the protocol.

use crate::sys::wide;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_START,
    StartServiceW,
};
use windows_sys::core::GUID;

pub const SERVICE: &str = "NetLeashLimiter";
const DEVICE: &str = r"\\.\NetLeashLimiter";
const PROTOCOL_VERSION: u32 = 1;
const MAX_LIMITS: usize = 256;
const IOCTL_GET_VERSION: u32 = 0x8E4C_6000;
const IOCTL_SET_LIMITS: u32 = 0x8E4C_A004;
/// RPC_C_AUTHN_WINNT
const AUTHN_WINNT: u32 = 10;
const SUBLAYER: GUID = GUID::from_u128(0x4e4c00fe_7a1e_4c1b_9b52_316e65746cfe);

const fn callout(n: u8) -> GUID {
    GUID::from_u128(0x4e4c0000_7a1e_4c1b_9b52_316e65746c00 | ((n as u128) << 96) | n as u128)
}

/// (callout key, layer, inspection only?) as in nlshared.h.
fn callouts() -> [(GUID, GUID, bool); 6] {
    [
        (callout(1), FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, true),
        (callout(2), FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, true),
        (callout(3), FWPM_LAYER_STREAM_V4, false),
        (callout(4), FWPM_LAYER_STREAM_V6, false),
        (callout(5), FWPM_LAYER_DATAGRAM_DATA_V4, false),
        (callout(6), FWPM_LAYER_DATAGRAM_DATA_V6, false),
    ]
}

/// FNV-1a 64, as the driver hashes a flow's app ID (nlbucket.h).
pub fn hash(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf29ce484222325, |h, &b| {
        (h ^ b as u64).wrapping_mul(0x100000001b3)
    })
}

/// The bytes WFP uses to identify the program at `path`.
fn app_id(path: &str) -> Result<Vec<u8>, String> {
    let w = wide(path);
    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    let rc = unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) };
    if rc != 0 || blob.is_null() {
        return Err(format!("no WFP app ID for {path} (0x{rc:08X})"));
    }
    let bytes = unsafe { std::slice::from_raw_parts((*blob).data, (*blob).size as usize).to_vec() };
    unsafe { FwpmFreeMemory0(&mut blob as *mut _ as *mut *mut core::ffi::c_void) };
    Ok(bytes)
}

/// The request bytes for NL_IOCTL_SET_LIMITS.
pub fn encode(limits: &[(u64, u64)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + 16 * limits.len());
    b.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    b.extend_from_slice(&(limits.len() as u32).to_le_bytes());
    for &(app, rate) in limits {
        b.extend_from_slice(&app.to_le_bytes());
        b.extend_from_slice(&rate.to_le_bytes());
    }
    b
}

fn ioctl(dev: HANDLE, code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, String> {
    let mut got = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            dev,
            code,
            if input.is_empty() {
                std::ptr::null()
            } else {
                input.as_ptr().cast()
            },
            input.len() as u32,
            if output.is_empty() {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(format!("driver request failed (error {})", unsafe {
            GetLastError()
        }))
    } else {
        Ok(got)
    }
}

/// Start the driver's service if it is installed but not running.
fn start_service() -> Result<(), String> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(format!("service manager: error {}", GetLastError()));
        }
        let name = wide(SERVICE);
        let svc = OpenServiceW(scm, name.as_ptr(), SERVICE_START);
        let result = if svc.is_null() {
            Err(format!("the {SERVICE} driver is not installed"))
        } else {
            let ok = StartServiceW(svc, 0, std::ptr::null());
            let err = GetLastError();
            CloseServiceHandle(svc);
            // 1056 = ERROR_SERVICE_ALREADY_RUNNING
            if ok != 0 || err == 1056 {
                Ok(())
            } else {
                Err(format!(
                    "could not start the {SERVICE} driver (error {err})"
                ))
            }
        };
        CloseServiceHandle(scm);
        result
    }
}

fn open_device() -> Result<HANDLE, String> {
    let path = wide(DEVICE);
    let open = || unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    let mut h = open();
    if h == INVALID_HANDLE_VALUE && unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
        start_service()?;
        h = open();
    }
    if h == INVALID_HANDLE_VALUE {
        let e = unsafe { GetLastError() };
        // 5 = access denied: the device allows one handle, or we're not elevated
        return Err(format!("could not open the NetLeash driver (error {e})"));
    }
    Ok(h)
}

pub struct KDriver {
    device: HANDLE,
    engine: HANDLE,
    /// Paths whose app ID could not be read (logged once each).
    missing: std::sync::Mutex<std::collections::HashSet<String>>,
}

// Both handles are only used through &self calls that the OS serialises.
unsafe impl Send for KDriver {}
unsafe impl Sync for KDriver {}

fn check(what: &str, rc: u32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (0x{rc:08X})"))
    }
}

impl KDriver {
    pub fn start() -> Result<Self, String> {
        let device = open_device()?;
        let mut v = [0u8; 4];
        let fail = |e: String| {
            unsafe { CloseHandle(device) };
            e
        };
        ioctl(device, IOCTL_GET_VERSION, &[], &mut v).map_err(fail)?;
        let version = u32::from_le_bytes(v);
        if version != PROTOCOL_VERSION {
            unsafe { CloseHandle(device) };
            return Err(format!(
                "NetLeash driver speaks protocol {version}, this NetLeash {PROTOCOL_VERSION}; reinstall NetLeash"
            ));
        }
        let engine = match Self::add_filters() {
            Ok(e) => e,
            Err(e) => {
                unsafe { CloseHandle(device) };
                return Err(e);
            }
        };
        Ok(KDriver {
            device,
            engine,
            missing: Default::default(),
        })
    }

    /// Route new flows, TCP data and UDP datagrams to the driver's callouts,
    /// in a dynamic session (removed with it).
    fn add_filters() -> Result<HANDLE, String> {
        let name = wide("NetLeash download limiter");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = name.as_ptr() as *mut _;
        let mut engine: HANDLE = std::ptr::null_mut();
        check("FwpmEngineOpen0", unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        let result = (|| {
            let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub.subLayerKey = SUBLAYER;
            sub.displayData.name = name.as_ptr() as *mut _;
            sub.weight = 0x7FFF;
            check("FwpmSubLayerAdd0", unsafe {
                FwpmSubLayerAdd0(engine, &sub, std::ptr::null_mut())
            })?;
            for (key, layer, inspect) in callouts() {
                let mut c: FWPM_CALLOUT0 = unsafe { std::mem::zeroed() };
                c.calloutKey = key;
                c.displayData.name = name.as_ptr() as *mut _;
                c.applicableLayer = layer;
                check("FwpmCalloutAdd0", unsafe {
                    FwpmCalloutAdd0(engine, &c, std::ptr::null_mut(), std::ptr::null_mut())
                })?;
                let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
                f.displayData.name = name.as_ptr() as *mut _;
                f.layerKey = layer;
                f.subLayerKey = SUBLAYER;
                f.weight.r#type = FWP_EMPTY;
                f.action.r#type = if inspect {
                    FWP_ACTION_CALLOUT_INSPECTION
                } else {
                    FWP_ACTION_CALLOUT_TERMINATING
                };
                f.action.Anonymous.calloutKey = key;
                check("FwpmFilterAdd0", unsafe {
                    FwpmFilterAdd0(engine, &f, std::ptr::null_mut(), std::ptr::null_mut())
                })?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(engine),
            Err(e) => {
                unsafe { FwpmEngineClose0(engine) };
                Err(e)
            }
        }
    }

    /// Replace all download limits: (app key or path, bytes per second).
    pub fn set_limits(&self, down: &HashMap<String, (String, u64)>) -> Result<(), String> {
        let mut entries = Vec::new();
        let mut missing = self.missing.lock().unwrap();
        let mut now_missing = std::collections::HashSet::new();
        let mut errors = Vec::new();
        for (path, rate) in down.values() {
            match app_id(path) {
                Ok(id) => entries.push((hash(&id), (*rate).max(1))),
                Err(e) => {
                    if !missing.contains(path) {
                        errors.push(e);
                    }
                    now_missing.insert(path.clone());
                }
            }
        }
        *missing = now_missing;
        entries.sort_unstable();
        entries.dedup_by_key(|e| e.0);
        entries.truncate(MAX_LIMITS);
        ioctl(self.device, IOCTL_SET_LIMITS, &encode(&entries), &mut [])?;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for KDriver {
    fn drop(&mut self) {
        // Closing the device lifts every limit; closing the session removes the filters.
        unsafe {
            CloseHandle(self.device);
            FwpmEngineClose0(self.engine);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_driver_definitions() {
        // nlbucket.h's reference values
        assert_eq!(hash(b""), 0xcbf29ce484222325);
        assert_eq!(hash(b"a"), 0xaf63dc4c8601ec8c);
        // nlshared.h: CTL_CODE(0x8E4C, 0x800/0x801, METHOD_BUFFERED, READ/WRITE)
        let ctl = |f: u32, a: u32| (0x8E4C << 16) | (a << 14) | (f << 2);
        assert_eq!(IOCTL_GET_VERSION, ctl(0x800, 1));
        assert_eq!(IOCTL_SET_LIMITS, ctl(0x801, 2));
        // {4e4c0003-7a1e-4c1b-9b52-316e65746c03}
        let g = callout(3);
        assert_eq!((g.data1, g.data2, g.data3), (0x4e4c0003, 0x7a1e, 0x4c1b));
        assert_eq!(g.data4, [0x9b, 0x52, 0x31, 0x6e, 0x65, 0x74, 0x6c, 0x03]);
    }

    #[test]
    fn encodes_like_nl_set_limits() {
        let b = encode(&[(0x1122334455667788, 1000)]);
        assert_eq!(b.len(), 8 + 16);
        assert_eq!(&b[0..4], &1u32.to_le_bytes());
        assert_eq!(&b[4..8], &1u32.to_le_bytes());
        assert_eq!(&b[8..16], &0x1122334455667788u64.to_le_bytes());
        assert_eq!(&b[16..24], &1000u64.to_le_bytes());
    }

    #[test]
    fn app_ids_are_stable() {
        // Works unelevated: the same bytes the driver sees at ALE_FLOW_ESTABLISHED.
        let a = app_id(r"C:\Windows\System32\curl.exe").unwrap();
        let b = app_id(r"c:\windows\system32\CURL.EXE").unwrap();
        assert_eq!(hash(&a), hash(&b), "case-insensitive, like the device path");
    }
}
