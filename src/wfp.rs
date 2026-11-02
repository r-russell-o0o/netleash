//! Per-application blocking through the Windows Filtering Platform — the same
//! engine Windows Defender Firewall uses — from user mode, with no driver.
//!
//! Filters live in a *dynamic* WFP session: Windows deletes every filter we
//! added the moment our engine handle closes, including when this process
//! crashes or is killed. A blocked app can therefore never stay blocked
//! because NetLeash went away (fail-open by construction).

use crate::sys::wide;
use std::collections::HashMap;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::core::GUID;

/// RPC_C_AUTHN_WINNT
const AUTHN_WINNT: u32 = 10;
const SUBLAYER: GUID = GUID::from_u128(0x6e4b1f3a_8c2d_4b7e_9a51_2f0c8d3e7a10);

/// Which connections to block. Like NetLimiter's firewall, this is about who
/// starts the connection, not which way the bytes flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Way {
    /// Connections the app makes (and the first datagram it sends).
    Out,
    /// Connections the app accepts (and the first datagram it receives).
    In,
}

impl Way {
    /// ALE authorisation layers, IPv4 and IPv6.
    fn layers(self) -> [GUID; 2] {
        match self {
            Way::Out => [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ],
            Way::In => [
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ],
        }
    }
}

/// (app path, direction, internet only: the local network stays reachable)
pub type BlockKey = (String, Way, bool);

pub struct Blocker {
    engine: HANDLE,
    /// block -> ids of the filters that make it
    filters: HashMap<BlockKey, Vec<u64>>,
}

// The engine handle is only used behind a Mutex.
unsafe impl Send for Blocker {}

fn check(what: &str, rc: u32) -> Result<(), String> {
    if rc == 0 {
        Ok(())
    } else {
        Err(format!("{what} failed (0x{rc:08X})"))
    }
}

impl Blocker {
    pub fn open() -> Result<Self, String> {
        let name = wide("NetLeash");
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
        let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sub.subLayerKey = SUBLAYER;
        sub.displayData.name = name.as_ptr() as *mut _;
        sub.weight = 0x8000;
        if let Err(e) = check("FwpmSubLayerAdd0", unsafe {
            FwpmSubLayerAdd0(engine, &sub, std::ptr::null_mut())
        }) {
            unsafe { FwpmEngineClose0(engine) };
            return Err(e);
        }
        Ok(Blocker {
            engine,
            filters: HashMap::new(),
        })
    }

    fn add_block(&self, path: &str, way: Way, internet_only: bool) -> Result<Vec<u64>, String> {
        let wpath = wide(path);
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check("FwpmGetAppIdFromFileName0", unsafe {
            FwpmGetAppIdFromFileName0(wpath.as_ptr(), &mut app_id)
        })
        .map_err(|e| format!("{e} for {path}"))?;

        let mut app: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        app.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        app.matchType = FWP_MATCH_EQUAL;
        app.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        app.conditionValue.Anonymous.byteBlob = app_id;

        // Internet-only: a higher-weight permit for this app AND a local
        // remote address. Conditions on the same field are ORed by WFP, so
        // one filter covers every local range. The permit is soft: a block
        // from Windows Firewall or another sublayer still wins.
        let mut v4: Vec<FWP_V4_ADDR_AND_MASK> = crate::lan::V4
            .iter()
            .map(|&(a, p)| FWP_V4_ADDR_AND_MASK {
                addr: u32::from(a),
                mask: crate::lan::mask_v4(p),
            })
            .collect();
        let mut v6: Vec<FWP_V6_ADDR_AND_MASK> = crate::lan::V6
            .iter()
            .map(|&(a, p)| FWP_V6_ADDR_AND_MASK {
                addr: a.octets(),
                prefixLength: p,
            })
            .collect();
        let remote = |ty, set: &mut dyn FnMut(&mut FWP_CONDITION_VALUE0)| {
            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = ty;
            set(&mut c.conditionValue);
            c
        };
        let mut local_v4: Vec<FWPM_FILTER_CONDITION0> = vec![app];
        for m in v4.iter_mut() {
            local_v4.push(remote(FWP_V4_ADDR_MASK, &mut |v| {
                v.Anonymous.v4AddrMask = m
            }));
        }
        let mut local_v6: Vec<FWPM_FILTER_CONDITION0> = vec![app];
        for m in v6.iter_mut() {
            local_v6.push(remote(FWP_V6_ADDR_MASK, &mut |v| {
                v.Anonymous.v6AddrMask = m
            }));
        }

        let name = wide(&format!(
            "NetLeash block {way:?}{} {path}",
            if internet_only { " internet" } else { "" }
        ));
        let mut ids = Vec::new();
        let mut result = Ok(());
        // way.layers() is [IPv4, IPv6].
        for (layer, local) in way.layers().into_iter().zip([&mut local_v4, &mut local_v6]) {
            let mut wanted: Vec<(u32, u8, &mut [FWPM_FILTER_CONDITION0])> =
                vec![(FWP_ACTION_BLOCK, 1, std::slice::from_mut(&mut app))];
            if internet_only {
                wanted.push((FWP_ACTION_PERMIT, 2, local.as_mut_slice()));
            }
            for (action, weight, conds) in wanted {
                let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
                f.displayData.name = name.as_ptr() as *mut _;
                f.layerKey = layer;
                f.subLayerKey = SUBLAYER;
                f.weight.r#type = FWP_UINT8;
                f.weight.Anonymous.uint8 = weight;
                f.numFilterConditions = conds.len() as u32;
                f.filterCondition = conds.as_mut_ptr();
                f.action.r#type = action;
                let mut id = 0u64;
                result = check("FwpmFilterAdd0", unsafe {
                    FwpmFilterAdd0(self.engine, &f, std::ptr::null_mut(), &mut id)
                });
                if result.is_err() {
                    break;
                }
                ids.push(id);
            }
            if result.is_err() {
                break;
            }
        }
        unsafe { FwpmFreeMemory0(&mut app_id as *mut _ as *mut *mut core::ffi::c_void) };
        if let Err(e) = result {
            for id in ids {
                unsafe { FwpmFilterDeleteById0(self.engine, id) };
            }
            return Err(e);
        }
        Ok(ids)
    }

    /// Make the set of blocks equal `wanted`. Returns the blocks newly added
    /// (so the caller can close open connections) and per-block errors.
    /// A block works whether or not the app is running.
    pub fn sync(&mut self, wanted: &[BlockKey]) -> (Vec<BlockKey>, Vec<(BlockKey, String)>) {
        let mut errors = Vec::new();
        let gone: Vec<BlockKey> = self
            .filters
            .keys()
            .filter(|k| !wanted.contains(k))
            .cloned()
            .collect();
        for k in gone {
            for id in self.filters.remove(&k).unwrap_or_default() {
                if let Err(e) = check("FwpmFilterDeleteById0", unsafe {
                    FwpmFilterDeleteById0(self.engine, id)
                }) {
                    errors.push((k.clone(), e));
                }
            }
        }
        let mut added = Vec::new();
        for k in wanted {
            if self.filters.contains_key(k) {
                continue;
            }
            match self.add_block(&k.0, k.1, k.2) {
                Ok(ids) => {
                    self.filters.insert(k.clone(), ids);
                    added.push(k.clone());
                }
                Err(e) => errors.push((k.clone(), e)),
            }
        }
        (added, errors)
    }
}

impl Drop for Blocker {
    fn drop(&mut self) {
        // Closing a dynamic session removes all of its filters.
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Exit code of a curl copy fetching `url` (0 = connected).
    fn curl(exe: &std::path::Path, url: &str) -> i32 {
        Command::new(exe)
            .args(["-s", "-o", "NUL", "--max-time", "5", url])
            .status()
            .map_or(-1, |s| s.code().unwrap_or(-1))
    }

    /// Needs admin and internet: `cargo test -- --ignored real_filters`
    #[test]
    #[ignore]
    fn real_filters() {
        let exe = std::env::temp_dir().join("netleash-wfp-test.exe");
        std::fs::copy(r"C:\Windows\System32\curl.exe", &exe).unwrap();
        let path = exe.display().to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let local = format!("http://{}/", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for mut s in listener.incoming().flatten() {
                let _ = s.read(&mut [0; 1024]);
                let _ = s.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let internet = "https://example.com/";
        assert_eq!(curl(&exe, &local), 0, "local, no block");
        assert_eq!(curl(&exe, internet), 0, "internet, no block");

        let mut b = Blocker::open().expect("run elevated");
        let (_, errs) = b.sync(&[(path.clone(), Way::Out, true)]);
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(
            curl(&exe, &local),
            0,
            "internet-only block: local still works"
        );
        assert_ne!(
            curl(&exe, internet),
            0,
            "internet-only block: internet blocked"
        );

        let (_, errs) = b.sync(&[(path.clone(), Way::Out, false)]);
        assert!(errs.is_empty(), "{errs:?}");
        assert_ne!(curl(&exe, &local), 0, "full block: local blocked too");

        b.sync(&[]);
        assert_eq!(curl(&exe, internet), 0, "unblocked again");
    }
}
