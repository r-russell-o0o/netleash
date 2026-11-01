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

pub type BlockKey = (String, Way);

pub struct Blocker {
    engine: HANDLE,
    /// (app path, direction) -> ids of the filters blocking it
    filters: HashMap<(String, Way), Vec<u64>>,
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

    fn add_block(&self, path: &str, way: Way) -> Result<Vec<u64>, String> {
        let wpath = wide(path);
        let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        check("FwpmGetAppIdFromFileName0", unsafe {
            FwpmGetAppIdFromFileName0(wpath.as_ptr(), &mut app_id)
        })
        .map_err(|e| format!("{e} for {path}"))?;

        let mut cond: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
        cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.Anonymous.byteBlob = app_id;

        let name = wide(&format!("NetLeash block {way:?} {path}"));
        let mut ids = Vec::new();
        let mut result = Ok(());
        for layer in way.layers() {
            let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            f.displayData.name = name.as_ptr() as *mut _;
            f.layerKey = layer;
            f.subLayerKey = SUBLAYER;
            f.weight.r#type = FWP_EMPTY; // let the engine pick
            f.numFilterConditions = 1;
            f.filterCondition = &mut cond;
            f.action.r#type = FWP_ACTION_BLOCK;
            let mut id = 0u64;
            result = check("FwpmFilterAdd0", unsafe {
                FwpmFilterAdd0(self.engine, &f, std::ptr::null_mut(), &mut id)
            });
            if result.is_err() {
                break;
            }
            ids.push(id);
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
    pub fn sync(&mut self, wanted: &[(String, Way)]) -> (Vec<BlockKey>, Vec<(BlockKey, String)>) {
        let mut errors = Vec::new();
        let gone: Vec<(String, Way)> = self
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
            match self.add_block(&k.0, k.1) {
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
