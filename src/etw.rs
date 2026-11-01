//! Traffic monitor built on the built-in "Microsoft-Windows-Kernel-Network"
//! ETW provider. The kernel emits one event per TCP/UDP send or receive,
//! tagged with the owning process ID and payload size. This is read-only
//! observation: nothing here can delay or alter traffic.
//!
//! Needs Administrator (or membership of "Performance Log Users").

use crate::state::Dir;
use crate::sys::wide;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::System::Diagnostics::Etw::*;
use windows_sys::core::GUID;

const SESSION_NAME: &str = "NetLeash-KernelNetwork";
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6
const KEYWORDS: u64 = 0x10 | 0x20;
const LEVEL_VERBOSE: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, PartialEq, Eq)]
pub struct NetEvent {
    pub pid: u32,
    pub bytes: u32,
    pub dir: Dir,
    pub proto: Proto,
    pub remote: IpAddr,
    pub remote_port: u16,
    pub local: IpAddr,
    pub local_port: u16,
}

/// Decode the fixed prefix shared by all Kernel-Network send/recv events:
/// `PID u32, size u32, daddr, saddr, dport u16 (BE), sport u16 (BE), ...`.
/// `daddr`/`saddr` are the connection's remote/local ends for both directions.
pub fn parse(event_id: u16, data: &[u8]) -> Option<NetEvent> {
    let (dir, proto, v6) = match event_id {
        10 => (Dir::Up, Proto::Tcp, false),
        11 => (Dir::Down, Proto::Tcp, false),
        26 => (Dir::Up, Proto::Tcp, true),
        27 => (Dir::Down, Proto::Tcp, true),
        42 => (Dir::Up, Proto::Udp, false),
        43 => (Dir::Down, Proto::Udp, false),
        58 => (Dir::Up, Proto::Udp, true),
        59 => (Dir::Down, Proto::Udp, true),
        _ => return None,
    };
    let alen = if v6 { 16 } else { 4 };
    if data.len() < 8 + 2 * alen + 4 {
        return None;
    }
    let u32le = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
    let addr = |o: usize| -> IpAddr {
        if v6 {
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&data[o..o + 16]).unwrap(),
            ))
        } else {
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&data[o..o + 4]).unwrap(),
            ))
        }
    };
    let port = |o: usize| u16::from_be_bytes([data[o], data[o + 1]]);
    let p = 8 + 2 * alen;
    Some(NetEvent {
        pid: u32le(0),
        bytes: u32le(4),
        dir,
        proto,
        remote: addr(8),
        local: addr(8 + alen),
        remote_port: port(p),
        local_port: port(p + 2),
    })
}

type Sink = Box<dyn Fn(NetEvent) + Send + Sync>;
static SINK: OnceLock<Sink> = OnceLock::new();

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let rec = unsafe { &*rec };
    let h = &rec.EventHeader;
    if h.ProviderId.data1 != KERNEL_NETWORK.data1 || h.ProviderId.data4 != KERNEL_NETWORK.data4 {
        return;
    }
    if rec.UserData.is_null() {
        return;
    }
    let data = unsafe {
        std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
    };
    if let (Some(ev), Some(sink)) = (parse(h.EventDescriptor.Id, data), SINK.get()) {
        sink(ev);
    }
}

/// Buffer holding EVENT_TRACE_PROPERTIES followed by the session name, as the API requires.
fn properties() -> Vec<u64> {
    let name = wide(SESSION_NAME);
    let head = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = head + name.len() * 2;
    let mut buf = vec![0u64; total.div_ceil(8)];
    let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
    unsafe {
        (*p).Wnode.BufferSize = total as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*p).Wnode.ClientContext = 1; // QueryPerformanceCounter timestamps
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).BufferSize = 64; // KB per buffer
        (*p).MinimumBuffers = 8;
        (*p).MaximumBuffers = 64;
        (*p).FlushTimer = 1; // deliver at least once a second
        (*p).LoggerNameOffset = head as u32;
    }
    buf
}

/// Stop our trace session. Real-time sessions outlive the process that
/// created them, so this runs at startup (stale session) and on exit.
pub fn stop() {
    let mut props = properties();
    let name = wide(SESSION_NAME);
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            props.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Start the session and deliver events to `sink` on a background thread.
pub fn start(sink: impl Fn(NetEvent) + Send + Sync + 'static) -> Result<(), String> {
    SINK.set(Box::new(sink))
        .map_err(|_| "monitor already started".to_string())?;
    let name = wide(SESSION_NAME);
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    unsafe {
        let mut props = properties();
        let mut rc = StartTraceW(&mut handle, name.as_ptr(), props.as_mut_ptr() as *mut _);
        if rc == ERROR_ALREADY_EXISTS {
            stop();
            let mut props = properties();
            rc = StartTraceW(&mut handle, name.as_ptr(), props.as_mut_ptr() as *mut _);
        }
        if rc != ERROR_SUCCESS {
            return Err(format!("StartTrace failed (error {rc})"));
        }
        let rc = EnableTraceEx2(
            handle,
            &KERNEL_NETWORK,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            LEVEL_VERBOSE,
            KEYWORDS,
            0,
            0,
            std::ptr::null(),
        );
        if rc != ERROR_SUCCESS {
            stop();
            return Err(format!("EnableTraceEx2 failed (error {rc})"));
        }
    }
    std::thread::Builder::new()
        .name("etw".into())
        .spawn(move || {
            let mut name = name;
            let mut log: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
            log.LoggerName = name.as_mut_ptr();
            log.Anonymous1.ProcessTraceMode =
                PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            log.Anonymous2.EventRecordCallback = Some(on_event);
            unsafe {
                let h = OpenTraceW(&mut log);
                if h.Value == u64::MAX {
                    eprintln!("OpenTrace failed");
                    return;
                }
                // Blocks until the session is stopped.
                ProcessTrace(&h, 1, std::ptr::null(), std::ptr::null());
                CloseTrace(h);
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_tcp_send() {
        let mut d = Vec::new();
        d.extend(1234u32.to_le_bytes()); // PID
        d.extend(1460u32.to_le_bytes()); // size
        d.extend([93, 184, 216, 34]); // daddr (remote)
        d.extend([192, 168, 1, 20]); // saddr (local)
        d.extend(443u16.to_be_bytes());
        d.extend(50123u16.to_be_bytes());
        d.extend([0u8; 16]); // trailing fields we ignore
        let ev = parse(10, &d).unwrap();
        assert_eq!(ev.pid, 1234);
        assert_eq!(ev.bytes, 1460);
        assert_eq!(ev.dir, Dir::Up);
        assert_eq!(ev.proto, Proto::Tcp);
        assert_eq!(ev.remote, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(ev.remote_port, 443);
        assert_eq!(ev.local_port, 50123);
    }

    #[test]
    fn parses_ipv6_udp_recv_and_rejects_short() {
        let mut d = Vec::new();
        d.extend(7u32.to_le_bytes());
        d.extend(512u32.to_le_bytes());
        d.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        d.extend("2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        d.extend(53u16.to_be_bytes());
        d.extend(60000u16.to_be_bytes());
        let ev = parse(59, &d).unwrap();
        assert_eq!(
            (ev.dir, ev.proto, ev.remote_port),
            (Dir::Down, Proto::Udp, 53)
        );
        assert!(parse(59, &d[..30]).is_none());
        assert!(parse(12, &d).is_none(), "connect events are not traffic");
    }
}
