//! Connection tables from the IP Helper API (the same data `netstat -ano`
//! shows), plus closing an app's TCP connections when it gets blocked.

use serde::Serialize;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[derive(Serialize, Clone, Debug)]
pub struct Conn {
    pub pid: u32,
    pub proto: &'static str,
    pub local: String,
    pub remote: String,
    pub state: &'static str,
}

fn tcp_state(s: u32) -> &'static str {
    match s {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "?",
    }
}

/// Ports in these tables are in network byte order in the low 16 bits.
fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

/// Call a GetExtended*Table function, growing the buffer until it fits.
/// Returns the rows that follow the leading `dwNumEntries` count.
fn table<R: Copy>(fetch: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> Vec<R> {
    let mut size = 64 * 1024u32;
    loop {
        // u64 storage keeps the rows correctly aligned.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = fetch(buf.as_mut_ptr() as *mut _, &mut size);
        if rc == ERROR_INSUFFICIENT_BUFFER {
            size += 16 * 1024;
            continue;
        }
        if rc != NO_ERROR {
            return Vec::new();
        }
        let base = buf.as_ptr() as *const u8;
        let n = unsafe { *(base as *const u32) } as usize;
        // Rows start after dwNumEntries, padded to the row's alignment.
        let off = align_of::<R>().max(4);
        let rows = unsafe { std::slice::from_raw_parts(base.add(off) as *const R, n) };
        return rows.to_vec();
    }
}

fn tcp4() -> Vec<MIB_TCPROW_OWNER_PID> {
    table(|b, s| unsafe {
        GetExtendedTcpTable(b, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })
}
fn tcp6() -> Vec<MIB_TCP6ROW_OWNER_PID> {
    table(|b, s| unsafe {
        GetExtendedTcpTable(b, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0)
    })
}
fn udp4() -> Vec<MIB_UDPROW_OWNER_PID> {
    table(|b, s| unsafe { GetExtendedUdpTable(b, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) })
}
fn udp6() -> Vec<MIB_UDP6ROW_OWNER_PID> {
    table(|b, s| unsafe { GetExtendedUdpTable(b, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0) })
}

fn v4(a: u32) -> Ipv4Addr {
    Ipv4Addr::from(a.to_ne_bytes())
}

/// All TCP and UDP endpoints owned by `pids`.
pub fn for_pids(pids: &[u32]) -> Vec<Conn> {
    let want: HashSet<u32> = pids.iter().copied().collect();
    let mut out = Vec::new();
    for r in tcp4().into_iter().filter(|r| want.contains(&r.dwOwningPid)) {
        out.push(Conn {
            pid: r.dwOwningPid,
            proto: "TCP",
            local: format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)),
            remote: format!("{}:{}", v4(r.dwRemoteAddr), port(r.dwRemotePort)),
            state: tcp_state(r.dwState),
        });
    }
    for r in tcp6().into_iter().filter(|r| want.contains(&r.dwOwningPid)) {
        out.push(Conn {
            pid: r.dwOwningPid,
            proto: "TCPv6",
            local: format!(
                "[{}]:{}",
                Ipv6Addr::from(r.ucLocalAddr),
                port(r.dwLocalPort)
            ),
            remote: format!(
                "[{}]:{}",
                Ipv6Addr::from(r.ucRemoteAddr),
                port(r.dwRemotePort)
            ),
            state: tcp_state(r.dwState),
        });
    }
    for r in udp4().into_iter().filter(|r| want.contains(&r.dwOwningPid)) {
        out.push(Conn {
            pid: r.dwOwningPid,
            proto: "UDP",
            local: format!("{}:{}", v4(r.dwLocalAddr), port(r.dwLocalPort)),
            remote: "*".into(),
            state: "",
        });
    }
    for r in udp6().into_iter().filter(|r| want.contains(&r.dwOwningPid)) {
        out.push(Conn {
            pid: r.dwOwningPid,
            proto: "UDPv6",
            local: format!(
                "[{}]:{}",
                Ipv6Addr::from(r.ucLocalAddr),
                port(r.dwLocalPort)
            ),
            remote: "*".into(),
            state: "",
        });
    }
    out
}

/// `(protocol number, local port, pid)` for every TCP and UDP endpoint.
/// Used by the shaper to attribute packets to processes.
pub fn port_owners() -> Vec<(u8, u16, u32)> {
    let mut out = Vec::new();
    out.extend(
        tcp4()
            .iter()
            .map(|r| (6, port(r.dwLocalPort), r.dwOwningPid)),
    );
    out.extend(
        tcp6()
            .iter()
            .map(|r| (6, port(r.dwLocalPort), r.dwOwningPid)),
    );
    out.extend(
        udp4()
            .iter()
            .map(|r| (17, port(r.dwLocalPort), r.dwOwningPid)),
    );
    out.extend(
        udp6()
            .iter()
            .map(|r| (17, port(r.dwLocalPort), r.dwOwningPid)),
    );
    out
}

/// PIDs that currently own at least one TCP connection (used by demo mode).
pub fn pids_with_tcp() -> Vec<u32> {
    let mut set: HashSet<u32> = tcp4().iter().map(|r| r.dwOwningPid).collect();
    set.extend(tcp6().iter().map(|r| r.dwOwningPid));
    set.remove(&0);
    set.into_iter().collect()
}

/// Reset the established IPv4 TCP connections of `pids`. A WFP block only
/// stops *new* connections; this ends the ones already open. Windows has no
/// equivalent call for IPv6 sockets, so those drain when the app closes them.
/// Loopback connections always stay open; with `keep_local`, connections to
/// the local network do too.
/// Returns how many connections were closed.
pub fn close_tcp4(pids: &[u32], keep_local: bool) -> usize {
    let want: HashSet<u32> = pids.iter().copied().collect();
    let mut closed = 0;
    for r in tcp4() {
        if !want.contains(&r.dwOwningPid) || r.dwState == 2 {
            continue; // not ours, or a listening socket
        }
        let remote = v4(r.dwRemoteAddr);
        // Loopback is never blocked (a browser showing NetLeash's own page).
        if remote.is_loopback() || (keep_local && crate::lan::is_local_v4(remote)) {
            continue;
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 {
                dwState: MIB_TCP_STATE_DELETE_TCB as u32,
            },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        if unsafe { SetTcpEntry(&row) } == NO_ERROR {
            closed += 1;
        }
    }
    closed
}
