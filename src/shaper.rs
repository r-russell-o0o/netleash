//! Per-application upload and download limits with WinDivert.
//!
//! While at least one limit exists, every non-loopback TCP/UDP packet is
//! diverted to user mode. Each packet is attributed to a process by its local
//! port, and from there to an app. Packets of limited apps pass through a
//! token bucket: a packet within budget is re-injected at once, an
//! over-budget packet waits in its connection's queue, and the queues are
//! released round-robin. Only when the queues are full is a packet dropped,
//! always from the connection holding the most, so that TCP backs off. Packets
//! of unlimited apps, or ones we can't attribute, are re-injected immediately.
//!
//! Delay is preferred over loss on purpose. Under a low limit shared by many
//! connections (a browser speed test), each connection has only a packet or
//! two in flight; a lost one can't be fast-retransmitted, so the sender waits
//! for a retransmission timeout and the app gets a fraction of its limit.
//!
//! Fail-open: when there are no limits the packet handle is closed, so no
//! traffic passes through NetLeash at all. If the process dies, WinDivert
//! stops diverting and traffic flows normally (queued packets are
//! retransmitted by TCP).

use crate::conns;
use crate::state::{Dir, app_key};
use crate::sys::ProcessNames;
use crate::windivert::{self as wd, Address, Api, Handle};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How often queued packets are released.
const TICK: Duration = Duration::from_millis(2);
/// Minimum interval between full re-reads of the connection tables on a lookup miss.
const TABLE_REFRESH: Duration = Duration::from_millis(250);

// ---- token bucket ----------------------------------------------------------

pub enum Verdict {
    Pass,
    Queued,
    Drop,
}

/// A connection, as seen from its packets: (protocol, source port, destination port).
type FlowId = (u8, u16, u16);

#[derive(Default)]
struct FlowQueue {
    packets: VecDeque<(Vec<u8>, Address)>,
    bytes: usize,
}

pub struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
    flows: HashMap<FlowId, FlowQueue>,
    /// Connections with waiting packets, in the order they are served.
    order: VecDeque<FlowId>,
    queued_bytes: usize,
    cap_bytes: usize,
}

impl Bucket {
    pub fn new(rate: u64, now: Instant) -> Self {
        let mut b = Bucket {
            rate: 0.0,
            burst: 0.0,
            tokens: 0.0,
            last: now,
            flows: HashMap::new(),
            order: VecDeque::new(),
            queued_bytes: 0,
            cap_bytes: 0,
        };
        b.set_rate(rate);
        b.tokens = b.burst;
        b
    }

    /// Burst is 100 ms of traffic (at least two full-size packets); the queues
    /// hold up to 1 s (at least eight full-size packets), so senders are slowed
    /// by delay long before they see a loss.
    pub fn set_rate(&mut self, rate: u64) {
        self.rate = rate as f64;
        self.burst = (self.rate / 10.0).max(3000.0);
        self.cap_bytes = (self.rate as usize).max(12_000);
        self.tokens = self.tokens.min(self.burst);
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
    }

    /// A packet may go when enough tokens are saved up. Packets larger than
    /// the whole burst (segmentation-offload super-packets) go once the bucket
    /// is full, leaving it in debt, so the average still holds.
    fn fits(&self, len: usize) -> bool {
        self.tokens >= (len as f64).min(self.burst)
    }

    pub fn admit(&mut self, packet: &[u8], addr: &Address, now: Instant) -> Verdict {
        self.refill(now);
        let len = packet.len();
        if wd::is_bare_tcp(packet) {
            return Verdict::Pass; // no data to limit; delaying it slows the other direction
        }
        if self.queued_bytes == 0 && self.fits(len) {
            self.tokens -= len as f64;
            return Verdict::Pass;
        }
        let id = wd::ports(packet).unwrap_or_default();
        // Make room by dropping from whichever connection holds the most. A
        // connection with that much waiting has enough in flight to recover
        // from the loss quickly; one with a packet or two would stall.
        while self.queued_bytes + len > self.cap_bytes {
            let own = self.flows.get(&id).map_or(0, |f| f.bytes);
            let longest = self
                .flows
                .iter()
                .max_by_key(|(_, f)| f.bytes)
                .map(|(k, f)| (*k, f.bytes));
            match longest {
                Some((k, bytes)) if k != id && bytes > own + len => self.drop_last(k),
                _ => return Verdict::Drop,
            }
        }
        let f = self.flows.entry(id).or_default();
        if f.packets.is_empty() {
            self.order.push_back(id);
        }
        f.packets.push_back((packet.to_vec(), *addr));
        f.bytes += len;
        self.queued_bytes += len;
        Verdict::Queued
    }

    /// Drop the newest waiting packet of connection `id`.
    fn drop_last(&mut self, id: FlowId) {
        let f = self.flows.get_mut(&id).unwrap();
        let (p, _) = f.packets.pop_back().unwrap();
        f.bytes -= p.len();
        self.queued_bytes -= p.len();
        if f.packets.is_empty() {
            self.flows.remove(&id);
            self.order.retain(|k| *k != id);
        }
    }

    /// Packets whose turn has come, one per connection in turn.
    pub fn release(&mut self, now: Instant, out: &mut Vec<(Vec<u8>, Address)>) {
        self.refill(now);
        while let Some(&id) = self.order.front() {
            let next = self.flows[&id].packets.front().unwrap().0.len();
            if !self.fits(next) {
                break;
            }
            let f = self.flows.get_mut(&id).unwrap();
            let (p, a) = f.packets.pop_front().unwrap();
            f.bytes -= p.len();
            self.order.pop_front();
            if f.packets.is_empty() {
                self.flows.remove(&id);
            } else {
                self.order.push_back(id);
            }
            self.tokens -= p.len() as f64;
            self.queued_bytes -= p.len();
            out.push((p, a));
        }
    }

    fn drain(&mut self) -> Vec<(Vec<u8>, Address)> {
        self.queued_bytes = 0;
        self.order.clear();
        self.flows
            .drain()
            .flat_map(|(_, f)| f.packets)
            .collect()
    }
}

// ---- local port -> process -------------------------------------------------

struct PortMap {
    map: Mutex<HashMap<(u8, u16), u32>>,
    last_refresh: Mutex<Option<Instant>>,
}

impl PortMap {
    fn insert(&self, proto: u8, port: u16, pid: u32) {
        self.map.lock().unwrap().insert((proto, port), pid);
    }

    fn lookup(&self, proto: u8, port: u16) -> Option<u32> {
        if let Some(&pid) = self.map.lock().unwrap().get(&(proto, port)) {
            return Some(pid);
        }
        // Unknown port: re-read the OS tables, but not more than a few times a second.
        {
            let mut last = self.last_refresh.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < TABLE_REFRESH) {
                return None;
            }
            *last = Some(Instant::now());
        }
        let fresh: HashMap<(u8, u16), u32> = conns::port_owners()
            .into_iter()
            .map(|(pr, po, pid)| ((pr, po), pid))
            .collect();
        let mut m = self.map.lock().unwrap();
        *m = fresh; // also forgets ports that have since closed
        m.get(&(proto, port)).copied()
    }
}

// ---- the shaper ---------------------------------------------------------------

type Buckets = Arc<Mutex<HashMap<(String, Dir), Bucket>>>;

struct Diverter {
    handle: Arc<Handle>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

pub struct Shaper {
    api: &'static Api,
    names: Arc<ProcessNames>,
    ports: Arc<PortMap>,
    buckets: Buckets,
    diverter: Mutex<Option<Diverter>>,
    _flow: Arc<Handle>,
}

impl Shaper {
    /// Load WinDivert and start following new connections. Fails if
    /// WinDivert is missing or its driver can't load. Nothing is diverted yet.
    pub fn start(names: Arc<ProcessNames>, windivert_dir: Option<&Path>) -> Result<Self, String> {
        let api = wd::load(windivert_dir)?;
        // The FLOW layer reports each new connection with its process ID, so
        // most packets are attributed without re-reading connection tables.
        let flow = Arc::new(Handle::open(
            api,
            "true",
            wd::LAYER_FLOW,
            0,
            wd::FLAG_SNIFF | wd::FLAG_RECV_ONLY,
        )?);
        let ports = Arc::new(PortMap {
            map: Mutex::new(HashMap::new()),
            last_refresh: Mutex::new(None),
        });
        {
            let (flow, ports) = (flow.clone(), ports.clone());
            std::thread::Builder::new()
                .name("windivert-flow".into())
                .spawn(move || {
                    let mut addr = Address::zeroed();
                    while flow.recv(&mut [], &mut addr).is_some() {
                        if addr.event() == wd::EVENT_FLOW_ESTABLISHED {
                            ports.insert(
                                addr.flow_protocol(),
                                addr.flow_local_port(),
                                addr.flow_pid(),
                            );
                        }
                    }
                })
                .map_err(|e| e.to_string())?;
        }
        Ok(Shaper {
            api,
            names,
            ports,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            diverter: Mutex::new(None),
            _flow: flow,
        })
    }

    /// Replace the set of limits: `(app key, direction) -> bytes per second`.
    pub fn set_limits(&self, limits: HashMap<(String, Dir), u64>) -> Result<(), String> {
        let now = Instant::now();
        let mut released = Vec::new();
        {
            let mut b = self.buckets.lock().unwrap();
            b.retain(|k, bucket| {
                let keep = limits.contains_key(k);
                if !keep {
                    released.extend(bucket.drain());
                }
                keep
            });
            for (k, rate) in &limits {
                b.entry(k.clone())
                    .and_modify(|bucket| bucket.set_rate(*rate))
                    .or_insert_with(|| Bucket::new(*rate, now));
            }
        }
        let mut d = self.diverter.lock().unwrap();
        if let Some(div) = d.as_ref() {
            for (p, a) in &released {
                div.handle.send(p, a);
            }
        }
        match (limits.is_empty(), d.is_some()) {
            (false, false) => *d = Some(self.open_diverter()?),
            (true, true) => stop(d.take().unwrap()),
            _ => {}
        }
        Ok(())
    }

    fn open_diverter(&self) -> Result<Diverter, String> {
        let handle = Arc::new(Handle::open(
            self.api,
            "!loopback and (tcp or udp)",
            wd::LAYER_NETWORK,
            0,
            0,
        )?);
        handle.enlarge_queues();
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // Receive, decide, re-inject.
        let (h, ports, names, buckets) = (
            handle.clone(),
            self.ports.clone(),
            self.names.clone(),
            self.buckets.clone(),
        );
        threads.push(
            std::thread::Builder::new()
                .name("windivert-recv".into())
                .spawn(move || {
                    let mut buf = vec![0u8; wd::MTU_MAX];
                    let mut addr = Address::zeroed();
                    while let Some(n) = h.recv(&mut buf, &mut addr) {
                        let packet = &buf[..n];
                        let verdict = classify(packet, &addr, &ports, &names)
                            .and_then(|key| {
                                let mut b = buckets.lock().unwrap();
                                b.get_mut(&key)
                                    .map(|bucket| bucket.admit(packet, &addr, Instant::now()))
                            })
                            .unwrap_or(Verdict::Pass);
                        if let Verdict::Pass = verdict {
                            h.send(packet, &addr);
                        }
                    }
                })
                .map_err(|e| e.to_string())?,
        );

        // Release queued packets as budget becomes available.
        let (h, buckets, stop_flag) = (handle.clone(), self.buckets.clone(), stop.clone());
        threads.push(
            std::thread::Builder::new()
                .name("windivert-pace".into())
                .spawn(move || {
                    let mut out = Vec::new();
                    while !stop_flag.load(Ordering::Relaxed) {
                        std::thread::sleep(TICK);
                        let now = Instant::now();
                        for bucket in buckets.lock().unwrap().values_mut() {
                            bucket.release(now, &mut out);
                        }
                        for (p, a) in out.drain(..) {
                            h.send(&p, &a);
                        }
                    }
                })
                .map_err(|e| e.to_string())?,
        );
        Ok(Diverter {
            handle,
            stop,
            threads,
        })
    }

    /// Stop diverting. Queued packets are dropped; TCP retransmits them.
    pub fn shutdown(&self) {
        if let Some(d) = self.diverter.lock().unwrap().take() {
            stop(d);
        }
    }
}

fn stop(d: Diverter) {
    d.stop.store(true, Ordering::Relaxed);
    d.handle.shutdown();
    for t in d.threads {
        let _ = t.join();
    }
    // Dropping the last Arc<Handle> closes it.
}

/// Which bucket a packet belongs to, if it can be attributed at all.
fn classify(
    packet: &[u8],
    addr: &Address,
    ports: &PortMap,
    names: &ProcessNames,
) -> Option<(String, Dir)> {
    let (proto, sport, dport) = wd::ports(packet)?;
    let (local_port, dir) = if addr.outbound() {
        (sport, Dir::Up)
    } else {
        (dport, Dir::Down)
    };
    let pid = ports.lookup(proto, local_port)?;
    Some((app_key(&names.resolve(pid)), dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_passes_burst_then_queues_then_drops() {
        let t0 = Instant::now();
        let addr = Address::zeroed();
        let pkt = vec![0u8; 1500];
        let mut b = Bucket::new(30_000, t0); // burst 3000 B, queue cap 30000 B
        assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Pass));
        assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Pass));
        for _ in 0..20 {
            assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Queued));
        }
        assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Drop));

        let mut out = Vec::new();
        b.release(t0 + Duration::from_millis(50), &mut out); // +1500 B of budget
        assert_eq!(out.len(), 1);
        b.release(t0 + Duration::from_secs(1), &mut out); // burst-capped refill
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn bucket_holds_long_run_rate() {
        let t0 = Instant::now();
        let addr = Address::zeroed();
        let pkt = vec![0u8; 1000];
        let mut b = Bucket::new(100_000, t0);
        let mut sent = 0usize;
        let mut out = Vec::new();
        // Offer 1 MB/s for 2 s in 1 ms steps; expect ~100 KB/s out.
        for ms in 0..2000u64 {
            let now = t0 + Duration::from_millis(ms);
            if let Verdict::Pass = b.admit(&pkt, &addr, now) {
                sent += pkt.len();
            }
            b.release(now, &mut out);
        }
        sent += out.iter().map(|(p, _)| p.len()).sum::<usize>();
        assert!(
            (200_000..=212_000).contains(&sent),
            "sent {sent} bytes in 2 s"
        );
    }

    /// A 1500-byte IPv4 TCP packet from local port `sport`.
    fn tcp(sport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 1500];
        p[0] = 0x45;
        p[9] = 6;
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[32] = 5 << 4; // 20-byte TCP header
        p[33] = 0x10; // ACK
        p
    }

    #[test]
    fn acks_without_data_are_never_held() {
        let t0 = Instant::now();
        let addr = Address::zeroed();
        let mut b = Bucket::new(10_000, t0);
        b.admit(&tcp(1), &addr, t0);
        b.admit(&tcp(1), &addr, t0);
        assert!(matches!(b.admit(&tcp(1), &addr, t0), Verdict::Queued));
        let ack = &tcp(2)[..40];
        assert!(matches!(b.admit(ack, &addr, t0), Verdict::Pass));
        let mut fin = ack.to_vec();
        fin[33] |= 0x01; // must not overtake the data queued before it
        assert!(matches!(b.admit(&fin, &addr, t0), Verdict::Queued));
    }

    fn sport(p: &[u8]) -> u16 {
        wd::ports(p).unwrap().1
    }

    #[test]
    fn connections_are_served_in_turn() {
        let t0 = Instant::now();
        let addr = Address::zeroed();
        let mut b = Bucket::new(30_000, t0);
        b.admit(&tcp(1), &addr, t0);
        b.admit(&tcp(1), &addr, t0); // the burst is spent
        for _ in 0..4 {
            assert!(matches!(b.admit(&tcp(1), &addr, t0), Verdict::Queued));
        }
        assert!(matches!(b.admit(&tcp(2), &addr, t0), Verdict::Queued));
        let mut out = Vec::new();
        b.release(t0 + Duration::from_millis(100), &mut out); // budget for two
        let ports: Vec<u16> = out.iter().map(|(p, _)| sport(p)).collect();
        assert_eq!(ports, [1, 2], "the late connection doesn't wait behind the busy one");
    }

    #[test]
    fn full_queue_drops_from_the_busiest_connection() {
        let t0 = Instant::now();
        let addr = Address::zeroed();
        let mut b = Bucket::new(10_000, t0); // burst 3000 B, queue cap 12000 B
        b.admit(&tcp(1), &addr, t0);
        b.admit(&tcp(1), &addr, t0);
        for _ in 0..8 {
            assert!(matches!(b.admit(&tcp(1), &addr, t0), Verdict::Queued));
        }
        // Full. A quiet connection still gets in, at the busy one's expense...
        assert!(matches!(b.admit(&tcp(2), &addr, t0), Verdict::Queued));
        // ...while the busy one's own new packet is the one dropped.
        assert!(matches!(b.admit(&tcp(1), &addr, t0), Verdict::Drop));
        assert!(matches!(b.admit(&tcp(2), &addr, t0), Verdict::Queued));
        let bytes = |port| b.flows.iter().find(|(k, _)| k.1 == port).unwrap().1.bytes;
        assert_eq!((bytes(1), bytes(2)), (9000, 3000));
        assert_eq!(b.queued_bytes, 12_000);
    }

    #[test]
    fn oversized_packet_goes_when_bucket_is_full() {
        let t0 = Instant::now();
        let mut b = Bucket::new(10_000, t0); // burst 3000
        let big = vec![0u8; 60_000];
        assert!(matches!(
            b.admit(&big, &Address::zeroed(), t0),
            Verdict::Pass
        ));
        assert!(b.tokens < 0.0, "left in debt");
    }
}
