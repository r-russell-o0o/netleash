//! Per-application upload and download limits with WinDivert.
//!
//! While at least one limit exists, every non-loopback TCP/UDP packet is
//! diverted to user mode. Each packet is attributed to a process by its local
//! port, and from there to an app. Packets of limited apps pass through a
//! token bucket: a packet within budget is re-injected at once, an
//! over-budget packet waits in a short queue, and anything beyond the queue is
//! dropped so that TCP backs off. Packets of unlimited apps, or ones we can't
//! attribute, are re-injected immediately.
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

pub struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
    queue: VecDeque<(Vec<u8>, Address)>,
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
            queue: VecDeque::new(),
            queued_bytes: 0,
            cap_bytes: 0,
        };
        b.set_rate(rate);
        b.tokens = b.burst;
        b
    }

    /// Burst is 100 ms of traffic (at least two full-size packets); the queue
    /// holds at most 250 ms, so a limit adds little latency.
    pub fn set_rate(&mut self, rate: u64) {
        self.rate = rate as f64;
        self.burst = (self.rate / 10.0).max(3000.0);
        self.cap_bytes = ((self.rate / 4.0) as usize).max(6000);
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
        if self.queue.is_empty() && self.fits(packet.len()) {
            self.tokens -= packet.len() as f64;
            Verdict::Pass
        } else if self.queued_bytes + packet.len() <= self.cap_bytes {
            self.queued_bytes += packet.len();
            self.queue.push_back((packet.to_vec(), *addr));
            Verdict::Queued
        } else {
            Verdict::Drop
        }
    }

    /// Packets whose turn has come.
    pub fn release(&mut self, now: Instant, out: &mut Vec<(Vec<u8>, Address)>) {
        self.refill(now);
        while let Some((p, _)) = self.queue.front() {
            if !self.fits(p.len()) {
                break;
            }
            let (p, a) = self.queue.pop_front().unwrap();
            self.tokens -= p.len() as f64;
            self.queued_bytes -= p.len();
            out.push((p, a));
        }
    }

    fn drain(&mut self) -> impl Iterator<Item = (Vec<u8>, Address)> + '_ {
        self.queued_bytes = 0;
        self.queue.drain(..)
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
        let mut b = Bucket::new(30_000, t0); // burst 3000 B, queue cap 7500 B
        assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Pass));
        assert!(matches!(b.admit(&pkt, &addr, t0), Verdict::Pass));
        for _ in 0..5 {
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
