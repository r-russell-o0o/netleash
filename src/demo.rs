//! Demo mode: synthetic traffic attributed to the real processes that own TCP
//! connections right now. Lets the UI, rules and history be exercised without
//! Administrator rights. Rules are honoured in the simulation.

use crate::conns;
use crate::state::{Dir, State, app_key};
use crate::sys::ProcessNames;
use crate::watch::Watch;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// xorshift64 — enough randomness for fake traffic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn unit(&mut self) -> f64 {
        (self.next() % 10_000) as f64 / 10_000.0
    }
}

pub fn spawn(state: Arc<State>, names: Arc<ProcessNames>, watch: Arc<Watch>) {
    std::thread::spawn(move || {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ std::process::id() as u64);
        // Per-pid (up, down) "intent" in bytes/s that drifts over time.
        let mut level: HashMap<u32, (f64, f64)> = HashMap::new();
        let mut pids = Vec::new();
        for step in (0u64..).take(usize::MAX) {
            if step % 20 == 0 {
                pids = conns::pids_with_tcp();
                pids.sort_unstable();
            }
            // Ten 100 ms slices per second, summed per app so limits apply
            // to the app as a whole, like real enforcement.
            let mut per_app: HashMap<String, (u32, u64, u64)> = HashMap::new();
            for &pid in &pids {
                let l = level.entry(pid).or_insert_with(|| {
                    let heavy = rng.unit() < 0.2;
                    let base = if heavy { 400_000.0 } else { 3_000.0 };
                    (base * rng.unit() * 0.3, base * rng.unit())
                });
                // Random walk with occasional bursts.
                let burst = if rng.unit() < 0.02 { 20.0 } else { 1.0 };
                l.0 = (l.0 * (0.8 + 0.4 * rng.unit())).clamp(0.0, 3e6);
                l.1 = (l.1 * (0.8 + 0.4 * rng.unit())).clamp(50.0, 2e7);
                let e = per_app.entry(names.resolve(pid)).or_insert((pid, 0, 0));
                e.1 += (l.0 * burst / 10.0) as u64;
                e.2 += (l.1 * burst / 10.0) as u64;
            }
            for (path, (pid, mut up, mut down)) in per_app {
                let rule = state.rule_for(&app_key(&path));
                // Outbound block: the simulated apps are clients, so no traffic at all.
                if rule.as_ref().is_some_and(|r| r.block_out) {
                    continue;
                }
                if let Some(r) = &rule {
                    if let Some(cap) = r.up_limit {
                        up = up.min(cap / 10);
                    }
                    if let Some(cap) = r.down_limit {
                        down = down.min(cap / 10);
                    }
                }
                watch.observe(&path);
                if up > 0 {
                    state.record(&path, pid, Dir::Up, up);
                }
                if down > 0 {
                    state.record(&path, pid, Dir::Down, down);
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}
