//! New-program alerts: notice when a program uses the network for the first
//! time, show it in the UI (and the tray helper), and in strict mode block it
//! until the user allows it.
//!
//! Limitation, stated plainly: a program is noticed on its first network
//! activity (the monitor reports traffic, not connection attempts), so in
//! strict mode its very first packets may already have gone out before the
//! block is in place. Asking *before* the first connection would need a
//! kernel driver of our own.
//!
//! Persistence: watch.json in the data directory (mode, known programs,
//! open alerts). On the very first run, programs already present are learned
//! silently: from the caller's seed list and during a short learning period.

use crate::state::{app_key, file_name};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_ALERTS: usize = 200;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Learn new programs silently.
    Off,
    /// List new programs and notify (tray).
    #[default]
    Notify,
    /// Also block each new program until the user allows it.
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Known {
    pub path: String,
    pub first_seen: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub key: String,
    pub path: String,
    pub name: String,
    pub first_seen: u64,
    pub seq: u64,
    /// Blocked automatically because strict mode was on.
    pub auto_blocked: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    mode: Mode,
    seq: u64,
    known: BTreeMap<String, Known>,
    alerts: Vec<Alert>,
}

struct Inner {
    saved: Saved,
    /// Paths seen for the first time, waiting for `drain_new`.
    queue: VecDeque<String>,
    dirty: bool,
}

pub struct Watch {
    inner: Mutex<Inner>,
    file: PathBuf,
    /// Until this moment (first run only), new programs are learned silently.
    learn_until: Option<Instant>,
    pub first_run: bool,
    /// Lowercased folder of netleash.exe, ending in a backslash.
    own_dir: String,
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Only real program paths: not "System", "Idle", "x.exe (pid 5, path hidden)".
fn is_program_path(path: &str) -> bool {
    path.contains('\\') && !path.contains("(pid ")
}

impl Watch {
    pub fn new(data_dir: &std::path::Path, learn_for: Duration) -> Self {
        let file = data_dir.join("watch.json");
        let existing: Option<Saved> = std::fs::read_to_string(&file)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok());
        let first_run = existing.is_none();
        Watch {
            inner: Mutex::new(Inner {
                saved: existing.unwrap_or_default(),
                queue: VecDeque::new(),
                dirty: first_run,
            }),
            file,
            learn_until: first_run.then(|| Instant::now() + learn_for),
            first_run,
            own_dir: std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| app_key(&format!("{}\\", d.display()))))
                .unwrap_or_default(),
        }
    }

    fn learning(&self) -> bool {
        self.learn_until.is_some_and(|t| Instant::now() < t)
    }

    /// Mark programs as known without alerting (first-run seeding).
    pub fn seed<'a>(&self, paths: impl IntoIterator<Item = &'a str>) {
        let now = now_unix();
        let mut g = self.inner.lock().unwrap();
        for p in paths.into_iter().filter(|p| is_program_path(p)) {
            g.saved.known.entry(app_key(p)).or_insert_with(|| Known {
                path: p.to_string(),
                first_seen: now,
            });
        }
        g.dirty = true;
    }

    /// Called for every attributed traffic event; must stay cheap.
    pub fn observe(&self, path: &str) {
        if !is_program_path(path) {
            return;
        }
        let key = app_key(path);
        // NetLeash's own programs (service and tray helper) never alert.
        if !self.own_dir.is_empty() && key.starts_with(&self.own_dir) {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        if g.saved.known.contains_key(&key) {
            return;
        }
        g.saved.known.insert(
            key,
            Known {
                path: path.to_string(),
                first_seen: now_unix(),
            },
        );
        g.dirty = true;
        if !self.learning() && g.saved.mode != Mode::Off {
            g.queue.push_back(path.to_string());
        }
    }

    /// New programs since the last call, turned into alerts. The caller blocks
    /// them when the returned mode is `Block`.
    pub fn drain_new(&self) -> (Mode, Vec<Alert>) {
        let mut g = self.inner.lock().unwrap();
        let mode = g.saved.mode;
        let mut out = Vec::new();
        while let Some(path) = g.queue.pop_front() {
            g.saved.seq += 1;
            let alert = Alert {
                key: app_key(&path),
                name: file_name(&path),
                path,
                first_seen: now_unix(),
                seq: g.saved.seq,
                auto_blocked: mode == Mode::Block,
            };
            g.saved.alerts.push(alert.clone());
            out.push(alert);
        }
        let excess = g.saved.alerts.len().saturating_sub(MAX_ALERTS);
        g.saved.alerts.drain(..excess);
        if !out.is_empty() {
            g.dirty = true;
        }
        (mode, out)
    }

    pub fn mode(&self) -> Mode {
        self.inner.lock().unwrap().saved.mode
    }

    pub fn set_mode(&self, mode: Mode) {
        let mut g = self.inner.lock().unwrap();
        g.saved.mode = mode;
        g.dirty = true;
    }

    /// Open alerts, newest first, and the current sequence number.
    pub fn alerts(&self) -> (Vec<Alert>, u64) {
        let g = self.inner.lock().unwrap();
        let mut a = g.saved.alerts.clone();
        a.reverse();
        (a, g.saved.seq)
    }

    /// Remove an alert (the user decided). Returns it, if it existed.
    pub fn resolve(&self, key: &str) -> Option<Alert> {
        let mut g = self.inner.lock().unwrap();
        let i = g.saved.alerts.iter().position(|a| a.key == key)?;
        g.dirty = true;
        Some(g.saved.alerts.remove(i))
    }

    pub fn clear(&self) -> Vec<Alert> {
        let mut g = self.inner.lock().unwrap();
        g.dirty = true;
        std::mem::take(&mut g.saved.alerts)
    }

    /// Write watch.json if anything changed (temp file + rename).
    pub fn flush(&self) {
        let text = {
            let mut g = self.inner.lock().unwrap();
            if !g.dirty {
                return;
            }
            g.dirty = false;
            serde_json::to_vec_pretty(&g.saved).unwrap_or_default()
        };
        let tmp = self.file.with_extension("json.tmp");
        if std::fs::write(&tmp, text).is_ok() {
            let _ = std::fs::rename(&tmp, &self.file);
        }
    }
}

// ---- acting on alerts (needs the rules and the enforcer) ----------------------------

use crate::enforce::Enforcer;
use crate::state::{Rule, State};

/// Once a second: turn newly seen programs into alerts, and in strict mode
/// block them right away.
pub fn process(watch: &Watch, state: &State, enforcer: &Enforcer) {
    let (mode, new) = watch.drain_new();
    let mut blocked = false;
    for a in &new {
        if mode == Mode::Block && state.rule_for(&a.key).is_none() {
            let rule = Rule {
                path: a.path.clone(),
                block_in: true,
                block_out: true,
                ..Default::default()
            };
            if state.set_rule(rule).is_ok() {
                blocked = true;
                state.log(format!("new program blocked until allowed: {}", a.name));
            }
        } else {
            state.log(format!("new program on the network: {}", a.name));
        }
    }
    if blocked {
        enforcer.apply();
    }
    watch.flush();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block,
    AllowAll,
}

/// The user's answer to an alert (or to all of them).
pub fn decide(
    watch: &Watch,
    state: &State,
    enforcer: &Enforcer,
    key: &str,
    d: Decision,
) -> Result<(), String> {
    let alerts = match d {
        Decision::AllowAll => watch.clear(),
        _ => vec![watch.resolve(key).ok_or("no such alert")?],
    };
    for a in alerts {
        let current = state.rule_for(&a.key);
        let rule = match d {
            Decision::Block => Rule {
                path: a.path.clone(),
                block_in: true,
                block_out: true,
                internet_only: false,
                ..current.unwrap_or_default()
            },
            // Allowing only lifts a block that strict mode added; a rule the
            // user made themselves stays as it is.
            _ if a.auto_blocked => match current {
                Some(r) => Rule {
                    block_in: false,
                    block_out: false,
                    ..r
                },
                None => continue,
            },
            _ => continue,
        };
        state.set_rule(rule).map_err(|e| e.to_string())?;
    }
    watch.flush();
    enforcer.apply();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("netleash-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn first_run_learns_silently_then_alerts() {
        let d = temp_dir("learn");
        let w = Watch::new(&d, Duration::from_millis(50));
        assert!(w.first_run);
        w.seed([r"C:\Seeded\a.exe"]);
        w.observe(r"C:\During\learning.exe");
        assert!(w.drain_new().1.is_empty(), "nothing during learning");
        std::thread::sleep(Duration::from_millis(80));
        w.observe(r"C:\Seeded\A.EXE"); // known (seeded), any case
        w.observe(r"C:\During\learning.exe"); // learned
        w.observe("System");
        w.observe(r"x.exe (pid 5, path hidden)");
        w.observe(r"C:\New\thing.exe");
        w.observe(r"C:\New\thing.exe"); // only once
        let (mode, new) = w.drain_new();
        assert_eq!(mode, Mode::Notify);
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].name, "thing.exe");
        assert!(!new[0].auto_blocked);
    }

    #[test]
    fn modes_persist_and_resolve() {
        let d = temp_dir("persist");
        let w = Watch::new(&d, Duration::ZERO);
        w.set_mode(Mode::Block);
        w.observe(r"C:\X\new.exe");
        let (_, new) = w.drain_new();
        assert!(new[0].auto_blocked);
        w.flush();

        let w2 = Watch::new(&d, Duration::from_secs(600));
        assert!(!w2.first_run, "second start: no learning period");
        assert_eq!(w2.mode(), Mode::Block);
        assert_eq!(w2.alerts().0.len(), 1);
        w2.observe(r"C:\Y\other.exe");
        assert_eq!(
            w2.drain_new().1.len(),
            1,
            "alerts right away after the first run"
        );
        assert!(w2.resolve(&app_key(r"C:\X\new.exe")).is_some());
        assert_eq!(w2.alerts().0.len(), 1);

        // NetLeash's own folder never alerts.
        let own = std::env::current_exe().unwrap();
        w2.observe(
            &own.with_file_name("netleash-tray.exe")
                .display()
                .to_string(),
        );
        assert!(w2.drain_new().1.is_empty(), "own programs are ignored");

        w2.set_mode(Mode::Off);
        w2.observe(r"C:\Z\quiet.exe");
        assert!(w2.drain_new().1.is_empty());
    }
}
