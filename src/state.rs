//! Shared, platform-independent state: per-app traffic counters, rules,
//! daily usage history and component status. Everything the web UI shows
//! comes from here, and everything here is plain data (no OS handles).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

/// Seconds of per-app rate history kept for the sparklines.
pub const HISTORY_SECS: usize = 60;
/// Apps with no traffic for this long (and no rule) are dropped from the live view.
const IDLE_FORGET_SECS: u64 = 15 * 60;
/// Days of usage history kept on disk.
const USAGE_KEEP_DAYS: usize = 120;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dir {
    Up,
    Down,
}

/// A rule for one application, keyed by its normalised executable path.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub path: String,
    /// Block connections the app makes.
    #[serde(default)]
    pub block_out: bool,
    /// Block connections the app accepts.
    #[serde(default)]
    pub block_in: bool,
    /// Blocks apply to the internet only; the local network stays reachable.
    #[serde(default)]
    pub internet_only: bool,
    /// Legacy/shorthand input: `"block": true` means both directions.
    /// Folded into `block_in`/`block_out` by `normalize` and never saved.
    #[serde(default, skip_serializing)]
    pub block: bool,
    /// Upload limit in bytes per second.
    #[serde(default)]
    pub up_limit: Option<u64>,
    /// Download limit in bytes per second (needs WinDivert).
    #[serde(default)]
    pub down_limit: Option<u64>,
    /// When the blocks and limits above apply (default: always).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<crate::timed::Schedule>,
    /// Daily or monthly data allowance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota: Option<crate::timed::Quota>,
}

impl Rule {
    pub fn normalize(mut self) -> Self {
        if self.block {
            self.block_in = true;
            self.block_out = true;
            self.block = false;
        }
        self.path = self.path.trim().to_string();
        self
    }

    pub fn blocks_any(&self) -> bool {
        self.block_in || self.block_out
    }

    /// Fully blocked apps carry no traffic, so limits on them are moot.
    pub fn blocks_all(&self) -> bool {
        self.block_in && self.block_out
    }

    pub fn is_noop(&self) -> bool {
        !self.blocks_any()
            && self.up_limit.is_none()
            && self.down_limit.is_none()
            && self.quota.is_none()
    }
}

/// Lowercased path used as the identity of an application.
pub fn app_key(path: &str) -> String {
    path.to_lowercase()
}

#[derive(Default)]
struct App {
    display_path: String,
    pids: HashMap<u32, Instant>,
    up_total: u64,
    down_total: u64,
    up_tick: u64,
    down_tick: u64,
    history: VecDeque<(u64, u64)>,
    last_traffic: Option<Instant>,
}

#[derive(Clone, Serialize, Default)]
pub struct ComponentStatus {
    pub monitor: String,
    pub blocker: String,
    pub limiter: String,
    pub shaper: String,
}

#[derive(Serialize)]
pub struct AppView {
    pub key: String,
    pub path: String,
    pub name: String,
    pub pids: Vec<u32>,
    pub up_rate: u64,
    pub down_rate: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub history: Vec<(u64, u64)>,
    pub rule: Option<Rule>,
    /// The program's own description ("Google Chrome"), filled in by the web layer.
    pub description: Option<String>,
    /// Set when a schedule or quota changes what the rule does right now.
    pub timed: Option<crate::timed::Timed>,
    /// Bytes used in the current quota period, if the rule has a quota.
    pub quota_used: Option<u64>,
}

#[derive(Serialize)]
pub struct Snapshot {
    pub demo: bool,
    pub uptime_secs: u64,
    pub up_rate: u64,
    pub down_rate: u64,
    pub history: Vec<(u64, u64)>,
    pub apps: Vec<AppView>,
    pub status: ComponentStatus,
    pub log: Vec<String>,
}

type Usage = BTreeMap<String, BTreeMap<String, [u64; 2]>>;

struct Inner {
    apps: HashMap<String, App>,
    rules: BTreeMap<String, Rule>,
    usage: Usage,
    usage_dirty: bool,
    totals_history: VecDeque<(u64, u64)>,
    status: ComponentStatus,
    log: VecDeque<String>,
}

pub struct State {
    inner: Mutex<Inner>,
    data_dir: PathBuf,
    started: Instant,
    pub demo: bool,
}

impl State {
    pub fn new(data_dir: PathBuf, demo: bool) -> Self {
        let rules: Vec<Rule> = read_json(&data_dir.join("rules.json")).unwrap_or_default();
        let usage: Usage = read_json(&data_dir.join("usage.json")).unwrap_or_default();
        let mut apps = HashMap::new();
        let rules: BTreeMap<String, Rule> = rules
            .into_iter()
            .map(|r| {
                let r = r.normalize();
                let key = app_key(&r.path);
                // Keep ruled apps visible even when they are not running.
                apps.entry(key.clone()).or_insert_with(|| App {
                    display_path: r.path.clone(),
                    ..Default::default()
                });
                (key, r)
            })
            .collect();
        State {
            inner: Mutex::new(Inner {
                apps,
                rules,
                usage,
                usage_dirty: false,
                totals_history: VecDeque::new(),
                status: ComponentStatus::default(),
                log: VecDeque::new(),
            }),
            data_dir,
            started: Instant::now(),
            demo,
        }
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    /// Count `bytes` of traffic for the app at `path`, seen from process `pid`.
    pub fn record(&self, path: &str, pid: u32, dir: Dir, bytes: u64) {
        let key = app_key(path);
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let app = g.apps.entry(key).or_insert_with(|| App {
            display_path: path.to_string(),
            ..Default::default()
        });
        // A rule may have created the entry with differently cased text (NetLimiter
        // stores lowercase paths); the running process has the real spelling.
        if app.display_path != path {
            app.display_path = path.to_string();
        }
        app.pids.insert(pid, now);
        app.last_traffic = Some(now);
        match dir {
            Dir::Up => {
                app.up_total += bytes;
                app.up_tick += bytes;
            }
            Dir::Down => {
                app.down_total += bytes;
                app.down_tick += bytes;
            }
        }
    }

    /// Called once per second: closes the current one-second bucket.
    pub fn tick(&self, today: &str) {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();
        let Inner {
            apps,
            rules,
            usage,
            usage_dirty,
            totals_history,
            ..
        } = &mut *g;
        let (mut up_sum, mut down_sum) = (0, 0);
        let day = usage.entry(today.to_string()).or_default();
        for app in apps.values_mut() {
            if app.up_tick + app.down_tick > 0 {
                let e = day.entry(app.display_path.clone()).or_insert([0, 0]);
                e[0] += app.up_tick;
                e[1] += app.down_tick;
                *usage_dirty = true;
            }
            up_sum += app.up_tick;
            down_sum += app.down_tick;
            push_capped(&mut app.history, (app.up_tick, app.down_tick));
            app.up_tick = 0;
            app.down_tick = 0;
            app.pids
                .retain(|_, seen| now.duration_since(*seen).as_secs() < 60);
        }
        push_capped(totals_history, (up_sum, down_sum));
        apps.retain(|key, app| {
            rules.contains_key(key)
                || app
                    .last_traffic
                    .is_some_and(|t| now.duration_since(t).as_secs() < IDLE_FORGET_SECS)
        });
        while usage.len() > USAGE_KEEP_DAYS {
            let oldest = usage.keys().next().cloned().unwrap();
            usage.remove(&oldest);
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = self.inner.lock().unwrap();
        let mut apps: Vec<AppView> = g
            .apps
            .iter()
            .map(|(key, a)| {
                let (up_rate, down_rate) = a.history.back().copied().unwrap_or((0, 0));
                let mut pids: Vec<u32> = a.pids.keys().copied().collect();
                pids.sort_unstable();
                AppView {
                    key: key.clone(),
                    path: a.display_path.clone(),
                    name: file_name(&a.display_path),
                    pids,
                    up_rate,
                    down_rate,
                    up_total: a.up_total,
                    down_total: a.down_total,
                    history: a.history.iter().copied().collect(),
                    rule: g.rules.get(key).cloned(),
                    description: None,
                    timed: None,
                    quota_used: None,
                }
            })
            .collect();
        apps.sort_by(|a, b| {
            (b.up_rate + b.down_rate)
                .cmp(&(a.up_rate + a.down_rate))
                .then((b.up_total + b.down_total).cmp(&(a.up_total + a.down_total)))
        });
        let (up_rate, down_rate) = g.totals_history.back().copied().unwrap_or((0, 0));
        Snapshot {
            demo: self.demo,
            uptime_secs: self.started.elapsed().as_secs(),
            up_rate,
            down_rate,
            history: g.totals_history.iter().copied().collect(),
            apps,
            status: g.status.clone(),
            log: g.log.iter().cloned().collect(),
        }
    }

    pub fn pids_of(&self, key: &str) -> Vec<u32> {
        let g = self.inner.lock().unwrap();
        g.apps
            .get(key)
            .map(|a| a.pids.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.inner.lock().unwrap().rules.values().cloned().collect()
    }

    pub fn rule_for(&self, key: &str) -> Option<Rule> {
        self.inner.lock().unwrap().rules.get(key).cloned()
    }

    /// Insert, replace or (if the rule does nothing) remove a rule, then persist.
    pub fn set_rule(&self, rule: Rule) -> std::io::Result<()> {
        self.set_rules(vec![rule])
    }

    /// Like `set_rule` for many rules at once, with a single save.
    pub fn set_rules(&self, rules: Vec<Rule>) -> std::io::Result<()> {
        let all: Vec<Rule> = {
            let mut g = self.inner.lock().unwrap();
            for rule in rules {
                let rule = rule.normalize();
                let key = app_key(&rule.path);
                if rule.is_noop() {
                    g.rules.remove(&key);
                } else {
                    g.apps.entry(key.clone()).or_insert_with(|| App {
                        display_path: rule.path.clone(),
                        ..Default::default()
                    });
                    g.rules.insert(key, rule);
                }
            }
            g.rules.values().cloned().collect()
        };
        write_json(&self.data_dir.join("rules.json"), &all)
    }

    /// Every program in the usage history: (path, last day seen, total bytes).
    pub fn usage_paths(&self) -> Vec<(String, String, u64)> {
        let g = self.inner.lock().unwrap();
        let mut seen: HashMap<String, (String, String, u64)> = HashMap::new();
        // Days are sorted oldest first, so the last write per program wins.
        for (day, programs) in &g.usage {
            for (path, [up, down]) in programs {
                let e = seen
                    .entry(app_key(path))
                    .or_insert_with(|| (path.clone(), day.clone(), 0));
                e.1 = day.clone();
                e.2 += up + down;
            }
        }
        seen.into_values().collect()
    }

    /// Bytes (up + down) the program used from day `since` (`YYYY-MM-DD`) on.
    pub fn used_since(&self, key: &str, since: &str) -> u64 {
        let g = self.inner.lock().unwrap();
        g.usage
            .range(since.to_string()..)
            .flat_map(|(_, programs)| programs.iter())
            .filter(|(path, _)| app_key(path) == key)
            .map(|(_, [up, down])| up + down)
            .sum()
    }

    pub fn usage_json(&self) -> String {
        serde_json::to_string(&self.inner.lock().unwrap().usage).unwrap_or_else(|_| "{}".into())
    }

    pub fn flush_usage(&self) {
        let usage = {
            let mut g = self.inner.lock().unwrap();
            if !g.usage_dirty {
                return;
            }
            g.usage_dirty = false;
            g.usage.clone()
        };
        if let Err(e) = write_json(&self.data_dir.join("usage.json"), &usage) {
            self.log(format!("could not save usage history: {e}"));
        }
    }

    pub fn set_status(&self, f: impl FnOnce(&mut ComponentStatus)) {
        f(&mut self.inner.lock().unwrap().status);
    }

    pub fn log(&self, msg: impl Into<String>) {
        let line = format!("{} {}", crate::sys::local_time_hms(), msg.into());
        eprintln!("{line}");
        let mut g = self.inner.lock().unwrap();
        // Also keep a file: started at boot there is no console to read.
        // Written under the lock so lines from different threads don't interleave.
        append_log(
            &self.data_dir.join("netleash.log"),
            &format!("{} {line}", crate::sys::local_date()),
        );
        if g.log.len() >= 50 {
            g.log.pop_front();
        }
        g.log.push_back(line);
    }
}

/// Append a line, keeping at most ~1 MB in `netleash.log` plus one older file.
pub fn append_log(path: &PathBuf, line: &str) {
    use std::io::Write;
    if std::fs::metadata(path).is_ok_and(|m| m.len() > 1024 * 1024) {
        let _ = std::fs::rename(path, path.with_extension("log.1"));
    }
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(path));
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

fn push_capped(q: &mut VecDeque<(u64, u64)>, v: (u64, u64)) {
    if q.len() >= HISTORY_SECS {
        q.pop_front();
    }
    q.push_back(v);
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Option<T> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&text) {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("ignoring unreadable {}: {e}", path.display());
            None
        }
    }
}

/// Write via a temp file and rename, so a crash never leaves half a file.
fn write_json<T: Serialize>(path: &PathBuf, value: &T) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> State {
        // Tests run in parallel: each gets its own folder.
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("netleash-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        State::new(dir, true)
    }

    #[test]
    fn tick_turns_bytes_into_rates_and_usage() {
        let s = temp_state();
        s.record(r"C:\Apps\Foo.exe", 10, Dir::Up, 300);
        s.record(r"c:\apps\foo.exe", 11, Dir::Down, 700);
        s.tick("2026-10-25");
        let snap = s.snapshot();
        assert_eq!(
            snap.apps.len(),
            1,
            "paths differing only in case are one app"
        );
        let a = &snap.apps[0];
        assert_eq!((a.up_rate, a.down_rate), (300, 700));
        assert_eq!(a.pids, vec![10, 11]);
        assert_eq!((snap.up_rate, snap.down_rate), (300, 700));
        s.tick("2026-10-25");
        assert_eq!(s.snapshot().apps[0].up_rate, 0, "rate resets each second");
        assert_eq!(s.snapshot().apps[0].up_total, 300, "totals do not");
        assert!(s.usage_json().contains("[300,700]"));
    }

    #[test]
    fn noop_rule_removes_and_rules_persist() {
        let s = temp_state();
        // Shorthand "block" becomes both directions and is saved that way.
        let r = Rule {
            path: r" C:\Apps\Foo.exe ".into(),
            block: true,
            ..Default::default()
        };
        s.set_rule(r).unwrap();
        let saved = Rule {
            path: r"C:\Apps\Foo.exe".into(),
            block_in: true,
            block_out: true,
            ..Default::default()
        };
        let reloaded = State::new(s.data_dir().clone(), true);
        assert_eq!(reloaded.rules(), vec![saved.clone()]);
        let text = std::fs::read_to_string(s.data_dir().join("rules.json")).unwrap();
        assert!(!text.contains("\"block\""), "legacy field is not written");

        s.set_rule(Rule {
            block_in: false,
            ..saved.clone()
        })
        .unwrap();
        assert!(s.rules()[0].block_out && !s.rules()[0].block_in);
        s.set_rule(Rule {
            block_out: false,
            block_in: false,
            ..saved
        })
        .unwrap();
        assert!(s.rules().is_empty());
    }

    #[test]
    fn old_rules_file_with_block_still_loads() {
        let s = temp_state();
        std::fs::create_dir_all(s.data_dir()).unwrap();
        std::fs::write(
            s.data_dir().join("rules.json"),
            r#"[{"path":"C:\\x.exe","block":true,"up_limit":null}]"#,
        )
        .unwrap();
        let r = &State::new(s.data_dir().clone(), true).rules()[0];
        assert!(r.block_in && r.block_out);
    }
}
