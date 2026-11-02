//! Turns the rule set into OS state: WFP filters for blocks, and either the
//! WinDivert shaper (upload + download) or, if WinDivert is unavailable,
//! Policy-based QoS (upload only) for limits. In demo mode nothing touches
//! the OS; the demo traffic generator reads the rules itself.

use crate::shaper::Shaper;
use crate::state::{Dir, Rule, State, app_key};
use crate::sys::ProcessNames;
use crate::timed::Timed;
use crate::wfp::Way;
use crate::{conns, pathglob, qos, wfp};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct Enforcer {
    state: Arc<State>,
    blocker: Mutex<Option<wfp::Blocker>>,
    shaper: Option<Shaper>,
    /// NetLeash's own driver for download limits (`--limiter driver`), instead of WinDivert.
    kdriver: Mutex<Option<crate::kdriver::KDriver>>,
    qos_ok: bool,
    failing: Mutex<HashSet<wfp::BlockKey>>,
    /// Wildcard patterns that matched nothing last time (logged once).
    unmatched: Mutex<HashSet<String>>,
    /// Rules with wildcards expanded, before schedules and quotas.
    concrete: Mutex<Vec<Rule>>,
    /// What was last put into effect, and why rules differ from their settings.
    applied: Mutex<Vec<Rule>>,
    timed: Mutex<HashMap<String, Timed>>,
}

impl Enforcer {
    pub fn new(
        state: Arc<State>,
        names: Arc<ProcessNames>,
        windivert_dir: Option<&Path>,
        use_driver: bool,
    ) -> Self {
        if state.demo {
            state.set_status(|s| {
                s.blocker = "demo (simulated)".into();
                s.limiter = "demo (simulated)".into();
                s.shaper = "demo (simulated)".into();
            });
            return Enforcer {
                state,
                blocker: Mutex::new(None),
                shaper: None,
                kdriver: Mutex::new(None),
                qos_ok: false,
                failing: Mutex::new(HashSet::new()),
                unmatched: Mutex::new(HashSet::new()),
                concrete: Mutex::new(Vec::new()),
                applied: Mutex::new(Vec::new()),
                timed: Mutex::new(HashMap::new()),
            };
        }
        let blocker = match wfp::Blocker::open() {
            Ok(b) => {
                state.set_status(|s| s.blocker = "ok (WFP, dynamic session)".into());
                Some(b)
            }
            Err(e) => {
                state.set_status(|s| s.blocker = format!("error: {e}"));
                state.log(format!("blocker unavailable: {e}"));
                None
            }
        };
        // Clear QoS policies a crashed earlier run may have left, whichever limiter we use.
        let qos_ok = qos::clear().is_ok();
        if use_driver {
            match crate::kdriver::KDriver::start() {
                Ok(k) => {
                    state.set_status(|st| {
                        st.limiter = "ok (NetLeash driver + Windows QoS)".into();
                        st.shaper = "ok (NetLeash driver)".into();
                    });
                    return Enforcer {
                        state,
                        blocker: Mutex::new(blocker),
                        shaper: None,
                        kdriver: Mutex::new(Some(k)),
                        qos_ok,
                        failing: Mutex::new(HashSet::new()),
                        unmatched: Mutex::new(HashSet::new()),
                        concrete: Mutex::new(Vec::new()),
                        applied: Mutex::new(Vec::new()),
                        timed: Mutex::new(HashMap::new()),
                    };
                }
                // Fall back to WinDivert, then to QoS alone.
                Err(e) => state.log(format!(
                    "NetLeash driver unavailable, trying WinDivert: {e}"
                )),
            }
        }
        let shaper = match Shaper::start(names, windivert_dir) {
            Ok(s) => {
                state.set_status(|st| {
                    st.limiter = "ok (WinDivert)".into();
                    st.shaper = "ok (WinDivert)".into();
                });
                Some(s)
            }
            Err(e) => {
                state.log(format!("WinDivert unavailable, download limits off: {e}"));
                state.set_status(|st| {
                    st.shaper = format!("not installed: {e}");
                    st.limiter = if qos_ok {
                        "ok (upload, Policy-based QoS fallback)".into()
                    } else {
                        "error: neither WinDivert nor NetQosPolicy available".into()
                    };
                });
                None
            }
        };
        Enforcer {
            state,
            blocker: Mutex::new(blocker),
            shaper,
            kdriver: Mutex::new(None),
            qos_ok,
            failing: Mutex::new(HashSet::new()),
            unmatched: Mutex::new(HashSet::new()),
            concrete: Mutex::new(Vec::new()),
            applied: Mutex::new(Vec::new()),
            timed: Mutex::new(HashMap::new()),
        }
    }

    /// Rules with wildcard paths replaced by one rule per matching file.
    fn concrete_rules(&self) -> Vec<Rule> {
        let mut out = Vec::new();
        let mut unmatched = Vec::new();
        for r in self.state.rules() {
            if !pathglob::has_wildcard(&r.path) {
                out.push(r);
                continue;
            }
            let files = pathglob::expand(&r.path);
            if files.is_empty() {
                unmatched.push(r.path.clone());
            }
            out.extend(files.into_iter().map(|path| Rule { path, ..r.clone() }));
        }
        let mut seen = self.unmatched.lock().unwrap();
        for p in &unmatched {
            if !seen.contains(p) {
                self.state.log(format!("pattern matches no files yet: {p}"));
            }
        }
        *seen = unmatched.into_iter().collect();
        out
    }

    /// Bring OS state in line with the current rules.
    pub fn apply(&self) {
        *self.concrete.lock().unwrap() = self.concrete_rules();
        self.check(true);
    }

    /// Re-expand wildcard rules (called every minute), so a program update
    /// that changes the version folder is covered without user action.
    pub fn refresh(&self) {
        if self
            .state
            .rules()
            .iter()
            .any(|r| pathglob::has_wildcard(&r.path))
        {
            *self.concrete.lock().unwrap() = self.concrete_rules();
        }
        self.check(false);
    }

    /// Apply schedules and quotas (called every 10 seconds); touches the OS
    /// only when the result changed, or always with `force`.
    pub fn check(&self, force: bool) {
        let now = crate::sys::local_now();
        let mut timed = HashMap::new();
        let rules: Vec<Rule> = self
            .concrete
            .lock()
            .unwrap()
            .iter()
            .map(|r| {
                let key = app_key(&r.path);
                let (eff, why) =
                    crate::timed::effective(r, &now, |since| self.state.used_since(&key, since));
                if let Some(w) = why {
                    timed.insert(key, w);
                }
                eff
            })
            .collect();
        {
            let mut before = self.timed.lock().unwrap();
            for (key, w) in &timed {
                if before.get(key) != Some(w) {
                    let name = crate::state::file_name(key);
                    self.state.log(match w {
                        Timed::Resting => format!("{name}: outside its schedule, rule resting"),
                        Timed::OverQuota => format!("{name}: data quota used up"),
                    });
                }
            }
            for key in before.keys().filter(|k| !timed.contains_key(*k)) {
                let name = crate::state::file_name(key);
                self.state
                    .log(format!("{name}: rule back to its normal settings"));
            }
            *before = timed;
        }
        let mut applied = self.applied.lock().unwrap();
        if self.state.demo || (!force && *applied == rules) {
            return;
        }
        self.apply_blocks(&rules);
        self.apply_limits(&rules, true);
        *applied = rules;
    }

    /// Why a program's rule acts differently from its settings right now.
    pub fn timed(&self) -> HashMap<String, Timed> {
        self.timed.lock().unwrap().clone()
    }

    fn apply_blocks(&self, rules: &[Rule]) {
        let mut wanted = Vec::new();
        for r in rules {
            if r.block_out {
                wanted.push((r.path.clone(), Way::Out, r.internet_only));
            }
            if r.block_in {
                wanted.push((r.path.clone(), Way::In, r.internet_only));
            }
        }
        if let Some(b) = self.blocker.lock().unwrap().as_mut() {
            let (added, errors) = b.sync(&wanted);
            // Blocks that fail (typically: the program isn't installed, or its
            // drive is offline) are retried on every change; report each once.
            let mut failing = self.failing.lock().unwrap();
            let now_failing: HashSet<wfp::BlockKey> =
                errors.iter().map(|(k, _)| k.clone()).collect();
            for (k, e) in errors {
                if !failing.contains(&k) {
                    self.state.log(format!("block {:?}: {e}", k.1));
                }
            }
            *failing = now_failing;
            let mut quiet = 0;
            for (path, way, internet_only) in added {
                let pids = self.state.pids_of(&app_key(&path));
                // Existing connections survive a new WFP block; end the outgoing ones.
                let n = if way == Way::Out && !pids.is_empty() {
                    conns::close_tcp4(&pids, internet_only)
                } else {
                    0
                };
                if pids.is_empty() {
                    quiet += 1; // not running: nothing to report per app
                    continue;
                }
                self.state.log(format!(
                    "blocked {} {}{} ({n} open connection{} closed)",
                    crate::state::file_name(&path),
                    if way == Way::Out {
                        "outbound"
                    } else {
                        "inbound"
                    },
                    if internet_only {
                        " to the internet"
                    } else {
                        ""
                    },
                    if n == 1 { "" } else { "s" }
                ));
            }
            if quiet > 0 {
                self.state.log(format!(
                    "{quiet} block filter(s) added for programs not running"
                ));
            }
        }
    }

    fn apply_limits(&self, rules: &[Rule], include_qos: bool) {
        if let Some(k) = self.kdriver.lock().unwrap().as_ref() {
            let down = rules
                .iter()
                .filter(|r| !r.blocks_all())
                .filter_map(|r| Some((app_key(&r.path), (r.path.clone(), r.down_limit?))))
                .collect();
            if let Err(e) = k.set_limits(&down) {
                self.state.log(format!("download limits: {e}"));
            }
            if include_qos
                && self.qos_ok
                && let Err(e) = qos::apply(rules)
            {
                self.state.log(format!("upload limit: {e}"));
            }
        } else if let Some(shaper) = &self.shaper {
            let mut limits = HashMap::new();
            for r in rules.iter().filter(|r| !r.blocks_all()) {
                if let Some(v) = r.up_limit {
                    limits.insert((app_key(&r.path), Dir::Up), v);
                }
                if let Some(v) = r.down_limit {
                    limits.insert((app_key(&r.path), Dir::Down), v);
                }
            }
            if let Err(e) = shaper.set_limits(limits) {
                self.state.log(format!("limits: {e}"));
                self.state.set_status(|s| s.shaper = format!("error: {e}"));
            }
        } else if include_qos
            && self.qos_ok
            && let Err(e) = qos::apply(rules)
        {
            self.state.log(format!("upload limit: {e}"));
        }
    }

    /// Remove what does not clean itself up. WFP filters vanish with the
    /// process; QoS ActiveStore policies would otherwise last until reboot.
    pub fn shutdown(&self) {
        if let Some(s) = &self.shaper {
            s.shutdown();
        }
        self.kdriver.lock().unwrap().take();
        if !self.state.demo && self.qos_ok {
            let _ = qos::clear();
        }
        self.blocker.lock().unwrap().take();
    }
}
