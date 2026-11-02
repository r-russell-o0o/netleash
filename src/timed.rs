//! Schedules and data quotas: what a rule does right now.
//!
//! - A **schedule** limits when a rule's blocks and limits are in effect, e.g.
//!   "block this game 22:00-07:00 on school nights". Outside it the rule rests.
//! - A **quota** counts the program's traffic (up + down) per day or per
//!   calendar month from the usage history. Once used up, the program is
//!   blocked or slowed until the next day or month. It applies with or
//!   without a schedule.
//!
//! The enforcer re-evaluates every 10 seconds, so a quota can overshoot by
//! about 10 seconds' worth of traffic.

use crate::state::Rule;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Schedule {
    /// Bit 0 = Monday ... bit 6 = Sunday: the days a window *starts* on.
    pub days: u8,
    /// Minutes after midnight. `end` before `start` runs past midnight;
    /// `end` equal to `start` means the whole day.
    pub start: u16,
    pub end: u16,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    #[default]
    Day,
    Month,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OverQuota {
    #[default]
    Block,
    /// Limit upload and download to `rate`.
    Limit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Quota {
    /// Bytes, upload + download.
    pub bytes: u64,
    #[serde(default)]
    pub period: Period,
    #[serde(default)]
    pub action: OverQuota,
    /// Bytes per second, for `action: limit`.
    #[serde(default)]
    pub rate: Option<u64>,
}

/// Local time, as the rules need it.
pub struct Now {
    /// 0 = Monday ... 6 = Sunday
    pub weekday: u8,
    pub minute: u16,
    /// `YYYY-MM-DD`, the usage-history key
    pub today: String,
}

impl Now {
    /// First usage-history day of the quota period.
    pub fn period_start(&self, p: Period) -> String {
        match p {
            Period::Day => self.today.clone(),
            Period::Month => format!("{}-01", &self.today[..7.min(self.today.len())]),
        }
    }
}

impl Schedule {
    fn on(&self, day: u8) -> bool {
        self.days & (1 << (day % 7)) != 0
    }

    pub fn active(&self, now: &Now) -> bool {
        let (m, d) = (now.minute, now.weekday);
        let yesterday = (d + 6) % 7;
        if self.start == self.end {
            self.on(d)
        } else if self.start < self.end {
            self.on(d) && (self.start..self.end).contains(&m)
        } else {
            (self.on(d) && m >= self.start) || (self.on(yesterday) && m < self.end)
        }
    }
}

/// Why a rule acts differently from its plain settings right now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Timed {
    /// Outside its schedule: blocks and limits rest.
    Resting,
    /// Quota used up: blocked or slowed.
    OverQuota,
}

/// The rule as it applies now, and why it differs (if it does).
/// `used` is the program's traffic since the quota period began.
pub fn effective(rule: &Rule, now: &Now, used: impl Fn(&str) -> u64) -> (Rule, Option<Timed>) {
    let mut r = rule.clone();
    let mut why = None;
    if let Some(s) = &rule.schedule
        && !s.active(now)
    {
        r.block_in = false;
        r.block_out = false;
        r.up_limit = None;
        r.down_limit = None;
        why = Some(Timed::Resting);
    }
    if let Some(q) = &rule.quota
        && used(&now.period_start(q.period)) >= q.bytes
    {
        match (q.action, q.rate) {
            (OverQuota::Limit, Some(rate)) => {
                r.up_limit = Some(r.up_limit.map_or(rate, |v| v.min(rate)));
                r.down_limit = Some(r.down_limit.map_or(rate, |v| v.min(rate)));
            }
            _ => {
                r.block_in = true;
                r.block_out = true;
                r.internet_only = false;
            }
        }
        why = Some(Timed::OverQuota);
    }
    (r, why)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(weekday: u8, h: u16, m: u16) -> Now {
        Now {
            weekday,
            minute: h * 60 + m,
            today: "2026-11-02".into(),
        }
    }

    #[test]
    fn schedules() {
        // Mon-Fri 09:00-17:00
        let work = Schedule {
            days: 0b0011111,
            start: 9 * 60,
            end: 17 * 60,
        };
        assert!(work.active(&at(0, 9, 0)));
        assert!(!work.active(&at(0, 17, 0)));
        assert!(!work.active(&at(5, 12, 0)), "Saturday");
        // Sun-Thu nights 22:00-07:00: Friday 06:59 still counts (started Thursday).
        let nights = Schedule {
            days: 0b1001111,
            start: 22 * 60,
            end: 7 * 60,
        };
        assert!(nights.active(&at(4, 6, 59)));
        assert!(!nights.active(&at(4, 22, 0)), "Friday night is free");
        assert!(!nights.active(&at(5, 6, 0)), "Saturday morning too");
        assert!(nights.active(&at(6, 23, 0)), "Sunday night");
        assert!(nights.active(&at(0, 1, 0)), "...into Monday");
        // Whole day on weekends
        let weekend = Schedule {
            days: 0b1100000,
            start: 0,
            end: 0,
        };
        assert!(weekend.active(&at(6, 13, 0)) && !weekend.active(&at(0, 13, 0)));
    }

    #[test]
    fn quotas_and_schedules_combine() {
        let now = at(0, 12, 0);
        assert_eq!(now.period_start(Period::Month), "2026-11-01");
        let rule = Rule {
            path: r"C:\Game\game.exe".into(),
            block_out: true,
            internet_only: true,
            schedule: Some(Schedule {
                days: 0b1111111,
                start: 22 * 60,
                end: 7 * 60,
            }),
            quota: Some(Quota {
                bytes: 1000,
                period: Period::Day,
                action: OverQuota::Block,
                rate: None,
            }),
            ..Default::default()
        };
        let (r, why) = effective(&rule, &now, |_| 10);
        assert_eq!(why, Some(Timed::Resting));
        assert!(!r.block_out, "outside the schedule the block rests");
        let (r, why) = effective(
            &rule,
            &now,
            |since| if since == "2026-11-02" { 1000 } else { 0 },
        );
        assert_eq!(why, Some(Timed::OverQuota));
        assert!(
            r.block_in && r.block_out && !r.internet_only,
            "quota blocks fully"
        );

        let slow = Rule {
            up_limit: Some(500),
            quota: Some(Quota {
                bytes: 1,
                period: Period::Month,
                action: OverQuota::Limit,
                rate: Some(100),
            }),
            ..Default::default()
        };
        let (r, _) = effective(&slow, &now, |_| 5);
        assert_eq!((r.up_limit, r.down_limit), (Some(100), Some(100)));
        let (r, why) = effective(&slow, &now, |_| 0);
        assert_eq!((r.up_limit, why), (Some(500), None));
    }
}
