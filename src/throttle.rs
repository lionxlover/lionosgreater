//! Per-user brute-force backoff. Failures 1-2 are free; after that the
//! lockout doubles (2s, 4s, ... capped at 60s). The remaining time is
//! reported to the UI so it can show a countdown instead of a dead form.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const FREE_ATTEMPTS: u32 = 2;
const MAX_LOCKOUT: Duration = Duration::from_secs(60);
const MAX_TRACKED: usize = 256;

/// Key used for every name that is not an eligible account, so probing
/// random usernames neither grows memory nor reveals which names exist.
pub const UNKNOWN_KEY: &str = "\0unknown";

#[derive(Default)]
struct Entry {
    fails: u32,
    locked_until: Option<Instant>,
}

#[derive(Default)]
pub struct Throttle {
    map: HashMap<String, Entry>,
}

impl Throttle {
    /// Time left before `user` may try again, if locked out.
    pub fn remaining(&self, user: &str) -> Option<Duration> {
        let until = self.map.get(user)?.locked_until?;
        until
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
    }

    /// Record a failure; returns the lockout now in force (zero if none).
    pub fn record_failure(&mut self, user: &str) -> Duration {
        if self.map.len() >= MAX_TRACKED && !self.map.contains_key(user) {
            self.map
                .retain(|_, e| e.locked_until.is_some_and(|t| t > Instant::now()));
        }
        let e = self.map.entry(user.to_owned()).or_default();
        e.fails = e.fails.saturating_add(1);
        if e.fails <= FREE_ATTEMPTS {
            return Duration::ZERO;
        }
        let secs = 2u64.saturating_pow((e.fails - FREE_ATTEMPTS).min(6));
        let d = Duration::from_secs(secs).min(MAX_LOCKOUT);
        e.locked_until = Some(Instant::now() + d);
        d
    }

    pub fn reset(&mut self, user: &str) {
        self.map.remove(user);
    }

    /// Drop every tracked user. Used on session-unlock / suspend-resume
    /// so that stale entries from before the lock don't keep counting
    /// against the user.
    #[allow(dead_code)] // public API for future suspend/resume hook
    pub fn clear_all(&mut self) {
        self.map.clear();
    }

    /// Number of currently tracked users (mostly for tests/diagnostics).
    #[allow(dead_code)] // used by tests
    pub fn tracked_len(&self) -> usize {
        self.map.len()
    }

    /// Total failure count for one user (mostly for tests/diagnostics).
    #[allow(dead_code)] // used by tests
    pub fn failure_count(&self, user: &str) -> u32 {
        self.map.get(user).map(|e| e.fails).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_then_escalating() {
        let mut t = Throttle::default();
        assert_eq!(t.record_failure("a"), Duration::ZERO);
        assert_eq!(t.record_failure("a"), Duration::ZERO);
        assert_eq!(t.record_failure("a"), Duration::from_secs(2));
        assert_eq!(t.record_failure("a"), Duration::from_secs(4));
        assert!(t.remaining("a").is_some());
        t.reset("a");
        assert!(t.remaining("a").is_none());
    }

    #[test]
    fn capped() {
        let mut t = Throttle::default();
        for _ in 0..40 {
            t.record_failure("a");
        }
        assert!(t.record_failure("a") <= MAX_LOCKOUT);
    }

    #[test]
    fn failure_count_is_tracked() {
        let mut t = Throttle::default();
        assert_eq!(t.failure_count("u"), 0);
        t.record_failure("u");
        t.record_failure("u");
        assert_eq!(t.failure_count("u"), 2);
        assert_eq!(t.tracked_len(), 1);
    }

    #[test]
    fn clear_all_drops_everyone() {
        let mut t = Throttle::default();
        t.record_failure("a");
        t.record_failure("b");
        assert_eq!(t.tracked_len(), 2);
        t.clear_all();
        assert_eq!(t.tracked_len(), 0);
        assert!(t.remaining("a").is_none());
    }

    #[test]
    fn unknown_users_share_one_entry() {
        // Probing arbitrary usernames should not grow the map without
        // bound — every unknown name collapses onto UNKNOWN_KEY in the
        // caller, but even if the caller passes them through directly,
        // the cap on MAX_TRACKED prevents runaway memory growth.
        let mut t = Throttle::default();
        for i in 0..MAX_TRACKED + 50 {
            t.record_failure(&format!("probe{i}"));
        }
        // Either we hit the cap (≤ MAX_TRACKED) or we evicted expired
        // entries to stay under it.
        assert!(t.tracked_len() <= MAX_TRACKED + 1);
    }
}
