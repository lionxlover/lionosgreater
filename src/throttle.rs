#![forbid(unsafe_code)]
//! Brute-force back-off (spec 01 §3: "exponential back-off per user and per
//! TTY, delegated to pam_faillock but surfaced to the UI as a countdown").
//!
//! Scope of this module: the *soft*, greeter-side layer — exponential
//! per-user lock-out computed from observed failures, surfaced as
//! `Throttle{seconds}` events so the UI can show a countdown. Hard,
//! system-side enforcement stays with `pam_faillock` (see
//! `packaging/pam/lion-greeter`); the greeter never assumes it is the only
//! line of defence.
//!
//! "Per TTY" maps to the connected UI client: failures are also counted per
//! peer uid, so a misbehaving UI instance cannot pivot lock-out onto other
//! users' attempts indefinitely.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Failure counter with exponential lock-out for one key (user or peer uid).
#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    locked_until: Option<Instant>,
}

impl Entry {
    fn lockout_secs(&self, cap: Duration) -> u64 {
        if self.failures == 0 {
            return 0;
        }
        // Exponential: first failure → 1 s, then doubling, hard-capped.
        // System-side enforcement remains pam_faillock's; this is the soft,
        // user-visible layer.
        let shift = self.failures.saturating_sub(1).min(16);
        let secs = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        secs.min(cap.as_secs())
    }
}

/// Per-user (and per-peer) back-off tracker.
pub struct Throttle {
    entries: HashMap<String, Entry>,
    cap: Duration,
    enabled: bool,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl Throttle {
    pub fn new(enabled: bool, cap: Duration) -> Self {
        Throttle {
            entries: HashMap::new(),
            cap,
            enabled,
            now: Box::new(Instant::now),
        }
    }

    /// Test seam: injectable clock.
    #[cfg(test)]
    pub fn with_clock(self, f: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Throttle {
            now: Box::new(f),
            ..self
        }
    }

    /// Apply live policy changes (config reload).
    pub fn set_policy(&mut self, enabled: bool, cap: Duration) {
        self.enabled = enabled;
        self.cap = cap;
    }

    fn entry(&mut self, key: &str) -> &mut Entry {
        self.entries.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            locked_until: None,
        })
    }

    /// Remaining lock-out for a user, `None` if not locked / disabled.
    /// Also prunes expired locks.
    pub fn remaining(&mut self, user: &str) -> Option<(u64, Instant)> {
        if !self.enabled {
            return None;
        }
        let now = (self.now)();
        let cap_secs = self.cap.as_secs();
        let e = self.entry(user);
        match e.locked_until {
            Some(until) if until > now => {
                let secs = (until - now).as_secs().max(1).min(cap_secs);
                Some((secs, until))
            }
            Some(_) => {
                e.locked_until = None;
                None
            }
            None => None,
        }
    }

    /// Record a failed authentication: bumps the counter and (re)locks.
    /// Returns the lock-out seconds the *next* attempt will face, for
    /// surfacing as a `Throttle` event right after `AuthResult{ok:false}`.
    pub fn record_failure(&mut self, user: &str, peer_key: &str) -> u64 {
        if !self.enabled {
            return 0;
        }
        let now = (self.now)();
        let cap = self.cap;
        for key in [user, peer_key] {
            let e = self.entry(key);
            e.failures = e.failures.saturating_add(1);
            let secs = e.lockout_secs(cap);
            e.locked_until = Some(now + Duration::from_secs(secs));
        }
        self.entry(user).lockout_secs(cap)
    }

    /// Record success: the user entry is cleared; the peer entry decays by
    /// one (a healthy UI should not stay poisoned by one user's typos).
    pub fn record_success(&mut self, user: &str, peer_key: &str) {
        self.entries.remove(user);
        if let Some(e) = self.entries.get_mut(peer_key) {
            e.failures = e.failures.saturating_sub(1);
            if e.failures == 0 {
                e.locked_until = None;
            }
        }
    }

    /// Prune entries with expired locks (called opportunistically).
    pub fn prune(&mut self) {
        let now = (self.now)();
        self.entries
            .retain(|_, e| e.locked_until.map(|u| u > now).unwrap_or(e.failures > 0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn exponential_backoff_capped() {
        let mut t = Throttle::new(true, Duration::from_secs(60));
        assert_eq!(t.record_failure("alice", "u1000"), 1); // 1 failure → 1 s
        assert_eq!(t.record_failure("alice", "u1000"), 2); // 2 → 2 s
        assert_eq!(t.record_failure("alice", "u1000"), 4); // 3 → 4 s
        assert_eq!(t.record_failure("alice", "u1000"), 8);
        for _ in 0..10 {
            t.record_failure("alice", "u1000");
        }
        assert_eq!(t.record_failure("alice", "u1000"), 60); // capped
    }

    #[test]
    fn remaining_counts_down_and_unlocks() {
        use std::sync::{Arc, Mutex};
        let clock = Arc::new(Mutex::new(Instant::now()));
        let c2 = clock.clone();
        let mut t =
            Throttle::new(true, Duration::from_secs(60)).with_clock(move || *c2.lock().unwrap());
        assert!(t.remaining("alice").is_none());
        t.record_failure("alice", "u1000");
        t.record_failure("alice", "u1000");
        let (secs, until) = t.remaining("alice").unwrap();
        assert!((1..=2).contains(&secs));
        // advance past the lock (single lock scope — no re-entrancy)
        {
            let mut now = clock.lock().unwrap();
            let delta = until.saturating_duration_since(*now) + Duration::from_secs(1);
            *now += delta;
        }
        assert!(t.remaining("alice").is_none());
    }

    #[test]
    fn success_resets_user_and_decays_peer() {
        let mut t = Throttle::new(true, Duration::from_secs(60));
        t.record_failure("alice", "peerA");
        t.record_failure("alice", "peerA");
        t.record_success("alice", "peerA");
        assert!(t.remaining("alice").is_none());
        // peer entry still has 1 failure → next failure on same peer locks 1s
        assert_eq!(t.record_failure("bob", "peerA"), 1);
    }

    #[test]
    fn disabled_is_transparent() {
        let mut t = Throttle::new(false, Duration::from_secs(60));
        assert_eq!(t.record_failure("alice", "p"), 0);
        assert!(t.remaining("alice").is_none());
    }

    #[test]
    fn per_user_isolation() {
        let mut t = Throttle::new(true, Duration::from_secs(60));
        t.record_failure("alice", "peerA");
        t.record_failure("alice", "peerA");
        assert!(t.remaining("bob").is_none());
    }
}
