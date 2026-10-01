//! Lightweight atomic counters for the greeter's runtime behaviour.
//!
//! Exposed over D-Bus via the `GetMetrics()` method on `org.lionos.Greeter1`
//! so that ops dashboards, post-mortem scripts, and the LionOS install
//! wizard can introspect the daemon's health without scraping the journal.
//!
//! All counters are `AtomicU64` with `Relaxed` ordering — we never read
//! them to make a decision, only to report, so we don't need release/acquire
//! fences. The start time is captured once at first use and is stable for
//! the life of the process.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct Metrics {
    auth_attempts: AtomicU64,
    auth_successes: AtomicU64,
    auth_failures: AtomicU64,
    auth_cancels: AtomicU64,
    sessions_started: AtomicU64,
    /// Cached number of throttled users, refreshed when GetMetrics is
    /// called. Best-effort: the throttle is owned by the IPC layer, so
    /// this is just the last-seen value.
    throttled_users: AtomicU64,
    /// 0.5.0: how many times the autologin driver actually fired (not
    /// merely armed). Success or not, a fire means the countdown ran
    /// to zero and the PAM autologin stack was consulted.
    autologin_fires: AtomicU64,
    /// 0.5.0: autologin attempts that ended without a session (user
    /// pressed Esc, PAM stack refused, session spawn failed). High
    /// values with low `autologin_fires` point at a misconfigured
    /// `/etc/pam.d/lion-greeter-autologin`.
    autologin_aborts: AtomicU64,
    /// 0.6.0: successful seat operations requested through the greeter
    /// (`SwitchToVT` / `ActivateSession`). A user-switching UI lives on
    /// this counter; its absence in a deployment that claims switching
    /// means the UI is wired to a different path.
    seat_switches: AtomicU64,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();
static STARTED_AT: OnceLock<Instant> = OnceLock::new();

pub fn get() -> &'static Metrics {
    METRICS.get_or_init(Metrics::default)
}

fn started_at() -> Instant {
    *STARTED_AT.get_or_init(Instant::now)
}

impl Metrics {
    pub fn inc_attempts(&self) {
        self.auth_attempts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_success(&self) {
        self.auth_successes.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_cancel(&self) {
        self.auth_cancels.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_session(&self) {
        self.sessions_started.fetch_add(1, Ordering::Relaxed);
    }
    pub fn set_throttled_users(&self, n: u64) {
        self.throttled_users.store(n, Ordering::Relaxed);
    }
    pub fn inc_autologin_fire(&self) {
        self.autologin_fires.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_autologin_abort(&self) {
        self.autologin_aborts.fetch_add(1, Ordering::Relaxed);
    }
    /// 0.6.0: one per successful SwitchToVT/ActivateSession.
    pub fn inc_seat_switch(&self) {
        self.seat_switches.fetch_add(1, Ordering::Relaxed);
    }

    /// Reset all counters to zero (except `started_at`, which is sticky
    /// for the process lifetime so uptime is always meaningful). Used
    /// by the D-Bus `ResetMetrics()` method for post-mortem resets.
    pub fn reset(&self) {
        self.auth_attempts.store(0, Ordering::Relaxed);
        self.auth_successes.store(0, Ordering::Relaxed);
        self.auth_failures.store(0, Ordering::Relaxed);
        self.auth_cancels.store(0, Ordering::Relaxed);
        self.sessions_started.store(0, Ordering::Relaxed);
        self.throttled_users.store(0, Ordering::Relaxed);
        self.autologin_fires.store(0, Ordering::Relaxed);
        self.autologin_aborts.store(0, Ordering::Relaxed);
        self.seat_switches.store(0, Ordering::Relaxed);
    }

    /// Serialize to a JSON object string. Stable field order so
    /// downstream parsers can use positional access if they need to.
    pub fn to_json(&self) -> String {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let uptime = started_at().elapsed().as_secs();
        // We report both a wall-clock start and an uptime so a
        // monitoring tool can plot either.
        let started_unix = now_unix.saturating_sub(uptime);
        format!(
            "{{\
              \"auth_attempts\":{},\
              \"auth_successes\":{},\
              \"auth_failures\":{},\
              \"auth_cancels\":{},\
              \"sessions_started\":{},\
              \"throttled_users\":{},\
              \"autologin_fires\":{},\
              \"autologin_aborts\":{},\
              \"seat_switches\":{},\
              \"uptime_seconds\":{},\
              \"started_unix\":{}\
            }}",
            self.auth_attempts.load(Ordering::Relaxed),
            self.auth_successes.load(Ordering::Relaxed),
            self.auth_failures.load(Ordering::Relaxed),
            self.auth_cancels.load(Ordering::Relaxed),
            self.sessions_started.load(Ordering::Relaxed),
            self.throttled_users.load(Ordering::Relaxed),
            self.autologin_fires.load(Ordering::Relaxed),
            self.autologin_aborts.load(Ordering::Relaxed),
            self.seat_switches.load(Ordering::Relaxed),
            uptime,
            started_unix,
        )
    }
}

/// Convenience for callers that want a typed view instead of parsing JSON.
#[allow(dead_code)] // used by tests
pub struct Snapshot {
    pub auth_attempts: u64,
    pub auth_successes: u64,
    pub auth_failures: u64,
    pub auth_cancels: u64,
    pub sessions_started: u64,
    pub throttled_users: u64,
    pub uptime: Duration,
}

#[allow(dead_code)] // used by tests
impl Metrics {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            auth_attempts: self.auth_attempts.load(Ordering::Relaxed),
            auth_successes: self.auth_successes.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            auth_cancels: self.auth_cancels.load(Ordering::Relaxed),
            sessions_started: self.sessions_started.load(Ordering::Relaxed),
            throttled_users: self.throttled_users.load(Ordering::Relaxed),
            uptime: started_at().elapsed(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_independent() {
        let m = Metrics::default();
        m.inc_attempts();
        m.inc_attempts();
        m.inc_success();
        m.inc_failure();
        m.inc_cancel();
        m.inc_session();
        let s = m.snapshot();
        assert_eq!(s.auth_attempts, 2);
        assert_eq!(s.auth_successes, 1);
        assert_eq!(s.auth_failures, 1);
        assert_eq!(s.auth_cancels, 1);
        assert_eq!(s.sessions_started, 1);
    }

    #[test]
    fn reset_clears_all_counters() {
        let m = Metrics::default();
        m.inc_attempts();
        m.inc_success();
        m.reset();
        let s = m.snapshot();
        assert_eq!(s.auth_attempts, 0);
        assert_eq!(s.auth_successes, 0);
    }

    #[test]
    fn json_round_trips() {
        let m = Metrics::default();
        m.inc_attempts();
        m.inc_attempts();
        let json = m.to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("metrics JSON is valid");
        assert_eq!(v["auth_attempts"].as_u64(), Some(2));
        assert!(v["uptime_seconds"].as_u64().is_some());
        assert!(v["started_unix"].as_u64().is_some());
    }

    #[test]
    fn seat_switch_counter_reports_in_json() {
        let m = Metrics::default();
        m.inc_seat_switch();
        m.inc_seat_switch();
        m.inc_seat_switch();
        let json = m.to_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("metrics JSON is valid");
        assert_eq!(v["seat_switches"].as_u64(), Some(3));
    }

    #[test]
    fn throttled_users_setter_works() {
        let m = Metrics::default();
        m.set_throttled_users(7);
        assert_eq!(m.snapshot().throttled_users, 7);
    }
}
