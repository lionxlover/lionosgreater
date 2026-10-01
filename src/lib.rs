//! lion-greeter: the LionOS login daemon.
//!
//! Does exactly six things:
//!   1. enumerate local users for `lion-login-ui`
//!   2. authenticate a username/password via PAM — forwarding any
//!      second-factor prompts back to the UI over D-Bus (0.5.0)
//!   3. optionally sign a configured user in automatically (0.5.0)
//!   4. list installed desktop sessions and hand the chosen one to
//!      `lion-session` (0.6.0)
//!   5. bridge logind seats for fast user switching (0.6.0)
//!   6. report progress/failure over D-Bus so the UI can animate it
//!
//! Rendering, post-login behaviour and account management are out of
//! scope.
//!
//! # Threat model
//!
//! The greeter runs as root and authenticates arbitrary local users.
//! The surface we expose is the system D-Bus interface
//! `org.lionos.Greeter1`, reachable only by the dedicated `lion-login`
//! account (see `dbus-1/org.lionos.Greeter.conf`). Failures take a
//! constant minimum latency so response time reveals neither valid
//! usernames nor which PAM module rejected a call. Brute force is
//! bounded by the per-user throttle in [`throttle`]. Secrets are
//! pinned into RAM via `mlockall` when the deployment allows it
//! ([`mlock`]), and every buffer that held one is zeroized on drop.
//! Session ids, logind session ids and VT numbers are validated
//! before any forwarding, so a compromised UI cannot turn the greeter
//! into a generic logind proxy.
//!
//! # Layout
//!
//! * [`auth`] — PAM worker + `lion-session` handoff
//! * [`pam_ffi`] — vendored, panic-safe libpam FFI with pluggable
//!   conversation bridges
//! * [`ipc`] — the D-Bus surface (`org.lionos.Greeter1`)
//! * [`sessions`] — XDG session directory listing
//! * [`seat`] — logind user-switching bridge
//! * [`methods`] — auth-method availability probing
//! * [`users_enum`] — NSS user enumeration (cached)
//! * [`throttle`] — per-user exponential backoff
//! * [`config`] — `/etc/lionos/greeter.toml` (hand-parsed subset)
//! * [`state`] — tiny persisted state (last user / session)
//! * [`mlock`] — `mlockall` with RLIMIT guard
//! * [`metrics`] — lock-free counters
//!
//! # Library target
//!
//! Since 0.6.0 the daemon is a thin binary over this library: the
//! split exists so integration tests (and downstream tooling) can
//! exercise the parsers and resolution policies without spawning a
//! root process. See `tests/` for the conversation-safe integration
//! suite.

pub mod auth;
pub mod config;
pub mod ipc;
pub mod methods;
pub mod metrics;
pub mod mlock;
pub mod pam_ffi;
pub mod seat;
pub mod sessions;
pub mod state;
pub mod throttle;
pub mod users_enum;

/// One lock to serialize tests that mutate process-global state
/// (`STATE_DIRECTORY`, `PAM_MODULES_DIR`, the shared user-list cache).
///
/// Rust's test harness runs `#[test]`s in parallel threads. Several
/// tests set an environment variable, then read files resolved
/// *through* that variable — without serialization, a sibling test's
/// `set_var` can interleave and make another test read the wrong
/// fixture directory (an intermittent one-in-a-few-hundred flake,
/// observed once in 0.6.0 and root-caused for 0.6.1).
///
/// Deadlock-free by construction: every taker acquires the lock
/// exactly once, at test start, and holds the guard for the test's
/// lifetime; no test takes it twice or nests it.
#[cfg(test)]
pub(crate) fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
