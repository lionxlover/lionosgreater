#![forbid(unsafe_code)]
//! systemd readiness/watchdog protocol (`sd_notify(3)`), hand-rolled over
//! `UnixDatagram` — no C dependency, and `NOTIFY_SOCKET` semantics kept
//! exact: `READY=1` only when actually usable, `WATCHDOG=1` heartbeats at
//! `WATCHDOG_USEC/2`, `STOPPING=1` on shutdown (spec 01 §9).
//!
//! If `NOTIFY_SOCKET` is absent (manual run, tests) every call is a no-op.

use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Notify {
    sock: Option<Arc<UnixDatagram>>,
}

impl Notify {
    /// Bind the notification socket from the environment.
    pub fn from_env() -> Notify {
        let path = std::env::var_os("NOTIFY_SOCKET");
        let sock = path.and_then(|p| {
            UnixDatagram::unbound().ok().and_then(|s| {
                // `@(abstract)`-style sockets use an initial `@` in the env
                // var, which maps to the Linux abstract namespace `\0…`.
                let mut p = p;
                let bytes = p.as_encoded_bytes();
                if bytes.first() == Some(&b'@') {
                    let mut nb = bytes.to_vec();
                    nb[0] = 0;
                    p = std::os::unix::ffi::OsStringExt::from_vec(nb);
                }
                s.connect(p).ok()?;
                Some(Arc::new(s))
            })
        });
        Notify { sock }
    }

    fn send(&self, msg: &str) {
        if let Some(sock) = &self.sock {
            if sock.send(msg.as_bytes()).is_err() {
                // systemd not listening (early boot, unit without Type=notify):
                // not fatal; readiness must still be reflected in logs.
                tracing::debug!(target: "notify", "sd_notify send failed for {msg:?}");
            }
        }
    }

    /// The daemon is actually usable (socket bound, backends up).
    pub fn ready(&self) {
        self.send("READY=1");
        tracing::info!(target: "notify", "READY=1");
    }

    /// Graceful shutdown started.
    pub fn stopping(&self) {
        self.send("STOPPING=1");
        tracing::info!(target: "notify", "STOPPING=1");
    }

    /// Watchdog heartbeat. Only arms a timer when `WATCHDOG_USEC` is set:
    /// with no watchdog the daemon stays fully idle (spec §7).
    pub fn watchdog_interval(&self) -> Option<Duration> {
        let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
        if usec == 0 {
            return None;
        }
        Some(Duration::from_micros(usec / 2).max(Duration::from_millis(250)))
    }

    pub fn watchdog_tick(&self) {
        self.send("WATCHDOG=1");
    }

    pub fn is_active(&self) -> bool {
        self.sock.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_without_socket_is_noop() {
        let n = Notify { sock: None };
        n.ready();
        n.stopping();
        n.watchdog_tick();
        assert!(!n.is_active());
    }

    #[test]
    fn listen_fd_absent_by_default() {
        // This test runs without systemd activation env; the fd claim is
        // exercised in sysffi tests.
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");
        assert!(crate::sysffi::take_listen_fd().is_none());
    }

    #[test]
    fn watchdog_interval_math() {
        // Without WATCHDOG_USEC → None (idle daemon: no timers).
        std::env::remove_var("WATCHDOG_USEC");
        let n = Notify { sock: None };
        assert!(n.watchdog_interval().is_none());
        std::env::set_var("WATCHDOG_USEC", "60000000");
        assert_eq!(n.watchdog_interval(), Some(Duration::from_secs(30)));
        std::env::remove_var("WATCHDOG_USEC");
    }
}
