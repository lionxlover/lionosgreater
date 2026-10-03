#![forbid(unsafe_code)]
//! logind integration (spec 01 §3 "Hand-off", §4 `Power`).
//!
//! Trait seam so tests can run without a system bus: [`LogindSessions`]
//! with [`RealLogind`] (zbus, blocking connection used from
//! `spawn_blocking`) and [`MockLogind`].
//!
//! Session reuse (switch-to-running-session) is deferred to v2 (spec §11)
//! — `ListSessions` reports *installable session types*, not running
//! logind sessions; see DESIGN.md.

use crate::proto::PowerAction;
use crate::sysffi;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Parameters for `org.freedesktop.login1.Manager.CreateSession`.
#[derive(Debug, Clone)]
pub struct SessionRequest {
    /// Pid of the process that will become the session leader (our forked
    /// child, pre-exec).
    pub pid: u32,
    pub uid: u32,
    pub service: String,
    pub session_type: String,
    pub class: String,
    pub desktop: String,
    pub seat: String,
    pub vtnr: u32,
}

impl SessionRequest {
    pub fn for_child(pid: u32, uid: u32, desktop: &str, seat: &str) -> Self {
        SessionRequest {
            pid,
            uid,
            service: "lion-greeter".into(),
            session_type: "wayland".into(),
            class: "user".into(),
            desktop: desktop.into(),
            seat: seat.into(),
            vtnr: 0,
        }
    }
}

/// What logind gave back for a registered session.
#[derive(Debug, Clone)]
pub struct RegisteredSession {
    pub id: String,
    pub runtime_path: String,
}

/// Seam over org.freedesktop.login1.
pub trait LogindSessions: Send + Sync {
    fn create_session(&self, req: &SessionRequest) -> Result<RegisteredSession, String>;

    /// Reboot/poweroff/suspend (privileged; the UI socket gate + config
    /// allow-list are the authorization).
    fn power(&self, action: PowerAction) -> Result<(), String>;

    fn describe(&self) -> &'static str;
}

// ── Real implementation (zbus) ─────────────────────────────────────────
/// Blocking zbus connection to the system bus, established lazily and
/// kept for the daemon's lifetime. A failure to connect denies the
/// privileged action (fail closed, spec §8) without killing the greeter.
#[cfg(feature = "real-logind")]
pub struct RealLogind {
    conn: Mutex<Option<zbus::blocking::Connection>>,
}

#[cfg(feature = "real-logind")]
impl Default for RealLogind {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "real-logind")]
impl RealLogind {
    pub fn new() -> Self {
        RealLogind {
            conn: Mutex::new(None),
        }
    }

    fn conn(&self) -> Result<zbus::blocking::Connection, String> {
        let mut guard = self.conn.lock().map_err(|e| e.to_string())?;
        if let Some(c) = guard.as_ref() {
            return Ok(c.clone());
        }
        let c = zbus::blocking::Connection::system().map_err(|e| format!("system bus: {e}"))?;
        *guard = Some(c.clone());
        Ok(c)
    }

    /// Build a manager proxy scoped to a live connection reference.
    fn with_manager<R>(
        &self,
        f: impl FnOnce(&zbus::blocking::Proxy<'_>) -> Result<R, String>,
    ) -> Result<R, String> {
        let conn = self.conn()?;
        let proxy = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .map_err(|e| e.to_string())?;
        f(&proxy)
    }
}

#[cfg(feature = "real-logind")]
impl LogindSessions for RealLogind {
    fn create_session(&self, req: &SessionRequest) -> Result<RegisteredSession, String> {
        self.with_manager(|proxy| {
            // (pid, uid, service, type, class, desktop, seat, tty, vtnr,
            //  remote, remote_user, remote_host)
            let tty = "";
            let reply: (
                String,
                zbus::zvariant::OwnedObjectPath,
                String,
                zbus::zvariant::OwnedFd,
                String,
                u32,
            ) = proxy
                .call(
                    "CreateSession",
                    &(
                        req.pid,
                        req.uid,
                        req.service.as_str(),
                        req.session_type.as_str(),
                        req.class.as_str(),
                        req.desktop.as_str(),
                        req.seat.as_str(),
                        tty,
                        req.vtnr,
                        false,
                        "",
                        "",
                    ),
                )
                .map_err(|e| format!("CreateSession: {e}"))?;
            // The returned fd belongs to the session leader (tty/seat
            // master). Our child execs lion-session which re-acquires what
            // it needs; drop the fd here (OwnedFd closes on drop).
            drop(reply.3);
            Ok(RegisteredSession {
                id: reply.0,
                runtime_path: reply.2,
            })
        })
    }

    fn power(&self, action: PowerAction) -> Result<(), String> {
        self.with_manager(|proxy| {
            let method = match action {
                PowerAction::Reboot => "Reboot",
                PowerAction::PowerOff => "PowerOff",
                PowerAction::Suspend => "Suspend",
            };
            let interactive = false;
            let (): () = proxy
                .call(method, &(interactive))
                .map_err(|e| format!("{method}: {e}"))?;
            Ok(())
        })
    }

    fn describe(&self) -> &'static str {
        "logind via zbus (system bus)"
    }
}

// ── Mock ───────────────────────────────────────────────────────────────
/// Records calls; hands out sequential fake session ids.
#[derive(Default)]
pub struct MockLogind {
    counter: AtomicU64,
    pub sessions: Mutex<Vec<SessionRequest>>,
    pub power_calls: Mutex<Vec<PowerAction>>,
    pub fail_create: bool,
    pub fail_power: bool,
}

impl MockLogind {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LogindSessions for MockLogind {
    fn create_session(&self, req: &SessionRequest) -> Result<RegisteredSession, String> {
        if self.fail_create {
            return Err("mock: create_session failed".into());
        }
        self.sessions
            .lock()
            .map_err(|e| e.to_string())?
            .push(req.clone());
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(RegisteredSession {
            id: format!("mock-session-{n}"),
            runtime_path: format!("/run/user/{}", req.uid),
        })
    }

    fn power(&self, action: PowerAction) -> Result<(), String> {
        if self.fail_power {
            return Err("mock: power failed".into());
        }
        self.power_calls
            .lock()
            .map_err(|e| e.to_string())?
            .push(action);
        Ok(())
    }

    fn describe(&self) -> &'static str {
        "mock-logind"
    }
}

/// Convenience: are we running as root (privileged launch path)?
pub fn privileged() -> bool {
    sysffi::is_root()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_logind_roundtrip() {
        let m = MockLogind::new();
        let req = SessionRequest::for_child(4242, 1000, "lion", "seat0");
        let s = m.create_session(&req).unwrap();
        assert_eq!(s.id, "mock-session-0");
        assert_eq!(s.runtime_path, "/run/user/1000");
        m.power(PowerAction::Reboot).unwrap();
        assert_eq!(m.power_calls.lock().unwrap().len(), 1);
        assert_eq!(m.sessions.lock().unwrap()[0].pid, 4242);
    }

    #[test]
    fn mock_logind_failure_modes() {
        let m = MockLogind {
            fail_create: true,
            ..MockLogind::new()
        };
        assert!(m
            .create_session(&SessionRequest::for_child(1, 1, "l", "s"))
            .is_err());
        let m = MockLogind {
            fail_power: true,
            ..MockLogind::new()
        };
        assert!(m.power(PowerAction::Suspend).is_err());
    }

    #[cfg(feature = "real-logind")]
    #[test]
    fn real_logind_fails_closed_without_bus() {
        // No system bus in the sandbox: must fail closed, not panic.
        let r = RealLogind::new();
        let err = r.power(PowerAction::Reboot).unwrap_err();
        assert!(!err.is_empty());
    }
}
