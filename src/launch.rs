#![forbid(unsafe_code)]
//! Session launch (spec 01 §3 "Hand-off").
//!
//! Real path (root only): fork → child parks on the env pipe → logind
//! `CreateSession(pid=child)` → write the clean `XDG_SESSION_*`
//! environment → child does chdir/setgroups/setgid/setuid/execve of
//! `lion-session` (or the chosen wayland-session Exec).
//!
//! Guest path: mount a tmpfs home first ([`Mounter`] seam), launch the
//! configured guest account, and detach the tmpfs lazily on cleanup.
//!
//! Mock path records everything for tests.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::logind::{LogindSessions, SessionRequest};
use crate::proto::{codes, Response};
use crate::sessions::SessionInfo;
use crate::sysffi::{self, ChildSpec, ExecStatus, SpawnedChild};
use crate::users::UserInfo;
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// tmpfs mount seam.
pub trait Mounter: Send + Sync {
    fn mount_tmpfs(&self, target: &Path, opts: &str) -> std::io::Result<()>;
    fn umount_lazy(&self, target: &Path) -> std::io::Result<()>;
    fn describe(&self) -> &'static str;
}

/// Real mounts (syscall-backed, audited in sysffi).
pub struct RealMounter;

impl Mounter for RealMounter {
    fn mount_tmpfs(&self, target: &Path, opts: &str) -> std::io::Result<()> {
        sysffi::mount_tmpfs(target, opts)
    }

    fn umount_lazy(&self, target: &Path) -> std::io::Result<()> {
        sysffi::umount_lazy(target)
    }

    fn describe(&self) -> &'static str {
        "mount(2) tmpfs"
    }
}

/// Records mounts (tests, dry environments).
#[derive(Default)]
pub struct MockMounter {
    pub mounted: std::sync::Mutex<Vec<(PathBuf, String)>>,
    pub unmounted: std::sync::Mutex<Vec<PathBuf>>,
    pub fail: bool,
}

impl Mounter for MockMounter {
    fn mount_tmpfs(&self, target: &Path, opts: &str) -> std::io::Result<()> {
        if self.fail {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "mock",
            ));
        }
        self.mounted
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .push((target.to_path_buf(), opts.to_string()));
        Ok(())
    }

    fn umount_lazy(&self, target: &Path) -> std::io::Result<()> {
        self.unmounted
            .lock()
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .push(target.to_path_buf());
        Ok(())
    }

    fn describe(&self) -> &'static str {
        "mock-mounter"
    }
}

/// Everything needed to launch one session.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub user: UserInfo,
    pub session: SessionInfo,
    /// Guest launch (tmpfs home, configured guest account).
    pub guest: bool,
    /// Seat to register on.
    pub seat: String,
}

/// Successful launch.
#[derive(Debug, Clone)]
pub struct LaunchSuccess {
    pub pid: u32,
    pub logind_session: String,
}

/// Launcher seam.
pub trait Launcher: Send + Sync {
    fn launch(&self, req: &LaunchRequest) -> Result<LaunchSuccess>;

    /// Build the argv for a session (shared by real+mock paths so tests
    /// can assert on it).
    fn describe(&self) -> &'static str;
}

/// Build the exec argv for a session entry. `Exec` lines are split on
/// whitespace (double/single quotes honoured); placeholders like `%u` are
/// not supported and such entries are rejected (fail closed).
pub fn session_argv(session: &SessionInfo) -> Result<Vec<CString>> {
    let exec = &session.exec;
    if exec.contains('%') {
        return Err(Error::Launch(format!(
            "session {} uses Exec placeholders (unsupported)",
            session.id
        )));
    }
    let mut argv = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in exec.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"') | (None, '\'') => quote = Some(c),
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    argv.push(
                        CString::new(cur.as_str())
                            .map_err(|_| Error::Launch("NUL in exec".into()))?,
                    );
                    cur.clear();
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if quote.is_some() {
        return Err(Error::Launch("unbalanced quote in Exec".into()));
    }
    if !cur.is_empty() {
        argv.push(CString::new(cur).map_err(|_| Error::Launch("NUL in exec".into()))?);
    }
    if argv.is_empty() {
        return Err(Error::Launch("empty Exec".into()));
    }
    Ok(argv)
}

/// Environment for the child, in `KEY=VALUE` form. Deliberately minimal
/// and identical for every session type (spec: "clean environment").
pub fn session_env(
    user: &UserInfo,
    session: &SessionInfo,
    logind: &crate::logind::RegisteredSession,
    home_override: Option<&Path>,
    seat: &str,
) -> Vec<(String, String)> {
    let home = home_override
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| user.home.display().to_string());
    vec![
        ("HOME".into(), home),
        ("USER".into(), user.name.clone()),
        ("LOGNAME".into(), user.name.clone()),
        ("SHELL".into(), user.shell.clone()),
        ("XDG_SESSION_ID".into(), logind.id.clone()),
        ("XDG_SESSION_TYPE".into(), "wayland".into()),
        ("XDG_SESSION_CLASS".into(), "user".into()),
        ("XDG_SESSION_DESKTOP".into(), session.id.clone()),
        ("XDG_CURRENT_DESKTOP".into(), session.id.clone()),
        ("XDG_RUNTIME_DIR".into(), logind.runtime_path.clone()),
        ("XDG_SEAT".into(), seat.to_string()),
        (
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        ),
    ]
}

/// The real, privileged launcher.
pub struct RealLauncher {
    logind: Arc<dyn LogindSessions>,
    mounts: Arc<dyn Mounter>,
    cfg: Config,
}

impl RealLauncher {
    pub fn new(logind: Arc<dyn LogindSessions>, mounts: Arc<dyn Mounter>, cfg: Config) -> Self {
        RealLauncher {
            logind,
            mounts,
            cfg,
        }
    }

    fn guest_home(&self) -> PathBuf {
        PathBuf::from(&self.cfg.greeter.guest.home)
    }

    fn prepare_guest(&self) -> Result<PathBuf> {
        let home = self.guest_home();
        std::fs::create_dir_all(&home)
            .map_err(|e| Error::Launch(format!("guest home {}: {e}", home.display())))?;
        self.mounts
            .mount_tmpfs(
                &home,
                &format!("size={},mode=700", self.cfg.greeter.guest.tmpfs_size),
            )
            .map_err(|e| Error::Launch(format!("tmpfs mount failed: {e}")))?;
        // Root-owned dirs inside; the session will chown what it needs.
        Ok(home)
    }
}

impl Launcher for RealLauncher {
    fn launch(&self, req: &LaunchRequest) -> Result<LaunchSuccess> {
        if !sysffi::is_root() {
            return Err(Error::Launch(format!(
                "refusing to launch: daemon must run as root (currently uid {})",
                sysffi::current_uid()
            )));
        }

        // Resolve the guest account when launching a guest session.
        let (user, home_override) = if req.guest {
            let guest_user = crate::users::UserDb::from_config(&self.cfg)
                .find_raw(&self.cfg.greeter.guest.user)
                .ok_or_else(|| {
                    Error::Launch(format!(
                        "guest account {:?} does not exist",
                        self.cfg.greeter.guest.user
                    ))
                })?;
            let home = self.prepare_guest()?;
            (guest_user, Some(home))
        } else {
            (req.user.clone(), None)
        };

        let argv = session_argv(&req.session)?;
        let groups =
            crate::users::supplementary_groups_from(&self.cfg.greeter.group_path, &user.name);
        let spec = ChildSpec {
            argv: argv.clone(),
            chdir: home_override
                .clone()
                .unwrap_or_else(|| user.home.clone())
                .to_str()
                .and_then(|s| CString::new(s).ok())
                .ok_or_else(|| Error::Launch("home path not representable".into()))?,
            uid: user.uid,
            gid: user.gid,
            groups,
        };

        // fork first: the child parks reading the env pipe while we
        // register the session with logind using its pid.
        let mut child: SpawnedChild =
            sysffi::fork_session_child(&spec).map_err(|e| Error::Launch(format!("fork: {e}")))?;

        let logind_req =
            SessionRequest::for_child(child.pid as u32, user.uid, &req.session.id, &req.seat);
        let registered = self.logind.create_session(&logind_req).map_err(|e| {
            // Best effort: reap the parked child instead of leaving it.
            sysffi::kill_child(child.pid);
            let _ = sysffi::wait_child(child.pid);
            Error::Launch(format!("logind: {e}"))
        })?;

        let env = session_env(
            &user,
            &req.session,
            &registered,
            home_override.as_deref(),
            &req.seat,
        );
        let env_block = encode_env(&env)?;
        use std::io::Write as _;
        child
            .env_tx
            .write_all(&env_block)
            .and_then(|_| child.env_tx.flush())
            .map_err(|e| Error::Launch(format!("env pipe: {e}")))?;
        drop(child.env_tx);

        match sysffi::wait_exec_status(&child.status_rx, Duration::from_secs(10)) {
            ExecStatus::Execed => {
                tracing::info!(
                    pid = child.pid,
                    logind_session = %registered.id,
                    session = %req.session.id,
                    user = %user.name,
                    guest = req.guest,
                    "session launched"
                );
                // Reap the session process when it eventually exits so it
                // never lingers as a zombie under the greeter.
                let pid = child.pid;
                std::thread::Builder::new()
                    .name("lion-greeter-reaper".into())
                    .spawn(move || {
                        if let Some(code) = sysffi::wait_child(pid) {
                            tracing::info!(pid, exit_code = code, "session process exited");
                        }
                    })
                    .ok();
                Ok(LaunchSuccess {
                    pid: child.pid as u32,
                    logind_session: registered.id,
                })
            }
            ExecStatus::TimedOut => {
                sysffi::kill_child(child.pid);
                let _ = sysffi::wait_child(child.pid);
                Err(Error::Launch(
                    "session process did not exec within 10 s".into(),
                ))
            }
            ExecStatus::Failed(errno) => {
                let _ = sysffi::wait_child(child.pid);
                Err(Error::Launch(format!(
                    "session process failed before exec (errno {errno})"
                )))
            }
        }
    }

    fn describe(&self) -> &'static str {
        "real launcher (fork/exec as user)"
    }
}

/// Encode env pairs as one NUL-separated block with a trailing NUL.
fn encode_env(env: &[(String, String)]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    for (k, v) in env {
        let k = k.as_bytes();
        let v = v.as_bytes();
        if k.is_empty() || k.contains(&b'=') || k.len() + v.len() > 1024 {
            return Err(Error::Launch("bad env key/value".into()));
        }
        out.extend_from_slice(k);
        out.push(b'=');
        out.extend_from_slice(v);
        out.push(0);
    }
    if out.len() > sysffi::MAX_ENV_BYTES {
        return Err(Error::Launch("env too large".into()));
    }
    out.push(0); // trailing empty marker; child scan stops at total boundary
    Ok(out)
}

/// Recording launcher for tests.
#[derive(Default)]
pub struct MockLauncher {
    pub launches: std::sync::Mutex<Vec<LaunchRequest>>,
    pub fail: bool,
    pub next_pid: std::sync::atomic::AtomicU32,
}

impl MockLauncher {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Launcher for MockLauncher {
    fn launch(&self, req: &LaunchRequest) -> Result<LaunchSuccess> {
        if self.fail {
            return Err(Error::Launch("mock launch failure".into()));
        }
        self.launches
            .lock()
            .map_err(|e| Error::Launch(e.to_string()))?
            .push(req.clone());
        let pid = self
            .next_pid
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 4321;
        Ok(LaunchSuccess {
            pid,
            logind_session: format!("mock-session-{pid}"),
        })
    }

    fn describe(&self) -> &'static str {
        "mock launcher"
    }
}

/// Map a launch failure to a protocol response (no secrets can leak:
/// launch errors contain paths/errnos only).
pub fn launch_error_response(id: u64, e: &Error) -> Response {
    let msg = match e {
        Error::Launch(m) => m.clone(),
        other => other.to_string(),
    };
    Response::err(id, codes::LAUNCH_FAILED, msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::SessionInfo;

    fn session(id: &str, exec: &str) -> SessionInfo {
        SessionInfo {
            id: id.into(),
            name: id.into(),
            exec: exec.into(),
            builtin: false,
        }
    }

    fn user() -> UserInfo {
        UserInfo {
            name: "alice".into(),
            uid: 1000,
            gid: 1000,
            real_name: "Alice".into(),
            shell: "/bin/bash".into(),
            home: "/home/alice".into(),
            avatar: None,
            last_session: None,
            is_guest: false,
        }
    }

    #[test]
    fn exec_line_parsing() {
        let argv = session_argv(&session("lion", "lion-session")).unwrap();
        assert_eq!(argv.len(), 1);
        assert_eq!(argv[0].to_bytes(), b"lion-session");

        let argv = session_argv(&session("s", "env WM=sway --arg \"two words\" 'x y'")).unwrap();
        let s: Vec<String> = argv.iter().map(|c| c.to_string_lossy().into()).collect();
        assert_eq!(s, vec!["env", "WM=sway", "--arg", "two words", "x y"]);

        assert!(session_argv(&session("s", "cmd %u")).is_err());
        assert!(session_argv(&session("s", "cmd \"unbalanced")).is_err());
        assert!(session_argv(&session("s", "   ")).is_err());
    }

    #[test]
    fn env_is_clean_and_bounded() {
        let reg = crate::logind::RegisteredSession {
            id: "c42".into(),
            runtime_path: "/run/user/1000".into(),
        };
        let env = session_env(
            &user(),
            &session("lion", "lion-session"),
            &reg,
            None,
            "seat0",
        );
        let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"XDG_SESSION_ID"));
        assert!(keys.contains(&"XDG_SESSION_TYPE"));
        assert!(keys.contains(&"XDG_RUNTIME_DIR"));
        assert!(!keys.iter().any(|k| k.contains("LION_SECRET")));
        assert_eq!(env.len(), 12);
        let block = encode_env(&env).unwrap();
        assert!(block.last() == Some(&0));
        assert!(block.len() <= sysffi::MAX_ENV_BYTES);
    }

    #[test]
    fn env_rejects_bad_keys() {
        let env = vec![("BAD=KEY".to_string(), "v".to_string())];
        assert!(encode_env(&env).is_err());
    }

    #[test]
    fn mock_launcher_records() {
        let l = MockLauncher::new();
        let out = l
            .launch(&LaunchRequest {
                user: user(),
                session: session("lion", "lion-session"),
                guest: false,
                seat: "seat0".into(),
            })
            .unwrap();
        assert_eq!(out.pid, 4321);
        assert_eq!(out.logind_session, "mock-session-4321");
        assert_eq!(l.launches.lock().unwrap().len(), 1);
    }
}
