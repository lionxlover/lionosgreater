//! PAM authentication + `lion-session` handoff, run on a dedicated OS
//! thread so the (blocking) PAM stack never stalls the async runtime.
//!
//! The thread owns the PAM session for its whole life: it authenticates,
//! re-establishes credentials (kerberos / keyring cleanup), opens the
//! PAM session (logind registration via pam_systemd), spawns
//! `lion-session` as the user, reports success, then waits for the
//! session to exit and closes the PAM session cleanly.
//!
//! # 0.5.0: live conversation forwarding
//! The worker no longer answers PAM prompts from a fixed password
//! buffer. It runs a `UiBridge` (see the private module docs) that:
//!
//! 1. answers the *first* echo-off prompt with the password the UI
//!    already collected (classic `pam_unix` round — the UI never sees
//!    a second prompt);
//! 2. forwards every other prompt (2FA code, security-key touch,
//!    password-change rounds) to the async layer, which relays it as a
//!    D-Bus `ConversationPrompt` signal and parks the worker on a
//!    condvar until the UI replies, the user cancels, or a 30 s
//!    deadline expires.
//!
//! This is the difference between "works with pam_unix" and "works
//! with any PAM stack a security-conscious site actually deploys"
//! (pam_google_authenticator, pam_u2f, pam_fido2, pam_pkcs11, SSSD …).
//!
//! # 0.5.0: autologin
//! [`spawn_autologin`] runs the identical session- establishment flow
//! but against the dedicated `lion-greeter-autologin` PAM stack with a
//! no-op conversation. If that stack refuses (site policy says the
//! account still needs a password), the failure is reported as
//! `AuthError::AutologinUnavailable` — the caller falls back to the
//! normal interactive path and, crucially, does *not* charge the
//! attempt against the user's throttle budget (it is not the user's
//! fault the stack said no).
//!
//! Hardening (additions over the original `pam-client` flow):
//! * All file descriptors other than stdio are closed before `execve` —
//!   so any FD the daemon happens to hold (D-Bus socket, journal, etc.)
//!   cannot leak into the user's session.
//! * `RLIMIT_CORE = 0` is set on the child so a session crash never
//!   writes a core dump that could be read by another user later.
//! * The login thread installs a panic hook so a panic is logged with a
//!   structured backtrace and turned into `AuthError::Service` rather
//!   than aborting the whole daemon.

use crate::pam_ffi::{self, ConvBridge, ConvSide, PamContext, Prompt, PromptStyle, PAM_CONV_ERR};
use crate::users_enum::LocalUser;
use std::{
    ffi::CString,
    io,
    os::{fd::RawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use zeroize::Zeroizing;

const PAM_SERVICE: &str = "lion-greeter";
/// Dedicated PAM stack for passwordless sign-in. Ships as
/// `pam.d/lion-greeter-autologin`; a site that wants autologin to
/// *require* something (group membership, a plugged token) expresses
/// that in the stack, not in the greeter.
pub const PAM_AUTOLOGIN_SERVICE: &str = "lion-greeter-autologin";
const LION_SESSION_BIN: &str = "/usr/bin/lion-session";

/// PAM service name. Exposed so other modules (e.g. `--check-pam` in
/// main.rs) can reference it without duplicating the literal.
pub fn pam_service() -> &'static str {
    PAM_SERVICE
}

/// Graceful shutdown hint: how long to wait before giving up on a stuck
/// PAM call. PAM modules that block on LDAP/Kerberos are the common
/// source of "greeter hung forever"; the D-Bus layer can use this to
/// bound its own cancel timeout. Also bounds every forwarded
/// conversation round: a prompt nobody answers is a prompt we walk
/// away from, never a hang.
pub const PAM_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Incorrect username or password")]
    InvalidCredentials,
    #[error("This account is locked or has expired")]
    AccountInvalid,
    #[error("Could not start your session")]
    SessionFailed,
    #[error("Sign-in is temporarily unavailable")]
    Service,
    #[error("Sign-in was canceled")]
    Canceled,
    #[error("Automatic sign-in is unavailable")]
    AutologinUnavailable,
}

/// Progress stages streamed to the UI (drives its animations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Verifying,
    Authorized,
    StartingSession,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Verifying => "verifying",
            Stage::Authorized => "authorized",
            Stage::StartingSession => "starting_session",
        }
    }
}

// ── conversation plumbing (worker thread -> async layer -> UI) ────────

/// One pending conversation round, shared between the worker thread
/// (which waits) and the async layer (which deposits the UI's answer
/// or a cancellation).
pub struct ConvSlot {
    state: Mutex<ConvState>,
    cv: Condvar,
}

struct ConvState {
    /// The UI's answers (one per prompt in the round). `None` until the
    /// reply arrives.
    answers: Option<Vec<String>>,
    /// Set when CancelAuth (or shutdown) aborts the round.
    cancelled: bool,
}

impl ConvSlot {
    /// Build a fresh, un-answered round. Public so the IPC layer (and
    /// its tests) can construct slots when wiring events.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(ConvState {
                answers: None,
                cancelled: false,
            }),
            cv: Condvar::new(),
        })
    }

    /// Deposit the UI's answers and wake the worker. Returns false if
    /// the round was already answered or cancelled (stale/spoofed id).
    pub fn complete(&self, answers: Vec<String>) -> bool {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if g.answers.is_some() || g.cancelled {
            return false;
        }
        g.answers = Some(answers);
        self.cv.notify_all();
        true
    }

    /// Abort the round (cancel/shutdown). Idempotent.
    pub fn cancel(&self) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.cancelled = true;
        self.cv.notify_all();
    }
}

/// Event handed from the worker thread to the async layer: "PAM is
/// asking this; here is the slot to stuff the answers into."
pub struct ConvEvent {
    pub id: u64,
    pub prompts: Vec<Prompt>,
    pub slot: Arc<ConvSlot>,
}

/// The bridge PAM talks to. Holds the one-shot password collected by
/// the UI; anything else becomes a [`ConvEvent`] round-trip.
struct UiBridge {
    /// Channel to the async layer (which emits D-Bus signals).
    tx: UnboundedSender<ConvEvent>,
    /// Shared cancel flag (same Arc as the login's `cancel`).
    cancel: Arc<AtomicBool>,
    /// The password the UI already collected; consumed by the first
    /// echo-off prompt (classic `pam_unix` "Password:" round) and then
    /// gone — a *second* echo-off prompt (2FA, password change) can
    /// only be answered by a real UI round-trip.
    password: Option<Zeroizing<Vec<u8>>>,
}

impl UiBridge {
    /// Answers a round entirely from fixed data (no UI round-trip).
    fn answer_static(
        &self,
        prompts: &[Prompt],
        password: &Zeroizing<Vec<u8>>,
    ) -> Vec<Zeroizing<String>> {
        prompts
            .iter()
            .map(|p| {
                if p.style.expects_answer() {
                    // The Vec is NUL-terminated (built by zeroizing_cstr);
                    // trim the terminator back into a plain String.
                    let end = password.len().saturating_sub(1);
                    Zeroizing::new(String::from_utf8_lossy(&password[..end]).into_owned())
                } else {
                    Zeroizing::new(String::new())
                }
            })
            .collect()
    }

    /// Wait for the UI's answer, honoring cancel + deadline. Returns
    /// `Err(PAM_CONV_ERR)` on any give-up path — libpam then aborts
    /// the operation cleanly and the worker surfaces a cancel/failure.
    fn wait_for_reply(&self, slot: &Arc<ConvSlot>) -> Result<Vec<String>, i32> {
        let deadline = Instant::now() + PAM_DEADLINE;
        let mut guard = slot.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(answers) = guard.answers.take() {
                return Ok(answers);
            }
            if guard.cancelled || self.cancel.load(Ordering::Acquire) {
                return Err(PAM_CONV_ERR);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(PAM_CONV_ERR);
            }
            let (g, _) = slot
                .cv
                .wait_timeout(guard, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
        }
    }
}

impl ConvBridge for UiBridge {
    fn converse(&mut self, prompts: &[Prompt]) -> Result<Vec<Zeroizing<String>>, i32> {
        // Decision: can this round be answered without the UI? Only if
        // it contains exactly one promptable prompt, that prompt is
        // echo-off, and we still hold the password. This is precisely
        // the shape of a `pam_unix` password round; anything richer
        // (2FA, multi-field password change, echo-on prompts) is a
        // genuine question for the human at the screen.
        let promptable: Vec<usize> = prompts
            .iter()
            .enumerate()
            .filter(|(_, p)| p.style.expects_answer())
            .map(|(i, _)| i)
            .collect();
        let single_password_round = promptable.len() == 1
            && prompts[promptable[0]].style == PromptStyle::EchoOff
            && self.password.is_some();

        if single_password_round {
            // take() — the password answers exactly one prompt, ever.
            let pw = self.password.take().expect("checked above");
            return Ok(self.answer_static(prompts, &pw));
        }

        if promptable.is_empty() {
            // Pure info/error round with nothing to answer (e.g. the
            // motd module saying hi). Log it for the journal and tell
            // PAM "no response needed" — do not bother the UI.
            for p in prompts {
                match p.style {
                    PromptStyle::Info => tracing::info!(pam.text = %p.text, "PAM info"),
                    PromptStyle::Error => tracing::warn!(pam.text = %p.text, "PAM error"),
                    _ => unreachable!("no promptable prompts in this round"),
                }
            }
            return Ok(prompts
                .iter()
                .map(|_| Zeroizing::new(String::new()))
                .collect());
        }

        // Forward the full round (info/error lines included — the UI
        // may want to render them above the input field).
        let slot = ConvSlot::new();
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let event = ConvEvent {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            prompts: prompts.to_vec(),
            slot: slot.clone(),
        };
        tracing::debug!(
            conv_id = event.id,
            prompts = prompts.len(),
            "forwarding PAM conversation to UI"
        );
        if self.tx.send(event).is_err() {
            // Async layer is gone (daemon shutting down). Abort.
            return Err(PAM_CONV_ERR);
        }

        let answers = self.wait_for_reply(&slot)?;
        if answers.len() != prompts.len() {
            // UI violated the protocol; refuse rather than misalign.
            return Err(PAM_CONV_ERR);
        }

        // Re-wrap the UI's strings so every answer (including any
        // secret) is zeroized on drop by the caller's ownership rules.
        Ok(answers
            .into_iter()
            .map(|a| {
                let z: Zeroizing<String> = Zeroizing::new(a);
                z
            })
            .collect())
    }
}

// ── worker spawning ───────────────────────────────────────────────────

/// Spawn the interactive login worker. The cancel flag lets the D-Bus
/// layer request cooperative cancellation; if it is set before the
/// session is up, the worker aborts at the next checkpoint (or at the
/// current conversation round). Progress arrives on `stages`; live PAM
/// prompts arrive on `conv_tx` (see [`ConvEvent`]). `session` is the
/// chosen desktop session (0.6.0): passed to `lion-session` via
/// `--session` and used to set `XDG_SESSION_DESKTOP`/
/// `XDG_CURRENT_DESKTOP`. `None` = no preference; `lion-session`'s own
/// default applies. Result arrives on `ready`.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "spawn_login",
    skip(password, stages, cancel, conv_tx, session),
    fields(user = %user.username, uid = user.uid, session = session.as_ref().map(|s| s.id.as_str()).unwrap_or("(default)")),
)]
pub fn spawn_login(
    user: LocalUser,
    password: Zeroizing<String>,
    stages: UnboundedSender<Stage>,
    cancel: std::sync::Arc<AtomicBool>,
    conv_tx: UnboundedSender<ConvEvent>,
    session: Option<crate::sessions::SessionEntry>,
) -> oneshot::Receiver<Result<u32, AuthError>> {
    let bridge = UiBridge {
        tx: conv_tx,
        cancel: cancel.clone(),
        // Embedded NUL in the password is not a valid PAM secret: pass
        // None so the bridge forwards the prompt to the UI instead of
        // silently mis-authenticating.
        password: crate::pam_ffi::zeroizing_cstr(password.as_str()).ok(),
    };
    let side = ConvSide::Interactive(Box::new(bridge));
    spawn_worker(user, PAM_SERVICE, side, stages, cancel, session)
}

/// Spawn the autologin worker: same session ceremony, no password, and
/// the dedicated `lion-greeter-autologin` PAM stack. Refusal by that
/// stack surfaces as `AuthError::AutologinUnavailable` — callers fall
/// back to the interactive flow without penalizing the user. The
/// session is resolved by the caller (config default, else
/// last-chosen) so kiosk deployments pin it in `greeter.toml`.
#[tracing::instrument(
    name = "spawn_autologin",
    skip(stages, cancel, session),
    fields(user = %user.username, uid = user.uid, session = session.as_ref().map(|s| s.id.as_str()).unwrap_or("(default)")),
)]
pub fn spawn_autologin(
    user: LocalUser,
    stages: UnboundedSender<Stage>,
    cancel: std::sync::Arc<AtomicBool>,
    session: Option<crate::sessions::SessionEntry>,
) -> oneshot::Receiver<Result<u32, AuthError>> {
    use crate::pam_ffi::StaticAnswers;
    let side = ConvSide::Static(StaticAnswers {
        username: CString::new(user.username.as_str()).unwrap_or_default(),
        password: Zeroizing::new(b"\0".to_vec()),
    });
    spawn_worker(user, PAM_AUTOLOGIN_SERVICE, side, stages, cancel, session)
}

fn spawn_worker(
    user: LocalUser,
    service: &'static str,
    side: ConvSide,
    stages: UnboundedSender<Stage>,
    cancel: std::sync::Arc<AtomicBool>,
    session: Option<crate::sessions::SessionEntry>,
) -> oneshot::Receiver<Result<u32, AuthError>> {
    let (tx, rx) = oneshot::channel();
    let spawned = std::thread::Builder::new()
        .name("lion-greeter-login".into())
        .spawn(move || {
            // A panic inside the worker must never escape into the
            // async runtime as an abort; convert it to AuthError::Service.
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                worker(user, service, side, stages, &cancel, session)
            }));
            let outcome = match res {
                Ok(Ok(pid)) => Ok(pid),
                Ok(Err(e)) => Err(e),
                Err(p) => {
                    tracing::error!(panic = ?p, "login worker panicked");
                    Err(AuthError::Service)
                }
            };
            let _ = tx.send(outcome);
        });
    if let Err(e) = spawned {
        tracing::error!(error = %e, "could not spawn login thread");
        // `tx` was moved into the closure passed to `spawn`, which has
        // been dropped along with it. The receiver will return
        // `RecvError::Closed`; the D-Bus layer turns that into
        // `AuthError::Service`.
    }
    rx
}

#[tracing::instrument(
    name = "login_worker",
    skip(side, stages, cancel),
    fields(user = %user.username, uid = user.uid),
)]
fn worker(
    user: LocalUser,
    service: &'static str,
    side: ConvSide,
    stages: UnboundedSender<Stage>,
    cancel: &std::sync::Arc<AtomicBool>,
    session: Option<crate::sessions::SessionEntry>,
) -> Result<u32, AuthError> {
    if cancel.load(Ordering::Acquire) {
        return Err(AuthError::Canceled);
    }
    let _ = stages.send(Stage::Verifying);

    let mut ctx = match PamContext::start_with(service, &user.username, side) {
        Ok(c) => c,
        Err(code) => {
            tracing::error!(user = %user.username, service, pam_code = code, "PAM init failed");
            return Err(AuthError::Service);
        }
    };
    // (any password Zeroizing buffers now live inside the conversation
    //  side and are wiped when the PamContext drops.)

    if cancel.load(Ordering::Acquire) {
        return Err(AuthError::Canceled);
    }

    if let Err(code) = ctx.authenticate(true) {
        tracing::warn!(user = %user.username, pam_code = code, "authentication failed");
        if service == PAM_AUTOLOGIN_SERVICE {
            // The autologin stack said no. Not the user's fault, not a
            // brute-force signal: report it as "unavailable" so the
            // caller falls back to the interactive flow.
            return Err(AuthError::AutologinUnavailable);
        }
        return Err(map_pam(code));
    }
    if let Err(code) = ctx.acct_mgmt(true) {
        if service == PAM_AUTOLOGIN_SERVICE {
            return Err(AuthError::AutologinUnavailable);
        }
        return Err(map_pam(code));
    }
    let _ = stages.send(Stage::Authorized);

    // Re-establish credentials cleanly. pam_systemd doesn't care, but
    // pam_krb5 / pam_gnome_keyring / pam_pkcs11 do; doing this here means
    // a stale kerberos ticket from a previous session is replaced rather
    // than reused. Errors here are non-fatal (we may not have any of
    // those modules), so we log but don't fail.
    if let Err(code) = ctx.setcred_reinit() {
        tracing::debug!(user = %user.username, pam_code = code, "setcred reinit failed (non-fatal)");
    }

    if cancel.load(Ordering::Acquire) {
        return Err(AuthError::Canceled);
    }

    let _ = stages.send(Stage::StartingSession);
    if let Err(code) = ctx.open_session(true) {
        tracing::error!(user = %user.username, pam_code = code, "open_session failed");
        return Err(AuthError::SessionFailed);
    }

    // Snapshot the env before we move ctx into the guard; libpam's
    // envlist is owned by the handle and lives until drop.
    let pam_env = ctx.envlist();

    let mut cmd = build_command(&user, &pam_env, session.as_ref());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to exec {LION_SESSION_BIN}");
            return Err(AuthError::SessionFailed);
        }
    };
    let pid = child.id();
    tracing::info!(user = %user.username, pid, "session started");

    // Keep the PAM session (and thus the logind session) alive until
    // the user's session exits, then close it cleanly. Drop of `ctx`
    // calls `pam_close_session` + `pam_end`.
    let status = child.wait();
    tracing::info!(user = %user.username, ?status, "session ended");
    drop(ctx);

    Ok(pid)
}

fn build_command(
    user: &LocalUser,
    pam_env: &[(String, String)],
    session: Option<&crate::sessions::SessionEntry>,
) -> Command {
    let runtime_dir = format!("/run/user/{}", user.uid);

    let mut cmd = Command::new(LION_SESSION_BIN);
    cmd.arg("--user").arg(&user.username);
    // 0.6.0: name the chosen desktop session. `lion-session` owns what
    // the id means; the greeter only passes the validated id through.
    if let Some(s) = session {
        cmd.arg("--session").arg(&s.id);
    }
    // Desktop names from the session file ("LionOS", "GNOME", …)
    // become XDG_CURRENT_DESKTOP — autostart filtering in lion-session
    // (OnlyShowIn/NotShowIn) keys off exactly this variable.
    let current_desktop = session
        .and_then(|s| (!s.desktop_names.is_empty()).then(|| s.desktop_names.join(":")))
        .unwrap_or_else(|| "LionOS".to_owned());
    let session_desktop = session.map(|s| s.id.clone());
    cmd.env_clear()
        .env("HOME", &user.home)
        .env("USER", &user.username)
        .env("LOGNAME", &user.username)
        .env("SHELL", &user.shell)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("XDG_SESSION_TYPE", "wayland")
        .env("XDG_SESSION_CLASS", "user")
        .env("XDG_CURRENT_DESKTOP", current_desktop)
        .env("XDG_RUNTIME_DIR", &runtime_dir)
        .envs(
            session_desktop
                .iter()
                .map(|v| ("XDG_SESSION_DESKTOP", v.as_str())),
        )
        // PAM-provided env (XDG_SESSION_ID, XDG_RUNTIME_DIR overrides,
        // pam_env(5) vars, etc.) goes last so it wins where appropriate.
        .envs(pam_env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    cmd.current_dir(&user.home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());

    let (uid, gid) = (user.uid, user.gid);
    let cname = CString::new(user.username.clone()).unwrap_or_default();
    // SAFETY: runs between fork and exec; only async-signal-safe libc calls.
    // Order matters: supplementary groups -> gid -> uid (uid drop last).
    unsafe {
        cmd.pre_exec(move || {
            // 1. Become a session leader so the child has no controlling
            //    tty inherited from the greeter.
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            // 2. Set supplementary groups (initgroups also clears the
            //    set first on glibc, but we call setgroups(0, NULL)
            //    explicitly to be paranoid and portable).
            libc::setgroups(0, std::ptr::null());
            if libc::initgroups(cname.as_ptr(), gid) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            // 3. Paranoia: privileges must be unrecoverable.
            if libc::setuid(0) == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "uid drop failed",
                ));
            }
            // 4. Disable core dumps for the session (privacy).
            let rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &rl);
            // 5. Close every inherited FD other than stdio. Anything we
            //    hold in the greeter (D-Bus socket, journal, secrets)
            //    must not leak into the user's session. /proc/self/fd
            //    is opened after setuid so we are already unprivileged.
            close_fds_except_stdio_preexec();
            Ok(())
        });
    }
    cmd
}

/// Close every file descriptor the daemon happens to have open, other
/// than 0/1/2, before execve-ing the user session. We walk
/// `/proc/self/fd`, which is the lowest-overhead and most reliable way
/// on Linux. Done *after* the uid drop so we walk as the unprivileged
/// user (we only close our own FDs anyway).
fn close_fds_except_stdio_preexec() {
    let dir = match std::fs::read_dir("/proc/self/fd") {
        Ok(d) => d,
        Err(_) => return,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let fd: RawFd = match name.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if fd <= 2 {
            continue;
        }
        // Best-effort: ignore EBADF (already-closed), EINVAL (e.g. an
        // O_PATH FD that's not really closeable), etc.
        unsafe {
            let _ = libc::close(fd);
        }
    }
}

fn map_pam(code: i32) -> AuthError {
    use pam_ffi::*;
    match code {
        PAM_AUTH_ERR | PAM_USER_UNKNOWN | PAM_CRED_INSUFFICIENT | PAM_MAXTRIES => {
            AuthError::InvalidCredentials
        }
        PAM_ACCT_EXPIRED | PAM_NEW_AUTHTOK_REQD | PAM_PERM_DENIED => AuthError::AccountInvalid,
        _ => AuthError::Service,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ConvSlot round-trip: complete() deposits answers and wakes the
    /// waiter; a second complete() on the same slot is rejected (stale
    /// id protection).
    #[test]
    fn conv_slot_complete_once_only() {
        let slot = ConvSlot::new();
        assert!(slot.complete(vec!["a".into(), "b".into()]));
        // Second completion of the same round: rejected.
        assert!(!slot.complete(vec!["c".into(), "d".into()]));
        // The deposited answers are the first ones.
        let g = slot.state.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(
            g.answers.as_deref(),
            Some(&["a".to_string(), "b".to_string()][..])
        );
    }

    /// After cancellation, a late UI reply is refused — a stale client
    /// cannot resurrect an aborted round.
    #[test]
    fn conv_slot_cancel_beats_late_reply() {
        let slot = ConvSlot::new();
        slot.cancel();
        assert!(!slot.complete(vec!["late".into()]));
    }

    /// The bridge's static password path: exactly one echo-off prompt +
    /// a held password = answered locally, no event ever sent, and the
    /// password is spent afterwards.
    #[test]
    fn ui_bridge_password_short_circuit() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConvEvent>();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut bridge = UiBridge {
            tx,
            cancel,
            password: Some(Zeroizing::new(b"pw\0".to_vec())),
        };
        let prompts = vec![Prompt {
            style: PromptStyle::EchoOff,
            text: "Password:".into(),
        }];
        let answers = bridge.converse(&prompts).expect("answered locally");
        assert_eq!(answers[0].as_str(), "pw");
        // No conversation event was emitted …
        assert!(rx.try_recv().is_err());
        // … and the password is spent: a second identical round would now
        // be forwarded (covered by the two-factor flow test below).
        assert!(bridge.password.is_none());
    }

    /// Pure info rounds are answered locally with no UI event.
    #[test]
    fn ui_bridge_info_round_no_event() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConvEvent>();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut bridge = UiBridge {
            tx,
            cancel,
            password: Some(Zeroizing::new(b"pw\0".to_vec())),
        };
        let prompts = vec![
            Prompt {
                style: PromptStyle::Info,
                text: "Welcome".into(),
            },
            Prompt {
                style: PromptStyle::Error,
                text: "Last login: never".into(),
            },
        ];
        let answers = bridge.converse(&prompts).expect("answered locally");
        assert!(answers.iter().all(|a| a.is_empty()));
        assert!(rx.try_recv().is_err());
    }

    /// Two-factor shape: first round answered from the stored password,
    /// second round forwarded — the wire shape the D-Bus layer emits.
    #[test]
    fn ui_bridge_two_factor_flow_shape() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ConvEvent>();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut bridge = UiBridge {
            tx,
            cancel,
            password: Some(Zeroizing::new(b"pw\0".to_vec())),
        };

        // Round 1: password.
        let r1 = vec![Prompt {
            style: PromptStyle::EchoOff,
            text: "Password:".into(),
        }];
        assert_eq!(bridge.converse(&r1).unwrap()[0].as_str(), "pw");

        // Round 2: OTP prompt from pam_google_authenticator.
        let r2 = vec![Prompt {
            style: PromptStyle::EchoOff,
            text: "Verification code:".into(),
        }];
        // converse() will block waiting for a reply — spawn it.
        let handle = std::thread::spawn(move || {
            let answers = bridge.converse(&r2).expect("round 2 forwarded");
            answers[0].as_str().to_owned()
        });

        // The event may race the thread start: poll briefly for it.
        let event = poll_event(&mut rx).expect("round 2 forwarded as an event");
        assert_eq!(event.prompts[0].text, "Verification code:");
        assert_eq!(event.prompts[0].style.as_str(), "echo_off");
        event.slot.complete(vec!["987654".into()]);
        assert_eq!(handle.join().expect("bridge thread"), "987654");
    }

    /// Poll a conversation channel for up to 5 s (thread start can race
    /// the send; the wait is bounded and tiny in practice).
    fn poll_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ConvEvent>) -> Option<ConvEvent> {
        for _ in 0..500 {
            if let Ok(ev) = rx.try_recv() {
                return Some(ev);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        None
    }
}
