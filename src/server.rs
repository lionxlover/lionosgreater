#![forbid(unsafe_code)]
//! The greeter daemon: accept loop, request dispatch, auth sessions,
//! autologin/timed-login, power actions, watchdog and signals.
//!
//! Trust model (spec 01 §8): every caller is untrusted; the socket is
//! gated by `SO_PEERCRED` against the configured UI user. All inputs are
//! bounded in `proto::decode_request`; expensive calls are rate-limited;
//! secrets never leave [`Secret`] buffers.
//!
//! Task topology per connection:
//! - `client_writer`: the only task that writes to the socket (events and
//!   responses arrive as pre-serialised lines on an unbounded channel).
//! - the connection task itself reads frames, decodes, dispatches.
//! - one `auth_pump` per authentication session: owns the [`AuthSession`],
//!   forwards events, drives the conversation watchdog, handles
//!   Answer/Cancel/Launch.
//! - `timed_login_task`: countdown, cancelled by any client request.

use crate::auth::{AuthEvent, AuthSession, Phase};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::launch::{launch_error_response, LaunchRequest, LaunchSuccess, Launcher};
use crate::logind::LogindSessions;
use crate::notify::Notify;
use crate::pam::{AuthFailReason, AuthOutcome, PamServiceFactory};
use crate::proto::{codes, decode_request, Event, PromptKind, Request, Response};
use crate::secret::Secret;
use crate::sessions::SessionDb;
use crate::sysffi;
use crate::throttle::Throttle;
use crate::users::UserDb;
use serde_json::json;
use std::collections::HashMap;
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

/// Injectable backends.
pub struct DaemonDeps {
    pub pam: Arc<dyn PamServiceFactory>,
    pub logind: Arc<dyn LogindSessions>,
    pub launcher: Arc<dyn Launcher>,
}

/// Config + derived data, swapped atomically on SIGHUP reload.
pub struct DaemonData {
    pub cfg: Config,
    pub userdb: UserDb,
    pub sessions: SessionDb,
    /// uid allowed to connect (resolved `ui_user`); `None` = fail closed.
    pub allowed_uid: Option<u32>,
}

/// Running handle to an auth session (for routing commands from the
/// dispatcher task to the pump task).
struct AuthHandle {
    id: u64,
    /// Owning connection id (None for internal autologin).
    conn: Option<u64>,
    guest: bool,
    user: String,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<PumpCmd>,
}

enum PumpCmd {
    Answer(Secret),
    Cancel,
    Launch {
        session_id: Option<String>,
        reply: Option<oneshot::Sender<Result<LaunchSuccess>>>,
    },
}

/// Pre-serialised wire lines to a client writer task; `None` = internal
/// autologin (events go to the journal instead).
type EventSink = Option<tokio::sync::mpsc::UnboundedSender<String>>;

pub struct Server {
    pub data: RwLock<DaemonData>,
    pub deps: DaemonDeps,
    pub throttle: Mutex<Throttle>,
    pub notify: Notify,
    auth: Mutex<Option<AuthHandle>>,
    next_auth_id: AtomicU64,
    next_conn_id: AtomicU64,
    connections: AtomicU64,
    launched_count: AtomicU64,
    started_at: Instant,
    stopping: Arc<AtomicBool>,
}

/// Snapshot of the active auth handle used for command routing.
#[derive(Clone)]
struct AuthView {
    conn: Option<u64>,
    guest: bool,
    user: String,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<PumpCmd>,
}

impl Server {
    pub fn new(cfg: Config, deps: DaemonDeps) -> Arc<Server> {
        let userdb = UserDb::from_config(&cfg);
        let allowed_uid = cfg
            .ui_uid()
            .or_else(|| userdb.find_raw(&cfg.greeter.ui_user).map(|u| u.uid));
        let sessions = SessionDb::new(&cfg);
        let throttle = Throttle::new(
            cfg.greeter.throttle.enabled,
            Duration::from_secs(cfg.greeter.throttle.cap_seconds),
        );
        if allowed_uid.is_none() {
            tracing::warn!(
                target: "boot",
                ui_user = %cfg.greeter.ui_user,
                "configured UI user does not exist; socket will fail closed"
            );
        }
        Arc::new(Server {
            data: RwLock::new(DaemonData {
                cfg,
                userdb,
                sessions,
                allowed_uid,
            }),
            deps,
            throttle: Mutex::new(throttle),
            notify: Notify::from_env(),
            auth: Mutex::new(None),
            next_auth_id: AtomicU64::new(1),
            next_conn_id: AtomicU64::new(1),
            connections: AtomicU64::new(0),
            launched_count: AtomicU64::new(0),
            started_at: Instant::now(),
            stopping: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn launched_count(&self) -> u64 {
        self.launched_count.load(Ordering::Relaxed)
    }

    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Replace configuration atomically (SIGHUP); keeps clients connected.
    pub fn reload_config(&self, path: &std::path::Path) -> Result<()> {
        let fresh = Config::load(path)?;
        fresh.validate()?;
        let userdb = UserDb::from_config(&fresh);
        let allowed_uid = fresh
            .ui_uid()
            .or_else(|| userdb.find_raw(&fresh.greeter.ui_user).map(|u| u.uid));
        let sessions = SessionDb::new(&fresh);
        let (enabled, cap) = (
            fresh.greeter.throttle.enabled,
            fresh.greeter.throttle.cap_seconds,
        );
        *self
            .data
            .write()
            .map_err(|_| Error::Other("config lock poisoned".into()))? = DaemonData {
            cfg: fresh,
            userdb,
            sessions,
            allowed_uid,
        };
        if let Ok(mut t) = self.throttle.lock() {
            t.set_policy(enabled, Duration::from_secs(cap));
        }
        Ok(())
    }

    fn cfg_snapshot(&self) -> Config {
        self.data
            .read()
            .map(|d| d.cfg.clone())
            .unwrap_or_else(|_| Config::default())
    }

    fn auth_view(&self) -> Option<AuthView> {
        self.auth.lock().ok().and_then(|g| {
            g.as_ref().map(|h| AuthView {
                conn: h.conn,
                guest: h.guest,
                user: h.user.clone(),
                cmd_tx: h.cmd_tx.clone(),
            })
        })
    }

    fn register_auth(&self, handle: AuthHandle) -> bool {
        match self.auth.lock() {
            Ok(mut guard) => {
                if guard.is_some() {
                    false
                } else {
                    *guard = Some(handle);
                    true
                }
            }
            Err(_) => false,
        }
    }

    fn clear_auth_if(&self, id: u64) {
        if let Ok(mut guard) = self.auth.lock() {
            if guard.as_ref().map(|h| h.id) == Some(id) {
                *guard = None;
            }
        }
    }
}

// ── Boot ───────────────────────────────────────────────────────────────
/// Bind the UI socket: systemd-passed fd (socket activation) or a fresh
/// one at `cfg.greeter.socket_path`.
async fn bind_socket(cfg: &Config) -> Result<UnixListener> {
    if let Some(fd) = sysffi::take_listen_fd() {
        tracing::info!(target: "boot", "using systemd socket-activation fd");
        let std_listener = std::os::unix::net::UnixListener::from(fd);
        return UnixListener::from_std(std_listener)
            .map_err(|e| Error::Io("activating socket fd".into(), e));
    }
    let path: PathBuf = cfg.greeter.socket_path.clone();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Io(format!("mkdir {}", parent.display()), e))?;
    }
    match std::fs::metadata(&path) {
        Ok(md) if md.file_type().is_socket() => {
            // stale socket from a previous crash — safe to replace
            let _ = std::fs::remove_file(&path);
        }
        Ok(_) => {
            return Err(Error::Config(format!(
                "{} exists and is not a socket; refusing to clobber",
                path.display()
            )))
        }
        Err(_) => {}
    }
    let listener =
        UnixListener::bind(&path).map_err(|e| Error::Io(format!("bind {}", path.display()), e))?;
    // 0660: root + the ui group (the .socket unit pins exact ownership
    // when socket activation is used).
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    if !sysffi::is_root() {
        tracing::warn!(
            target: "boot",
            uid = sysffi::current_uid(),
            "running unprivileged: the shipped unit runs as root with socket activation"
        );
    }
    Ok(listener)
}

/// Run the daemon until SIGTERM/SIGINT.
pub async fn run(server: Arc<Server>, config_path: PathBuf) -> Result<()> {
    let listener = bind_socket(&server.cfg_snapshot()).await?;
    server.notify.ready();
    tracing::info!(
        target: "boot",
        socket = %server.cfg_snapshot().greeter.socket_path.display(),
        pam = server.deps.pam.describe(),
        logind = server.deps.logind.describe(),
        launcher = server.deps.launcher.describe(),
        "lion-greeter ready"
    );

    // Watchdog heartbeats — only when the unit armed one (spec §7: no
    // timers when idle otherwise).
    if let Some(interval) = server.notify.watchdog_interval() {
        let sv = server.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if sv.stopping.load(Ordering::Relaxed) {
                    break;
                }
                sv.notify.watchdog_tick();
            }
        });
    }

    // Autologin (config-driven; fires without any UI connected).
    {
        let cfg = server.cfg_snapshot();
        if let Some(user) = cfg.greeter.autologin.user.clone().filter(|u| !u.is_empty()) {
            let sv = server.clone();
            let service = cfg.greeter.autologin.service.clone();
            let session_pref = cfg.greeter.autologin.session.clone();
            tokio::spawn(async move {
                tracing::info!(user = %user, "autologin configured; starting transaction");
                if let Err((code, msg)) =
                    start_auth(&sv, None, None, 0, &user, &service, session_pref, true).await
                {
                    tracing::warn!(user = %user, code, %msg, "autologin transaction not started");
                }
            });
        }
    }

    // Signals: TERM/INT stop; HUP reloads config in place.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

    let mut stopping = false;
    while !stopping {
        tokio::select! {
            _ = async { term.as_mut().expect("guarded").recv().await }, if term.is_some() => {
                stopping = true;
            }
            _ = tokio::signal::ctrl_c() => {
                stopping = true;
            }
            _ = async { hup.as_mut().expect("guarded").recv().await }, if hup.is_some() => {
                match server.reload_config(&config_path) {
                    Ok(()) => tracing::info!(target: "config", "configuration reloaded"),
                    Err(e) => tracing::error!(
                        target: "config",
                        error = %e,
                        "reload failed; keeping previous configuration"
                    ),
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let active = server.connections.fetch_add(1, Ordering::SeqCst);
                        if active >= 8 {
                            server.connections.fetch_sub(1, Ordering::SeqCst);
                            let mut s = stream;
                            let _ = s.shutdown().await;
                            tracing::warn!(target: "conn", "connection limit reached; refusing client");
                            continue;
                        }
                        let sv = server.clone();
                        tokio::spawn(async move {
                            handle_conn(sv.clone(), stream).await;
                            sv.connections.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) => {
                        tracing::warn!(target: "conn", error = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    server.notify.stopping();
    // Abort any live auth (spec §6: wipe on teardown).
    if let Some(view) = server.auth_view() {
        let _ = view.cmd_tx.send(PumpCmd::Cancel);
    }
    // Give pumps a moment to settle, then remove the socket.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let cfg = server.cfg_snapshot();
    let _ = std::fs::remove_file(cfg.greeter.socket_path);
    Ok(())
}

// ── Connection handling ────────────────────────────────────────────────
async fn handle_conn(server: Arc<Server>, stream: UnixStream) {
    let conn_id = server.next_conn_id.fetch_add(1, Ordering::SeqCst);
    let peer = sysffi::peer_credentials(stream.as_raw_fd());
    let allowed = server
        .data
        .read()
        .ok()
        .and_then(|d| d.allowed_uid)
        .map(|allowed| peer.as_ref().map(|p| p.uid == allowed).unwrap_or(false));

    match (&peer, allowed) {
        (Ok(p), Some(true)) => {
            tracing::info!(
                target: "conn",
                conn_id,
                peer_pid = p.pid,
                peer_uid = p.uid,
                "UI client connected"
            );
        }
        (Ok(p), _) => {
            tracing::warn!(
                target: "conn",
                conn_id,
                peer_pid = p.pid,
                peer_uid = p.uid,
                "connection from unexpected uid; dropping (fail closed)"
            );
            let mut s = stream;
            let _ = s.shutdown().await;
            return;
        }
        (Err(e), _) => {
            tracing::error!(target: "conn", conn_id, error = %e, "SO_PEERCRED failed; dropping");
            return;
        }
    }

    let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let (rd, wr) = stream.into_split();
    tokio::spawn(client_writer(wr, evt_rx));

    // Timed login: countdown starts when the UI connects; any client
    // request cancels it. (No timers when not configured — idle is idle.)
    let timed_counter = Arc::new(AtomicU64::new(0));
    {
        let cfg = server.cfg_snapshot();
        if let Some(user) = cfg
            .greeter
            .timed_login
            .user
            .clone()
            .filter(|u| !u.is_empty())
        {
            let delay = cfg.greeter.timed_login.delay_seconds;
            let service = cfg.greeter.autologin.service.clone();
            let sv = server.clone();
            let tx = evt_tx.clone();
            let counter = timed_counter.clone();
            tokio::spawn(async move {
                timed_login_task(sv, tx, counter, conn_id, user, delay, service).await
            });
        }
    }

    // Reader/dispatcher.
    let mut fr = crate::codec::FrameReader::new(rd);
    let mut gate = RateGate::default();
    loop {
        let frame = match fr.next_frame().await {
            Ok(Some(f)) => f,
            Ok(None) => break, // clean EOF: UI exited normally
            Err(e) => {
                tracing::debug!(target: "conn", conn_id, error = %e, "frame error; closing");
                break;
            }
        };
        match decode_request(&frame) {
            Ok(req) => {
                timed_counter.fetch_add(1, Ordering::SeqCst);
                if !gate.allow_message() {
                    let _ = evt_tx.send(
                        Response::err(req.id(), codes::RATE_LIMITED, "too many messages").to_wire(),
                    );
                    tracing::warn!(target: "conn", conn_id, "message flood; dropping client");
                    break;
                }
                dispatch(&server, conn_id, evt_tx.clone(), &mut gate, req).await;
            }
            Err(e) => {
                let _ = evt_tx.send(Response::err(e.id, e.code, e.message).to_wire());
                if e.fatal {
                    tracing::warn!(target: "conn", conn_id, code = e.code, "fatal protocol error; closing");
                    break;
                }
            }
        }
    }

    // UI crash / disconnect mid-auth: abort the PAM transaction and wipe
    // buffers (spec §6). The accept loop is immediately ready for the
    // restarted UI.
    if let Some(view) = server.auth_view() {
        if view.conn == Some(conn_id) {
            tracing::info!(
                target: "conn",
                conn_id,
                user = %view.user,
                "owning client gone; aborting auth session"
            );
            let _ = view.cmd_tx.send(PumpCmd::Cancel);
        }
    }
    drop(evt_tx);
}

async fn client_writer(
    mut wr: tokio::net::unix::OwnedWriteHalf,
    mut evt_rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    while let Some(line) = evt_rx.recv().await {
        if wr.write_all(line.as_bytes()).await.is_err() {
            break;
        }
        if wr.write_all(b"\n").await.is_err() {
            break;
        }
    }
    let _ = wr.shutdown().await;
}

async fn timed_login_task(
    server: Arc<Server>,
    evt_tx: tokio::sync::mpsc::UnboundedSender<String>,
    req_counter: Arc<AtomicU64>,
    conn_id: u64,
    user: String,
    delay: u64,
    service: String,
) {
    let base = req_counter.load(Ordering::SeqCst);
    for remaining in (1..=delay).rev() {
        let info = Event::Prompt {
            kind: PromptKind::Info,
            text: format!("Logging in as {user} in {remaining} s"),
        }
        .to_wire(0);
        if evt_tx.send(info).is_err() {
            return; // client gone
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        if req_counter.load(Ordering::SeqCst) != base {
            tracing::debug!(target: "timed", "user interaction cancelled timed login");
            return;
        }
        if server.auth_view().is_some() {
            return; // an auth session started meanwhile
        }
        if server.stopping.load(Ordering::Relaxed) {
            return;
        }
    }
    tracing::info!(target: "timed", user = %user, "timed login firing");
    let _ = start_auth(
        &server,
        Some(conn_id),
        Some(evt_tx),
        0,
        &user,
        &service,
        None,
        true,
    )
    .await;
}

// ── Dispatch ───────────────────────────────────────────────────────────
async fn dispatch(
    server: &Arc<Server>,
    conn_id: u64,
    evt_tx: tokio::sync::mpsc::UnboundedSender<String>,
    gate: &mut RateGate,
    req: Request,
) {
    match req {
        Request::ListUsers { id } => {
            if !gate.allow("list_users", Duration::from_millis(250)) {
                let _ = evt_tx.send(
                    Response::err(id, codes::RATE_LIMITED, "ListUsers is rate-limited").to_wire(),
                );
                return;
            }
            let resp = match list_users(server) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, codes::INTERNAL, e.to_string()),
            };
            let _ = evt_tx.send(resp.to_wire());
        }
        Request::ListSessions { id } => {
            if !gate.allow("list_sessions", Duration::from_millis(250)) {
                let _ = evt_tx.send(
                    Response::err(id, codes::RATE_LIMITED, "ListSessions is rate-limited")
                        .to_wire(),
                );
                return;
            }
            let resp = match list_sessions(server) {
                Ok(v) => Response::ok(id, v),
                Err(e) => Response::err(id, codes::INTERNAL, e.to_string()),
            };
            let _ = evt_tx.send(resp.to_wire());
        }
        Request::StartAuth { id, user } => {
            if !gate.allow("start_auth", Duration::from_millis(200)) {
                let _ = evt_tx.send(
                    Response::err(id, codes::RATE_LIMITED, "StartAuth is rate-limited").to_wire(),
                );
                return;
            }
            let cfg = server.cfg_snapshot();
            // Guest: policy-authenticated, no PAM.
            if user == cfg.greeter.guest.user {
                if !cfg.greeter.allow_guest {
                    let _ = evt_tx.send(
                        Response::err(id, codes::NOT_ALLOWED, "guest sessions are disabled")
                            .to_wire(),
                    );
                    return;
                }
                match start_guest(server, Some(conn_id), Some(evt_tx.clone()), id).await {
                    Ok(()) => {
                        let _ = evt_tx.send(
                            Response::ok(id, json!({"started": true, "guest": true})).to_wire(),
                        );
                    }
                    Err((code, msg)) => {
                        let _ = evt_tx.send(Response::err(id, code, msg).to_wire());
                    }
                }
                return;
            }
            let service = cfg.greeter.pam.service.clone();
            match start_auth(
                server,
                Some(conn_id),
                Some(evt_tx.clone()),
                id,
                &user,
                &service,
                None,
                false,
            )
            .await
            {
                Ok(()) => {
                    let _ = evt_tx
                        .send(Response::ok(id, json!({"started": true, "user": user})).to_wire());
                }
                Err((code, msg)) => {
                    let _ = evt_tx.send(Response::err(id, code, msg).to_wire());
                }
            }
        }
        Request::AnswerPrompt { id, text } => {
            let routed = match server.auth_view() {
                Some(view) if view.conn == Some(conn_id) && !view.guest => {
                    view.cmd_tx.send(PumpCmd::Answer(text)).is_ok()
                }
                _ => false,
            };
            let resp = if routed {
                Response::ok(id, json!({}))
            } else {
                Response::err(id, codes::BAD_REQUEST, "no active prompt to answer")
            };
            let _ = evt_tx.send(resp.to_wire());
        }
        Request::CancelAuth { id } => {
            let routed = match server.auth_view() {
                Some(view) if view.conn == Some(conn_id) => {
                    view.cmd_tx.send(PumpCmd::Cancel).is_ok()
                }
                _ => false,
            };
            let resp = if routed {
                Response::ok(id, json!({}))
            } else {
                Response::err(id, codes::BAD_REQUEST, "no active authentication session")
            };
            let _ = evt_tx.send(resp.to_wire());
        }
        Request::Launch { id, session } => {
            match server.auth_view() {
                None => {
                    let _ = evt_tx.send(
                        Response::err(id, codes::NOT_AUTHENTICATED, "authenticate first").to_wire(),
                    );
                }
                Some(view) if view.conn == Some(conn_id) => {
                    // Both PAM and guest sessions flow through the pump;
                    // the pump decides whether setcred is needed.
                    let (tx, rx) = oneshot::channel();
                    if view
                        .cmd_tx
                        .send(PumpCmd::Launch {
                            session_id: Some(session),
                            reply: Some(tx),
                        })
                        .is_err()
                    {
                        let _ = evt_tx.send(
                            Response::err(id, codes::INTERNAL, "auth session vanished").to_wire(),
                        );
                        return;
                    }
                    match tokio::time::timeout(Duration::from_secs(20), rx).await {
                        Ok(Ok(Ok(s))) => {
                            let _ = evt_tx.send(
                                Response::ok(
                                    id,
                                    json!({"session_id": s.logind_session, "pid": s.pid}),
                                )
                                .to_wire(),
                            );
                        }
                        Ok(Ok(Err(e))) => {
                            let _ = evt_tx.send(launch_error_response(id, &e).to_wire());
                        }
                        Ok(Err(_)) | Err(_) => {
                            let _ = evt_tx.send(
                                Response::err(id, codes::INTERNAL, "launch timed out").to_wire(),
                            );
                        }
                    }
                }
                Some(_) => {
                    let _ = evt_tx.send(
                        Response::err(
                            id,
                            codes::NOT_AUTHENTICATED,
                            "session owned by another client",
                        )
                        .to_wire(),
                    );
                }
            }
        }
        Request::Power { id, action } => {
            if !gate.allow("power", Duration::from_secs(1)) {
                let _ = evt_tx.send(
                    Response::err(id, codes::RATE_LIMITED, "Power is rate-limited").to_wire(),
                );
                return;
            }
            let allowed = server
                .cfg_snapshot()
                .greeter
                .power
                .allowed
                .iter()
                .any(|a| a == action.as_str());
            if !allowed {
                let _ = evt_tx.send(
                    Response::err(
                        id,
                        codes::POWER_DENIED,
                        "action not allowed by configuration",
                    )
                    .to_wire(),
                );
                return;
            }
            let logind = server.deps.logind.clone();
            let res = tokio::task::spawn_blocking(move || logind.power(action))
                .await
                .unwrap_or_else(|e| Err(format!("power task: {e}")));
            let resp = match res {
                Ok(()) => {
                    tracing::info!(target: "power", action = action.as_str(), "power action issued");
                    Response::ok(id, json!({"action": action.as_str()}))
                }
                Err(e) => Response::err(id, codes::POWER_DENIED, e),
            };
            let _ = evt_tx.send(resp.to_wire());
        }
    }
}

fn list_users(server: &Arc<Server>) -> Result<serde_json::Value> {
    let data = server
        .data
        .read()
        .map_err(|_| Error::Other("data lock poisoned".into()))?;
    let mut users: Vec<serde_json::Value> = data
        .userdb
        .list()?
        .into_iter()
        .map(|u| {
            json!({
                "name": u.name,
                "uid": u.uid,
                "real_name": u.real_name,
                "shell": u.shell,
                "avatar": u.avatar.as_ref().map(|p| p.display().to_string()),
                "last_session": u.last_session,
                "is_guest": false,
            })
        })
        .collect();
    if data.cfg.greeter.allow_guest {
        if let Some(g) = data.userdb.find_raw(&data.cfg.greeter.guest.user) {
            users.push(json!({
                "name": g.name,
                "uid": g.uid,
                "real_name": "Guest",
                "shell": g.shell,
                "avatar": serde_json::Value::Null,
                "last_session": serde_json::Value::Null,
                "is_guest": true,
            }));
        }
    }
    Ok(json!({
        "users": users,
        "show_user_list": data.cfg.greeter.show_user_list,
        "allow_guest": data.cfg.greeter.allow_guest,
    }))
}

fn list_sessions(server: &Arc<Server>) -> Result<serde_json::Value> {
    let data = server
        .data
        .read()
        .map_err(|_| Error::Other("data lock poisoned".into()))?;
    let sessions: Vec<serde_json::Value> = data
        .sessions
        .list()?
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id,
                "name": s.name,
                "exec": s.exec,
                "builtin": s.builtin,
            })
        })
        .collect();
    Ok(json!({
        "sessions": sessions,
        "default": data.cfg.greeter.default_session,
    }))
}

// ── Auth session creation ─────────────────────────────────────────────
#[allow(clippy::too_many_arguments)]
async fn start_auth(
    server: &Arc<Server>,
    conn: Option<u64>,
    sink: EventSink,
    req_id: u64,
    user: &str,
    service: &str,
    session_pref: Option<String>,
    auto_launch: bool,
) -> std::result::Result<(), (&'static str, String)> {
    let cfg = server.cfg_snapshot();
    let timeout = cfg.conv_timeout();

    // One session at a time.
    if server.auth_view().is_some() {
        return Err((
            codes::BUSY,
            "an authentication session is already in progress".into(),
        ));
    }
    // Throttle (UI-driven attempts only; internal autologin is trusted
    // config, not an attack surface).
    if conn.is_some() {
        let mut t = server
            .throttle
            .lock()
            .map_err(|_| (codes::INTERNAL, "lock".into()))?;
        if let Some((secs, _)) = t.remaining(user) {
            return Err((
                codes::THROTTLED,
                format!("too many failed attempts; retry in {secs} s"),
            ));
        }
    }
    // User must exist and be a visible login candidate.
    let user_info = {
        let data = server
            .data
            .read()
            .map_err(|_| (codes::INTERNAL, "lock".into()))?;
        data.userdb
            .find(user)
            .map_err(|e| (codes::INTERNAL, e.to_string()))?
    };
    let Some(user_info) = user_info else {
        tracing::warn!(target: "auth", user, "StartAuth for unknown or hidden user");
        return Err((codes::NO_SUCH_USER, "no such user".into()));
    };

    let session =
        AuthSession::start_pam(server.deps.pam.clone(), service, user_info, timeout, req_id);
    spawn_pump(server, session, conn, sink, session_pref, auto_launch);
    Ok(())
}

async fn start_guest(
    server: &Arc<Server>,
    conn: Option<u64>,
    sink: EventSink,
    req_id: u64,
) -> std::result::Result<(), (&'static str, String)> {
    if server.auth_view().is_some() {
        return Err((
            codes::BUSY,
            "an authentication session is already in progress".into(),
        ));
    }
    let cfg = server.cfg_snapshot();
    let data = server
        .data
        .read()
        .map_err(|_| (codes::INTERNAL, "lock".into()))?;
    let guest = data
        .userdb
        .find_raw(&cfg.greeter.guest.user)
        .ok_or_else(|| (codes::NO_SUCH_USER, "guest account not present".into()))?;
    drop(data);
    let session = AuthSession::guest(req_id, guest);
    spawn_pump(server, session, conn, sink, None, false);
    Ok(())
}

fn spawn_pump(
    server: &Arc<Server>,
    session: AuthSession,
    conn: Option<u64>,
    sink: EventSink,
    session_pref: Option<String>,
    auto_launch: bool,
) {
    let handle_id = server.next_auth_id.fetch_add(1, Ordering::SeqCst);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel::<PumpCmd>();
    if !server.register_auth(AuthHandle {
        id: handle_id,
        conn,
        guest: session.guest,
        user: session.user.name.clone(),
        cmd_tx,
    }) {
        // Raced with another session: fail closed by ending this one.
        let mut session = session;
        session.close();
        return;
    }
    let peer_key = format!(
        "conn-{}",
        conn.map(|c| c.to_string())
            .unwrap_or_else(|| "internal".into())
    );
    let sv = server.clone();
    tokio::spawn(async move {
        auth_pump(
            sv,
            session,
            handle_id,
            conn,
            sink,
            cmd_rx,
            peer_key,
            session_pref,
            auto_launch,
        )
        .await;
    });
}

// ── The auth pump ──────────────────────────────────────────────────────
struct PendingLaunch {
    session_id: Option<String>,
    reply: Option<oneshot::Sender<Result<LaunchSuccess>>>,
}

#[allow(clippy::too_many_arguments)]
async fn auth_pump(
    server: Arc<Server>,
    mut session: AuthSession,
    handle_id: u64,
    _conn: Option<u64>,
    sink: EventSink,
    mut cmd_rx: tokio::sync::mpsc::UnboundedReceiver<PumpCmd>,
    peer_key: String,
    session_pref: Option<String>,
    auto_launch: bool,
) {
    let timeout = server.cfg_snapshot().conv_timeout();
    let mut last_activity = Instant::now();
    let mut pending_launch: Option<PendingLaunch> = None;

    // Forward a wire line to the sink (or the journal for internal flows).
    macro_rules! emit {
        ($line:expr) => {
            match &sink {
                Some(tx) => {
                    if tx.send($line).is_err() {
                        // UI crashed mid-auth: abort + wipe (spec §6).
                        tracing::warn!(target: "auth", "event sink closed; aborting session");
                        session.cancel();
                    }
                }
                None => tracing::info!(target: "auth", "internal event: {}", $line),
            }
        };
    }

    // Guest sessions carry no PAM events — emit the verdict up front.
    if session.guest {
        emit!(Event::AuthResult {
            ok: true,
            reason: "guest session".into()
        }
        .to_wire(session.req_id));
    }

    loop {
        // Watchdog arm: only while waiting for conversation input.
        let armed = session.phase() == Phase::Authenticating && !session.guest;
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(PumpCmd::Answer(secret)) => {
                        session.answer(secret);
                    }
                    Some(PumpCmd::Cancel) => {
                        if session.phase() == Phase::Authenticating {
                            session.cancel();
                            emit!(Event::AuthResult {
                                ok: false,
                                reason: AuthFailReason::Cancelled.ui_reason().into(),
                            }
                            .to_wire(session.req_id));
                        } else if session.guest {
                            session.cancel();
                            break;
                        } else {
                            session.cancel();
                        }
                    }
                    Some(PumpCmd::Launch { session_id, reply }) => {
                        if session.phase() != Phase::AuthOk {
                            if let Some(tx) = reply {
                                let _ = tx.send(Err(Error::Denied("not authenticated".into())));
                            }
                        } else if session.guest {
                            // Guest: no setcred step.
                            let user = session.user.name.clone();
                            let out = launch_flow(&server, reply, session_id, user, true).await;
                            if out.is_ok() {
                                session.mark_launched();
                                server.launched_count.fetch_add(1, Ordering::SeqCst);
                            }
                            break;
                        } else {
                            session.setcred();
                            pending_launch = Some(PendingLaunch { session_id, reply });
                        }
                    }
                    None => {
                        // All senders gone (daemon teardown): end + wipe.
                        session.cancel();
                        break;
                    }
                }
                last_activity = Instant::now();
            }
            evt = session.recv_event(), if !session.guest => {
                last_activity = Instant::now();
                match evt {
                    AuthEvent::Prompt(p) => {
                        emit!(Event::Prompt { kind: p.kind, text: p.text }
                            .to_wire(session.req_id));
                    }
                    AuthEvent::Done(outcome) => {
                        let phase_before = session.phase();
                        session.apply(AuthEvent::Done(outcome));
                        if phase_before == Phase::Authenticating {
                            emit!(Event::AuthResult {
                                ok: outcome.ok(),
                                reason: match outcome {
                                    AuthOutcome::Success => "ok".into(),
                                    AuthOutcome::Failed(r) => r.ui_reason().into(),
                                },
                            }
                            .to_wire(session.req_id));
                            match outcome {
                                AuthOutcome::Success => {
                                    if let Ok(mut t) = server.throttle.lock() {
                                        t.record_success(&session.user.name, &peer_key);
                                    }
                                    if auto_launch {
                                        pending_launch = Some(PendingLaunch {
                                            session_id: session_pref.clone(),
                                            reply: None,
                                        });
                                        session.setcred();
                                    }
                                }
                                AuthOutcome::Failed(reason) => {
                                    if matches!(
                                        reason,
                                        AuthFailReason::AuthErr
                                            | AuthFailReason::Locked
                                            | AuthFailReason::AcctExpired
                                    ) {
                                        let next_lock = if let Ok(mut t) = server.throttle.lock() {
                                            t.record_failure(&session.user.name, &peer_key)
                                        } else {
                                            0
                                        };
                                        if next_lock > 0 {
                                            emit!(Event::Throttle { seconds: next_lock }
                                                .to_wire(session.req_id));
                                        }
                                    }
                                    // Release the parked worker; the UI may retry.
                                    session.close();
                                }
                            }
                        }
                    }
                    AuthEvent::SetCredDone(res) => {
                        session.apply(AuthEvent::SetCredDone(res));
                        if res.is_ok() {
                            let pl = pending_launch.take();
                            if let Some(pl) = pl {
                                let user = session.user.name.clone();
                                let out = launch_flow(
                                    &server,
                                    pl.reply,
                                    pl.session_id,
                                    user,
                                    false,
                                )
                                .await;
                                if out.is_ok() {
                                    session.mark_launched();
                                    server.launched_count.fetch_add(1, Ordering::SeqCst);
                                }
                                session.close();
                            }
                        } else {
                            if let Some(pl) = pending_launch.take() {
                                if let Some(tx) = pl.reply {
                                    let _ = tx.send(Err(Error::Pam(
                                        "credential establishment failed".into(),
                                    )));
                                }
                            }
                            session.close();
                        }
                    }
                    AuthEvent::Finished => {
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(next_deadline(last_activity, timeout)), if armed => {
                // Conversation step timed out: cancel + generic failure.
                tracing::warn!(target: "auth", user = %session.user.name, "conversation timed out");
                session.cancel();
                emit!(Event::AuthResult {
                    ok: false,
                    reason: AuthFailReason::Timeout.ui_reason().into(),
                }
                .to_wire(session.req_id));
            }
        }
    }
    session.close();
    server.clear_auth_if(handle_id);
    tracing::debug!(target: "auth", handle_id, user = %session.user.name, "auth pump finished");
}

fn next_deadline(last: Instant, timeout: Duration) -> tokio::time::Instant {
    tokio::time::Instant::from_std(last + timeout)
}

// ── Launch ─────────────────────────────────────────────────────────────
async fn launch_flow(
    server: &Arc<Server>,
    reply: Option<oneshot::Sender<Result<LaunchSuccess>>>,
    session_id: Option<String>,
    user_name: String,
    guest: bool,
) -> Result<LaunchSuccess> {
    // Resolve session + user under the data lock.
    let (resolved, user, seat) = {
        let data = server
            .data
            .read()
            .map_err(|_| Error::Other("data lock poisoned".into()))?;
        let effective = data
            .sessions
            .resolve_for_user(session_id.as_deref(), &user_name)
            .map_err(|e| Error::Denied(e.to_string()))?;
        let info = data
            .sessions
            .find(&effective)?
            .ok_or_else(|| Error::Denied(format!("session {effective:?} vanished")))?;
        let user = if guest {
            data.userdb
                .find_raw(&data.cfg.greeter.guest.user)
                .ok_or_else(|| Error::Launch("guest account missing".into()))?
        } else {
            data.userdb
                .find(&user_name)?
                .ok_or_else(|| Error::Launch(format!("user {user_name:?} vanished")))?
        };
        (info, user, data.cfg.greeter.seat.clone())
    };

    let launch_req = LaunchRequest {
        user,
        session: resolved,
        guest,
        seat,
    };
    let user_name = launch_req.user.name.clone();
    let session_id_resolved = launch_req.session.id.clone();
    let launcher = server.deps.launcher.clone();
    let out = tokio::task::spawn_blocking(move || launcher.launch(&launch_req))
        .await
        .map_err(|e| Error::Launch(format!("launch task: {e}")))??;

    // Remember the last session choice (non-guest only).
    if !guest {
        if let Ok(data) = server.data.read() {
            if let Err(e) = data
                .sessions
                .set_last_session(&user_name, &session_id_resolved)
            {
                tracing::warn!(target: "session", error = %e, "could not persist last-session choice");
            }
        }
    }
    if let Some(tx) = reply {
        let _ = tx.send(Ok(out.clone()));
    }
    Ok(out)
}

// ── Rate gate ──────────────────────────────────────────────────────────
#[derive(Default)]
struct RateGate {
    last: HashMap<&'static str, Instant>,
    window: std::collections::VecDeque<Instant>,
}

impl RateGate {
    fn allow_message(&mut self) -> bool {
        let now = Instant::now();
        self.window.push_back(now);
        while let Some(front) = self.window.front() {
            if now.duration_since(*front) > Duration::from_secs(1) {
                self.window.pop_front();
            } else {
                break;
            }
        }
        self.window.len() <= 64
    }

    fn allow(&mut self, key: &'static str, min_gap: Duration) -> bool {
        let now = Instant::now();
        match self.last.get(key) {
            Some(prev) if now.duration_since(*prev) < min_gap => false,
            _ => {
                self.last.insert(key, now);
                true
            }
        }
    }
}
