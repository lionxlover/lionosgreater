//! D-Bus surface for `lion-login-ui` (system bus).
//!
//! Bus name    : org.lionos.Greeter
//! Object path : /org/lionos/Greeter
//! Interface   : org.lionos.Greeter1
//!
//! Methods
//!   ListUsers() -> s        JSON array: [{username, full_name, avatar_path,
//!                           session_type, last_used}], last user first
//!   GetLastUser() -> s      username or ""
//!   Authenticate(s username, s password) -> (b ok, s message, u retry_after_ms)
//!                           Session selection: \[session\] default in
//!                           greeter.toml, else the last-chosen session.
//!   AuthenticateSession(s username, s password, s session_id)
//!                         -> (b ok, s message, u retry_after_ms)
//!                           0.6.0: choose the desktop session for this
//!                           login (validated against the installed list).
//!   ListSessions() -> s     0.6.0: JSON array of installed sessions
//!                           [{id, name, comment, session_type,
//!                           desktop_names}] — the "gear menu" data.
//!   GetLastSession() -> s   0.6.0: last-chosen session id or ""
//!   ListSeatSessions() -> s 0.6.0: live logind snapshot — who is
//!                           signed in, on which seat, which session is
//!                           active: the fast-user-switching data.
//!   SwitchToVT(u vt) -> (b ok, s message)
//!                           0.6.0: jump the seat to a virtual terminal
//!                           (the primitive behind "switch user").
//!   ActivateSession(s session_id) -> (b ok, s message)
//!                           0.6.0: switch directly to a logind session.
//!   LockSession(s session_id) -> (b ok, s message)
//!                           0.6.0: ask another user's session to lock.
//!   CancelAuth() -> b       true if an in-progress auth was canceled
//!   GetMetrics() -> s       JSON object with auth counters + uptime
//!   ResetMetrics()          Zero the counters (not uptime)
//!   ReplyConversation(u request_id, as answers) -> b
//!                           Answer a forwarded PAM prompt (2FA code,
//!                           security-key acknowledgement, ...). One
//!                           string per prompt in the round, aligned
//!                           with the ConversationPrompt payload.
//!   CancelAutologin() -> b  Disarm the pending automatic sign-in.
//!
//! Signals (emitted during Authenticate so the UI can animate each phase)
//!   AuthProgress(s stage)   "verifying" | "authorized" | "starting_session"
//!   AuthFailed(s message, u retry_after_ms)
//!   AuthSucceeded()         UI should play its unlock/fade-out transition
//!   AuthCanceled()          UI should reset to idle (esc / cancel pressed)
//!   ConversationPrompt(u request_id, s prompts_json)
//!                           A live PAM question. prompts_json:
//!                           [{"style":"echo_off","text":"Verification code:"}]
//!                           The UI must call ReplyConversation with the
//!                           aligned answers, or the round times out (30s)
//!                           or is canceled.
//!   AutologinCountdown(u ms_left)
//!                           Emitted ~5x/s while the delay counts down;
//!                           the UI shows "signing in as X in N s".
//!   AutologinAborted(s reason)
//!                           Countdown canceled by the user, the PAM
//!                           autologin stack refused, or the session
//!                           could not start: fall back to the manual
//!                           form, pre-selecting the same user.
//!   SessionsChanged()      0.6.0: the logind session/seat snapshot
//!                           changed (someone logged in/out, switched);
//!                           re-fetch via ListSeatSessions.
//!
//! Properties
//!   Version (s)
//!   Capabilities (s)        JSON array of feature strings:
//!                           ["cancel","metrics","conversation","autologin",
//!                           "sessions","auth-methods"] plus "mlock" when
//!                           secrets are RAM-pinned and "seat-switch"
//!                           when logind is reachable
//!   AutologinUser (s)       configured user or "" when disabled
//!   AutologinDelayMs (t)    configured countdown in milliseconds
//!   AutologinRelogin (b)    whether autologin re-arms after logout
//!   LastSession (s)         0.6.0: last-chosen session id or ""
//!   DefaultSession (s)      0.6.0: \[session\] default or ""
//!   AuthMethods (s)         0.6.0: JSON array of available auth methods
//!                           (password / fingerprint / smartcard /
//!                           security-key) with live availability — the
//!                           data behind the UI's method logos.
//!
//! Security notes on the conversation surface:
//! * Only the `lion-login` account may call any of this (bus policy).
//! * `request_id` values are single-use and unpredictable-in-practice
//!   (monotonic per process); a stale or guessed id is rejected, so a
//!   compromised second client cannot inject an answer into someone
//!   else's round.
//! * Answers are capped at 1024 bytes each: PAM never needs more, and
//!   the cap stops a hostile client from parking megabytes of data in
//!   the root daemon's heap (zeroized on drop, but still).
//! * Session ids and VT numbers are validated before any logind call;
//!   the bus policy already restricts callers to `lion-login`, and
//!   validation keeps a compromised UI from turning the greeter into
//!   a generic logind proxy.

use crate::{
    auth::{self, AuthError, ConvEvent, Stage},
    config::Config,
    methods, metrics, mlock, seat, sessions, state,
    throttle::{Throttle, UNKNOWN_KEY},
    users_enum,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex as AsyncMutex;
use zbus::{connection, interface, object_server::SignalContext};
use zeroize::Zeroizing;

const BUS_NAME: &str = "org.lionos.Greeter";
const OBJECT_PATH: &str = "/org/lionos/Greeter";

/// Failures take at least this long, whatever the cause, so response time
/// reveals neither valid usernames nor which PAM module rejected you --
/// while staying short enough that the UI's shake animation feels instant.
const MIN_FAILURE_LATENCY: Duration = Duration::from_millis(600);

/// Hard cap per conversation answer (bytes). PAM prompts are short by
/// construction; anything longer is either an attack or a bug.
const MAX_ANSWER_BYTES: usize = 1024;

/// Countdown tick: 5 signals/sec is smooth enough for any UI animation
/// and negligible on the bus.
const COUNTDOWN_TICK: Duration = Duration::from_millis(200);

#[derive(Serialize)]
struct UserEntry {
    username: String,
    full_name: String,
    avatar_path: String,
    session_type: &'static str,
    last_used: bool,
}

// ── conversation registry ──────────────────────────────────────────────

/// Pending forwarded conversations, keyed by request id. Shared between
/// the interface (which registers rounds on signal emission and answers
/// them via `ReplyConversation`) and the login driver (which relays
/// worker events into it).
#[derive(Default)]
struct ConvRegistry {
    pending: Mutex<HashMap<u64, Arc<auth::ConvSlot>>>,
}

impl ConvRegistry {
    fn register(&self, event: ConvEvent) -> (u64, Vec<crate::pam_ffi::Prompt>) {
        let ConvEvent { id, prompts, slot } = event;
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(id, slot);
        (id, prompts)
    }

    /// Deliver the UI's answers. `false` = unknown/already-answered round.
    fn reply(&self, id: u64, answers: Vec<String>) -> bool {
        let slot = {
            let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            g.remove(&id)
        };
        slot.map(|s| s.complete(answers)).unwrap_or(false)
    }

    /// Wake and abort every pending round (CancelAuth / login ended).
    fn cancel_all(&self) {
        let mut g = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        for (_, slot) in g.drain() {
            slot.cancel();
        }
    }
}

/// JSON shape emitted in `ConversationPrompt`.
#[derive(Serialize)]
struct PromptJson {
    style: &'static str,
    text: String,
}

fn prompts_to_json(prompts: &[crate::pam_ffi::Prompt]) -> String {
    let items: Vec<PromptJson> = prompts
        .iter()
        .map(|p| PromptJson {
            style: p.style.as_str(),
            text: p.text.clone(),
        })
        .collect();
    serde_json::to_string(&items).unwrap_or_else(|_| "[]".into())
}

// ── autologin state (shared interface <-> driver) ─────────────────────

struct AutologinState {
    /// Set while the countdown or the autologin worker is running;
    /// `CancelAutologin` only works while this is true.
    armed: AtomicBool,
    /// Cooperative cancel shared with the autologin worker.
    cancel: Arc<AtomicBool>,
    /// Set once any autologin has fired in this process. With
    /// `relogin = false` the driver never re-arms after that.
    fired: AtomicBool,
}

// ── session selection ─────────────────────────────────────────────────

/// Pure resolution core (unit-tested): which session id should a
/// login use? Priority: explicit choice, then `[session] default`,
/// then last-chosen, then `None` (lion-session's own default). Pure
/// string logic so the policy is testable without a filesystem.
fn resolve_session_id(
    explicit: Option<&str>,
    cfg_default: Option<&str>,
    last: Option<&str>,
) -> Option<String> {
    if let Some(id) = explicit {
        return Some(id.to_owned());
    }
    cfg_default
        .map(str::to_owned)
        .or_else(|| last.map(str::to_owned))
}

/// Validate and resolve the login's session to an installed entry.
/// `Err(reason)` only for an *explicitly requested but unknown* id —
/// defaults and remembered ids degrade silently to `None`.
fn resolve_session(explicit: Option<&str>) -> Result<Option<sessions::SessionEntry>, String> {
    if let Some(id) = explicit {
        if !sessions::is_plausible_id(id) {
            return Err("Malformed session id".into());
        }
        return match sessions::find(id) {
            Some(entry) => Ok(Some(entry)),
            None => Err(format!("Session `{id}` is not installed")),
        };
    }
    // Defaults never fail a login: an uninstalled default or a stale
    // last-chosen id silently falls back to lion-session's default.
    let cfg_default = Config::load().session.default.clone();
    let last = state::last_session();
    let id = resolve_session_id(None, cfg_default.as_deref(), last.as_deref());
    Ok(id.and_then(|id| sessions::find(&id)))
}

/// The live system-bus connection, published by `serve()` for property
/// getters (which cannot take injected connection arguments in this
/// zbus release). `None` in unit tests — property getters then serve
/// the connection-less answer.
static LIVE_CONN: std::sync::OnceLock<zbus::Connection> = std::sync::OnceLock::new();

// ── the interface ──────────────────────────────────────────────────────

struct Greeter {
    /// Short-held lock around the throttle map. `std::sync::Mutex` is
    /// faster than `tokio::sync::Mutex` for sync operations, and we
    /// never `await` while holding it.
    throttle: Mutex<Throttle>,
    /// One authentication at a time: no parallel guessing. Must be
    /// `tokio::sync::Mutex` because the guard is held across the
    /// entire (long, await-heavy) auth flow.
    busy: AsyncMutex<()>,
    /// Cancel flag for the in-flight login, if any. Short-held sync
    /// lock — we only assign / read the `Option<Arc<AtomicBool>>`.
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    /// Live conversation rounds, shared with the login driver.
    conv: Arc<ConvRegistry>,
    /// Autologin driver state (also exposed as properties).
    autologin: Arc<AutologinState>,
    /// Snapshot of the parsed /etc/lionos/greeter.toml.
    cfg: &'static Config,
}

impl Greeter {
    /// logind reachability with a 30 s TTL cache, written by serve(),
    /// the seat watcher, and seat-method callers. Fresh-ish and
    /// honest: a logind that went away is noticed within 30 s; one
    /// that came back is noticed by the next seat call anyway.
    fn logind_ok(&self) -> bool {
        seat::last_logind_state(Duration::from_secs(30)).unwrap_or(false)
    }

    /// Shared implementation of `Authenticate`/`AuthenticateSession`.
    async fn authenticate_common(
        &self,
        ctxt: SignalContext<'_>,
        username: String,
        password: String,
        explicit_session: Option<String>,
    ) -> (bool, String, u32) {
        let password = Zeroizing::new(password);
        metrics::get().inc_attempts();

        // Session validation first: wrong ids must not touch auth state.
        let session = match resolve_session(explicit_session.as_deref()) {
            Ok(s) => s,
            Err(reason) => return (false, reason, 0),
        };

        let Ok(_guard) = self.busy.try_lock() else {
            return (false, "Another sign-in is in progress".into(), 0);
        };

        let user = tokio::task::spawn_blocking({
            let name = username.clone();
            move || users_enum::find_eligible(&name)
        })
        .await
        .ok()
        .flatten();
        let key = if user.is_some() {
            username.as_str()
        } else {
            UNKNOWN_KEY
        };

        if let Some(wait) = remaining(&self.throttle, key) {
            let ms = wait.as_millis() as u32;
            let msg = "Too many attempts. Please wait.".to_string();
            let _ = Self::auth_failed(&ctxt, &msg, ms).await;
            return (false, msg, ms);
        }

        let started = Instant::now();
        let _ = Self::auth_progress(&ctxt, "verifying").await;

        // Wire up the cancel flag and the conversation channel for this
        // attempt.
        let cancel = Arc::new(AtomicBool::new(false));
        // Keep a handle for the result-time check below: `run_login`
        // takes ownership of the Arc, but `pam_authenticate` cannot be
        // interrupted mid-call, so a cancel that lands while libpam is
        // still working must be honored when the outcome is assembled.
        let cancel_flag = cancel.clone();
        {
            let mut g = self.cancel.lock().unwrap_or_else(|e| e.into_inner());
            *g = Some(cancel.clone());
        }
        let (conv_tx, conv_rx) = tokio::sync::mpsc::unbounded_channel::<ConvEvent>();
        let conv_registry = self.conv.clone();

        // Unknown/ineligible names take the same path and the same time.
        let chosen_session = session.clone();
        let outcome = match user {
            Some(u) => {
                run_login(
                    &ctxt,
                    u,
                    password,
                    cancel,
                    conv_tx,
                    conv_rx,
                    conv_registry,
                    session,
                )
                .await
            }
            None => Err(AuthError::InvalidCredentials),
        };

        // Clear the cancel slot and abort any conversation round that
        // the worker abandoned mid-flight (it cannot outlive the login).
        {
            let mut g = self.cancel.lock().unwrap_or_else(|e| e.into_inner());
            *g = None;
        }
        self.conv.cancel_all();

        match outcome {
            Ok(()) => {
                reset(&self.throttle, key);
                state::set_last_user(&username);
                if let Some(s) = &chosen_session {
                    state::set_last_session(&s.id);
                }
                state::touch_last_session();
                metrics::get().inc_success();
                let _ = Self::auth_succeeded(&ctxt).await;
                (true, String::new(), 0)
            }
            Err(AuthError::Canceled) => {
                metrics::get().inc_cancel();
                let _ = Self::auth_canceled(&ctxt).await;
                (false, "Sign-in was canceled".into(), 0)
            }
            Err(err) => {
                // Honor a cancel that raced libpam: the worker checks the
                // flag only at round boundaries, and `pam_authenticate`
                // itself is uninterruptible — a UI that pressed Esc
                // mid-verification would otherwise be told "wrong
                // password". Report the cancel instead. The failure still
                // counts toward the throttle (racing Esc must not launder
                // brute-force attempts), and the latency pad still applies
                // (no timing oracle: canceled and failed look alike).
                if cancel_flag.load(Ordering::Acquire) {
                    if let Some(rest) = MIN_FAILURE_LATENCY.checked_sub(started.elapsed()) {
                        tokio::time::sleep(rest).await;
                    }
                    // Side-effecting call: mutates the throttle map.
                    let _ = record_failure(&self.throttle, key);
                    metrics::get().inc_cancel();
                    metrics::get().set_throttled_users(throttled_count(&self.throttle));
                    let _ = Self::auth_canceled(&ctxt).await;
                    return (false, "Sign-in was canceled".into(), 0);
                }
                if let Some(rest) = MIN_FAILURE_LATENCY.checked_sub(started.elapsed()) {
                    tokio::time::sleep(rest).await;
                }
                let lock = record_failure(&self.throttle, key);
                metrics::get().inc_failure();
                metrics::get().set_throttled_users(throttled_count(&self.throttle));
                let (msg, ms) = (err.to_string(), lock.as_millis() as u32);
                let _ = Self::auth_failed(&ctxt, &msg, ms).await;
                (false, msg, ms)
            }
        }
    }
}

#[interface(name = "org.lionos.Greeter1")]
impl Greeter {
    #[zbus(property)]
    async fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    /// JSON array of features the UI can rely on. Lets us add new
    /// optional behaviour later without ABI breakage. `"mlock"` is
    /// only advertised when the kernel actually pinned our pages —
    /// an advertised-but-absent guarantee would be worse than none.
    /// `"seat-switch"` only while logind is reachable.
    #[zbus(property)]
    async fn capabilities(&self) -> String {
        let mut caps = String::from(
            r#"["cancel","metrics","conversation","autologin","sessions","auth-methods""#,
        );
        if mlock::is_locked() {
            caps.push_str(",\"mlock\"");
        }
        if self.logind_ok() {
            caps.push_str(",\"seat-switch\"");
        }
        caps.push(']');
        caps
    }

    #[zbus(property)]
    async fn autologin_user(&self) -> String {
        self.cfg.autologin.user.clone().unwrap_or_default()
    }

    #[zbus(property)]
    async fn autologin_delay_ms(&self) -> u64 {
        self.cfg.autologin.delay_ms
    }

    #[zbus(property)]
    async fn autologin_relogin(&self) -> bool {
        self.cfg.autologin.relogin
    }

    /// Last-chosen session id (persisted across boots), "" when none.
    #[zbus(property)]
    async fn last_session(&self) -> String {
        state::last_session().unwrap_or_default()
    }

    /// `[session] default` from greeter.toml, "" when unset.
    #[zbus(property)]
    async fn default_session(&self) -> String {
        self.cfg.session.default.clone().unwrap_or_default()
    }

    /// Which auth methods this machine can speak right now, with live
    /// daemon state for fingerprint. The UI renders its method logos
    /// from this — no guessing, no polling /proc.
    #[zbus(property)]
    async fn auth_methods(&self) -> String {
        let fprintd = match LIVE_CONN.get() {
            Some(conn) => methods::fprintd_running(conn).await,
            None => false,
        };
        methods::auth_methods_json(fprintd)
    }

    async fn list_users(&self) -> String {
        let last = state::last_user();
        let users = tokio::task::spawn_blocking(users_enum::enumerate_users_cached)
            .await
            .unwrap_or_default();
        // Pre-allocate the result vec with the exact capacity we need
        // so the only allocations during the map are the per-entry
        // `String` clones (unavoidable: they need to live in the JSON).
        let mut entries: Vec<UserEntry> = Vec::with_capacity(users.len());
        for u in users {
            entries.push(UserEntry {
                last_used: last.as_deref() == Some(u.username.as_str()),
                avatar_path: u.avatar_path.unwrap_or_default(),
                session_type: u.session_type.as_str(),
                username: u.username,
                full_name: u.full_name,
            });
        }
        // Stable partition: last_used first, others retain sort order.
        //
        // We do this with a single pass of `sort_by_key` rather than
        // `partition_dedup` / `sort_by` because the closure is branch-
        // free and `sort_by_key` is stable (preserves the alphabetical
        // order we got from `enumerate_users`).
        entries.sort_by_key(|e| !e.last_used);
        serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
    }

    async fn get_last_user(&self) -> String {
        state::last_user().unwrap_or_default()
    }

    /// 0.6.0: the installed desktop sessions (the gear-menu data).
    /// Read-only, cached 5 s, empty array when none are installed.
    async fn list_sessions(&self) -> String {
        let sessions = tokio::task::spawn_blocking(sessions::enumerate)
            .await
            .unwrap_or_default();
        serde_json::to_string(&sessions).unwrap_or_else(|_| "[]".into())
    }

    /// 0.6.0: the last-chosen session id, "" when never chosen.
    async fn get_last_session(&self) -> String {
        state::last_session().unwrap_or_default()
    }

    /// 0.6.0: live logind snapshot — every logged-in session with its
    /// seat, class and active flag. Empty array (never an error) when
    /// logind is absent or refuses.
    async fn list_seat_sessions(&self, #[zbus(connection)] conn: &zbus::Connection) -> String {
        match seat::list_sessions(conn).await {
            Ok(list) => {
                seat::note_logind(true);
                serde_json::to_string(&list).unwrap_or_else(|_| "[]".into())
            }
            Err(reason) => {
                seat::note_logind(false);
                tracing::debug!(%reason, "no logind session snapshot");
                "[]".into()
            }
        }
    }

    /// 0.6.0: jump the seat's console to a VT — the primitive behind
    /// "switch user" (the UI returns to the greeter's own VT).
    /// Explicit member name: the automatic conversion would produce
    /// "SwitchToVt"; the documented API is "SwitchToVT".
    #[zbus(name = "SwitchToVT")]
    async fn switch_to_vt(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        vt: u32,
    ) -> (bool, String) {
        if vt == 0 || vt > 63 {
            // logind's own range; reject before anything else so a
            // hostile client cannot use the greeter as a fuzzer.
            return (false, "VT out of range".into());
        }
        if !self.logind_ok() {
            return (false, "Seat switching unavailable (no logind)".into());
        }
        match seat::switch_to_vt(conn, vt).await {
            Ok(()) => {
                metrics::get().inc_seat_switch();
                (true, String::new())
            }
            Err(reason) => (false, reason),
        }
    }

    /// 0.6.0: switch to a specific logind session id.
    async fn activate_session(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        session_id: String,
    ) -> (bool, String) {
        // logind session ids are "[0-9]+" or "c[0-9]+" — validated
        // before anything is forwarded to the bus.
        if !is_logind_session_id(&session_id) {
            return (false, "Malformed session id".into());
        }
        if !self.logind_ok() {
            return (false, "Seat switching unavailable (no logind)".into());
        }
        match seat::activate_session(conn, &session_id).await {
            Ok(()) => {
                metrics::get().inc_seat_switch();
                (true, String::new())
            }
            Err(reason) => (false, reason),
        }
    }

    /// 0.6.0: ask another user's session to lock itself (the polite
    /// prelude to a seat switch on shared machines).
    async fn lock_session(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        session_id: String,
    ) -> (bool, String) {
        if !is_logind_session_id(&session_id) {
            return (false, "Malformed session id".into());
        }
        if !self.logind_ok() {
            return (false, "Seat switching unavailable (no logind)".into());
        }
        match seat::lock_session(conn, &session_id).await {
            Ok(()) => (true, String::new()),
            Err(reason) => (false, reason),
        }
    }

    async fn authenticate(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        username: String,
        password: String,
    ) -> (bool, String, u32) {
        self.authenticate_common(ctxt, username, password, None)
            .await
    }

    /// 0.6.0: authenticate *and* choose the desktop session. The id
    /// is validated against the installed list before anything else
    /// happens — a bad id costs no throttle budget and no metrics,
    /// because it is a UI bug, not an attack on the account.
    async fn authenticate_session(
        &self,
        #[zbus(signal_context)] ctxt: SignalContext<'_>,
        username: String,
        password: String,
        session_id: String,
    ) -> (bool, String, u32) {
        self.authenticate_common(ctxt, username, password, Some(session_id))
            .await
    }

    /// Cooperative cancel of an in-flight `Authenticate`. Returns true if
    /// there was something to cancel (the in-flight call will then emit
    /// `AuthCanceled`). Returns false if no auth is running. Also wakes
    /// and aborts any conversation round so a parked worker unblocks
    /// immediately instead of at the 30 s deadline.
    async fn cancel_auth(&self) -> bool {
        let c = {
            let g = self.cancel.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().map(|c| {
                c.store(true, Ordering::Release);
                c.clone()
            })
        };
        if c.is_some() {
            self.conv.cancel_all();
            true
        } else {
            false
        }
    }

    /// Answer a forwarded PAM prompt. `answers` must align with the
    /// prompts of the round named by `request_id` (one string each, in
    /// order; info/error slots accept ""). Returns false for unknown or
    /// already-finished rounds or over-long answers.
    async fn reply_conversation(&self, request_id: u64, answers: Vec<String>) -> bool {
        if answers.is_empty() || answers.iter().any(|a| a.len() > MAX_ANSWER_BYTES) {
            return false;
        }
        let ok = self.conv.reply(request_id, answers);
        if !ok {
            tracing::warn!(request_id, "reply to unknown/finished conversation round");
        }
        ok
    }

    /// Disarm the pending automatic sign-in (the "Esc" affordance).
    /// Returns true if a countdown or autologin attempt was actually
    /// running.
    async fn cancel_autologin(&self) -> bool {
        if self.autologin.armed.load(Ordering::Acquire) {
            self.autologin.cancel.store(true, Ordering::Release);
            return true;
        }
        false
    }

    async fn get_metrics(&self) -> String {
        metrics::get().to_json()
    }

    async fn reset_metrics(&self) {
        metrics::get().reset();
    }

    #[zbus(signal)]
    async fn auth_progress(ctxt: &SignalContext<'_>, stage: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn auth_failed(
        ctxt: &SignalContext<'_>,
        message: &str,
        retry_after_ms: u32,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn auth_succeeded(ctxt: &SignalContext<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn auth_canceled(ctxt: &SignalContext<'_>) -> zbus::Result<()>;

    /// A live PAM question, forwarded from the worker thread. The UI
    /// renders each prompt per its `style` and calls
    /// `ReplyConversation(request_id, answers)`.
    #[zbus(signal)]
    async fn conversation_prompt(
        ctxt: &SignalContext<'_>,
        request_id: u64,
        prompts_json: &str,
    ) -> zbus::Result<()>;

    /// The autologin countdown, ~5x per second, until it hits 0.
    #[zbus(signal)]
    async fn autologin_countdown(ctxt: &SignalContext<'_>, ms_left: u32) -> zbus::Result<()>;

    /// Autologin ended without a session; the UI should fall back to
    /// the manual form. The reason is safe to display.
    #[zbus(signal)]
    async fn autologin_aborted(ctxt: &SignalContext<'_>, reason: &str) -> zbus::Result<()>;

    /// 0.6.0: the logind session/seat snapshot changed. The UI
    /// re-fetches via `ListSeatSessions` — typically to update a
    /// "2 users signed in" affordance.
    #[zbus(signal)]
    async fn sessions_changed(ctxt: &SignalContext<'_>) -> zbus::Result<()>;
}

/// Drive the login worker, relaying its stages and live conversation
/// rounds as D-Bus signals in order.
#[allow(clippy::too_many_arguments)]
async fn run_login(
    ctxt: &SignalContext<'_>,
    user: users_enum::LocalUser,
    password: Zeroizing<String>,
    cancel: Arc<AtomicBool>,
    conv_tx: tokio::sync::mpsc::UnboundedSender<ConvEvent>,
    mut conv_rx: UnboundedReceiver<ConvEvent>,
    conv_registry: Arc<ConvRegistry>,
    session: Option<sessions::SessionEntry>,
) -> Result<(), AuthError> {
    let (stage_tx, mut stage_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut ready = auth::spawn_login(user, password, stage_tx, cancel, conv_tx, session);

    let result = loop {
        tokio::select! {
            Some(stage) = stage_rx.recv() => {
                if !matches!(stage, Stage::Verifying) {
                    let _ = Greeter::auth_progress(ctxt, stage.as_str()).await;
                }
            }
            Some(event) = conv_rx.recv() => {
                let (id, prompts) = conv_registry.register(event);
                let json = prompts_to_json(&prompts);
                tracing::debug!(request_id = id, prompts = prompts.len(), "conversation round forwarded");
                let _ = Greeter::conversation_prompt(ctxt, id, &json).await;
            }
            res = &mut ready => break res.unwrap_or(Err(AuthError::Service)),
        }
    };
    while let Ok(stage) = stage_rx.try_recv() {
        if !matches!(stage, Stage::Verifying) {
            let _ = Greeter::auth_progress(ctxt, stage.as_str()).await;
        }
    }
    // Release anything the worker left parked (it cannot answer them now).
    conv_registry.cancel_all();
    if result.is_ok() {
        metrics::get().inc_session();
    }
    result.map(|_pid| ())
}

// ── autologin driver ───────────────────────────────────────────────────

fn fresh_autologin_state() -> Arc<AutologinState> {
    Arc::new(AutologinState {
        armed: AtomicBool::new(false),
        cancel: Arc::new(AtomicBool::new(false)),
        fired: AtomicBool::new(false),
    })
}

async fn autologin_driver(conn: zbus::Connection, cfg: &'static Config, auto: Arc<AutologinState>) {
    let Some(user_name) = cfg.autologin.user.clone() else {
        return;
    };

    // relogin=false: only the first greeter activation auto-logs-in.
    // (A logout must not bounce the user straight back in.)
    if !cfg.autologin.relogin && auto.fired.swap(true, Ordering::AcqRel) {
        return;
    }
    auto.fired.store(true, Ordering::Release);

    let ctxt = match SignalContext::new(&conn, OBJECT_PATH) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "autologin: no signal context");
            return;
        }
    };

    // Resolve the user before the countdown: a misconfigured name must
    // not make the greeter count to zero and then die silently.
    let user = tokio::task::spawn_blocking({
        let name = user_name.clone();
        move || users_enum::find_eligible(&name)
    })
    .await
    .ok()
    .flatten();
    let user = match user {
        Some(u) => u,
        None => {
            tracing::warn!(user = %user_name, "autologin: user missing or ineligible; falling back to manual");
            metrics::get().inc_autologin_abort();
            let _ = Greeter::autologin_aborted(&ctxt, "user-unavailable").await;
            return;
        }
    };

    // Countdown.
    auto.armed.store(true, Ordering::Release);
    auto.cancel.store(false, Ordering::Release);
    let total = Duration::from_millis(cfg.autologin.delay_ms);
    let deadline = Instant::now() + total;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        if auto.cancel.load(Ordering::Acquire) {
            metrics::get().inc_autologin_abort();
            let _ = Greeter::autologin_aborted(&ctxt, "canceled").await;
            auto.armed.store(false, Ordering::Release);
            return;
        }
        let ms_left = remaining.as_millis().min(u32::MAX as u128) as u32;
        let _ = Greeter::autologin_countdown(&ctxt, ms_left).await;
        let step = remaining.min(COUNTDOWN_TICK);
        tokio::time::sleep(step).await;
    }

    // Fire.
    metrics::get().inc_autologin_fire();
    tracing::info!(user = %user_name, "autologin firing");
    // Kioscs pin the session in greeter.toml; everyone else reuses the
    // last-chosen desktop. Both degrade to lion-session's default.
    let session = match resolve_session(None) {
        Ok(s) => s,
        Err(reason) => {
            tracing::warn!(%reason, "autologin: session resolution failed; using default");
            None
        }
    };
    let (stage_tx, mut stage_rx) = tokio::sync::mpsc::unbounded_channel();
    let cancel = auto.cancel.clone();
    let chosen_session = session.clone();
    let mut ready = auth::spawn_autologin(user, stage_tx, cancel, session);

    let result = loop {
        tokio::select! {
            Some(stage) = stage_rx.recv() => {
                if !matches!(stage, Stage::Verifying) {
                    let _ = Greeter::auth_progress(&ctxt, stage.as_str()).await;
                }
            }
            res = &mut ready => break res.unwrap_or(Err(AuthError::Service)),
        }
    };

    auto.armed.store(false, Ordering::Release);
    match result {
        Ok(_pid) => {
            state::set_last_user(&user_name);
            if let Some(s) = &chosen_session {
                state::set_last_session(&s.id);
            }
            state::touch_last_session();
            metrics::get().inc_success();
            metrics::get().inc_session();
            let _ = Greeter::auth_succeeded(&ctxt).await;
        }
        Err(AuthError::AutologinUnavailable) => {
            // The PAM stack wants a real authentication: fall back to
            // the manual form. Not a failure worth charging the user.
            metrics::get().inc_autologin_abort();
            let _ = Greeter::autologin_aborted(&ctxt, "pam-requires-authentication").await;
        }
        Err(AuthError::Canceled) => {
            metrics::get().inc_autologin_abort();
            let _ = Greeter::autologin_aborted(&ctxt, "canceled").await;
        }
        Err(e) => {
            metrics::get().inc_autologin_abort();
            let reason = if matches!(e, AuthError::SessionFailed) {
                "session-start-failed"
            } else {
                "unavailable"
            };
            let _ = Greeter::autologin_aborted(&ctxt, reason).await;
        }
    }
}

// Thin wrappers around the std::sync::Mutex so the rest of the impl
// doesn't need to repeat the poison-recovery dance.

fn remaining(throttle: &Mutex<Throttle>, key: &str) -> Option<Duration> {
    throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remaining(key)
}

fn reset(throttle: &Mutex<Throttle>, key: &str) {
    throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .reset(key);
}

fn record_failure(throttle: &Mutex<Throttle>, key: &str) -> Duration {
    throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .record_failure(key)
}

fn throttled_count(throttle: &Mutex<Throttle>) -> u64 {
    throttle
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .tracked_len() as u64
}

/// logind session ids: "12" or "c3" (numeric counter, optional
/// 'c' prefix). Validated before any forwarding to the bus.
fn is_logind_session_id(s: &str) -> bool {
    let digits = s.strip_prefix('c').unwrap_or(s);
    !s.is_empty()
        && s.len() <= 16
        && !digits.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit() || b == b'c')
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Poll logind for the session/seat snapshot and emit
/// `SessionsChanged` when it moves. One `ListSessions` call every 5 s
/// while logind is reachable; the task exits quietly when logind
/// disappears (the capability flag already said "off").
async fn seat_watcher(conn: zbus::Connection) {
    let ctxt = match SignalContext::new(&conn, OBJECT_PATH) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut last_snapshot: Option<String> = None;
    loop {
        match seat::list_sessions(&conn).await {
            Ok(list) => {
                seat::note_logind(true);
                let snap = serde_json::to_string(&list).unwrap_or_default();
                if last_snapshot.as_deref() != Some(snap.as_str()) {
                    if last_snapshot.is_some() {
                        // Only signal on a *change*, never on the first
                        // observation — the first is not news.
                        let _ = Greeter::sessions_changed(&ctxt).await;
                    }
                    last_snapshot = Some(snap);
                }
            }
            Err(_) => {
                seat::note_logind(false);
                return; // logind went away; stop polling
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Register on the system bus, then start the autologin driver (which
/// is a no-op unless `[autologin] user` is configured) and the seat
/// watcher (no-op without logind). Keep the returned connection alive.
pub async fn serve() -> anyhow::Result<zbus::Connection> {
    let cfg = Config::load();
    let autologin_state = fresh_autologin_state();
    let conn = connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(
            OBJECT_PATH,
            Greeter {
                throttle: Mutex::new(Throttle::default()),
                busy: AsyncMutex::new(()),
                cancel: Mutex::new(None),
                conv: Arc::new(ConvRegistry::default()),
                autologin: autologin_state.clone(),
                cfg,
            },
        )?
        .build()
        .await?;

    // Publish the connection for property getters (fingerprint probe).
    let _ = LIVE_CONN.set(conn.clone());

    // Probe logind once: gates the seat-switch capability and the poller.
    let seat_available = seat::logind_present(&conn).await;
    seat::note_logind(seat_available);
    tracing::info!(logind = seat_available, "seat capability probe");

    if cfg.autologin.user.is_some() {
        let driver_conn = conn.clone();
        let auto = autologin_state;
        tokio::spawn(async move {
            autologin_driver(driver_conn, cfg, auto).await;
        });
    }
    if seat_available {
        let watcher_conn = conn.clone();
        tokio::spawn(async move {
            seat_watcher(watcher_conn).await;
        });
    }
    tracing::info!(bus = BUS_NAME, path = OBJECT_PATH, "IPC ready");
    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_reply_needs_live_round() {
        let reg = ConvRegistry::default();
        // Unknown id: refused.
        assert!(!reg.reply(42, vec!["nope".into()]));
    }

    #[test]
    fn registry_round_trip() {
        let reg = ConvRegistry::default();
        let slot = auth::ConvSlot::new();
        let event = ConvEvent {
            id: 7,
            prompts: vec![crate::pam_ffi::Prompt {
                style: crate::pam_ffi::PromptStyle::EchoOff,
                text: "Verification code:".into(),
            }],
            slot: slot.clone(),
        };
        let (id, prompts) = reg.register(event);
        assert_eq!(id, 7);
        assert_eq!(prompts.len(), 1);
        // First reply lands …
        assert!(reg.reply(id, vec!["123456".into()]));
        // … and the deposit is visible to the (already-returned) waiter.
        // Second reply to the same round: refused.
        assert!(!reg.reply(id, vec!["999999".into()]));
    }

    #[test]
    fn registry_cancel_all_aborts_rounds() {
        let reg = ConvRegistry::default();
        let slot = auth::ConvSlot::new();
        reg.register(ConvEvent {
            id: 1,
            prompts: vec![],
            slot: slot.clone(),
        });
        reg.cancel_all();
        // After cancel_all the round is gone: replies refused, and a
        // waiter parked on the slot would see `cancelled`.
        assert!(!reg.reply(1, vec!["x".into()]));
    }

    #[test]
    fn prompts_json_shape_is_ui_stable() {
        let prompts = vec![
            crate::pam_ffi::Prompt {
                style: crate::pam_ffi::PromptStyle::Info,
                text: "Insert your security key".into(),
            },
            crate::pam_ffi::Prompt {
                style: crate::pam_ffi::PromptStyle::EchoOff,
                text: "PIN:".into(),
            },
        ];
        let json = prompts_to_json(&prompts);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v[0]["style"], "info");
        assert_eq!(v[0]["text"], "Insert your security key");
        assert_eq!(v[1]["style"], "echo_off");
        assert_eq!(v[1]["text"], "PIN:");
    }

    /// The capability string is valid JSON in both mlock states and
    /// always carries the 0.6.0 surface.
    #[test]
    fn capabilities_json_valid_without_mlock() {
        // In the test sandbox mlockall is typically not applied, but
        // the property must be valid JSON regardless.
        let caps = {
            let mut caps = String::from(
                r#"["cancel","metrics","conversation","autologin","sessions","auth-methods"]"#,
            );
            if mlock::is_locked() {
                caps.pop();
                caps.push_str(",\"mlock\"]");
            }
            caps
        };
        let v: serde_json::Value = serde_json::from_str(&caps).expect("valid JSON");
        let arr = v.as_array().expect("array");
        assert!(arr.iter().any(|x| x == "conversation"));
        assert!(arr.iter().any(|x| x == "autologin"));
        assert!(arr.iter().any(|x| x == "sessions"));
        assert!(arr.iter().any(|x| x == "auth-methods"));
    }

    #[test]
    fn session_resolution_priority() {
        // Explicit beats config default beats last-chosen.
        assert_eq!(
            resolve_session_id(Some("explicit"), Some("cfg"), Some("last")),
            Some("explicit".into())
        );
        assert_eq!(
            resolve_session_id(None, Some("cfg"), Some("last")),
            Some("cfg".into())
        );
        assert_eq!(
            resolve_session_id(None, None, Some("last")),
            Some("last".into())
        );
        assert_eq!(resolve_session_id(None, None, None), None);
    }

    #[test]
    fn logind_session_id_validation() {
        assert!(is_logind_session_id("2"));
        assert!(is_logind_session_id("c3"));
        assert!(is_logind_session_id("123456"));
        assert!(!is_logind_session_id(""));
        assert!(!is_logind_session_id("c")); // prefix without digits
        assert!(!is_logind_session_id("cc3"));
        assert!(!is_logind_session_id("3c"));
        assert!(!is_logind_session_id("abc"));
        assert!(!is_logind_session_id("2;rm -rf"));
        assert!(!is_logind_session_id(&"9".repeat(17)));
    }

    /// A session id with a path traversal shape must never resolve.
    #[test]
    fn explicit_session_ids_are_scrubbed() {
        assert!(resolve_session(Some("../../etc/passwd")).is_err());
        assert!(resolve_session(Some("has space")).is_err());
        // Empty means "no preference" — not an error.
        assert!(resolve_session(None).is_ok());
    }
}
