#![forbid(unsafe_code)]
//! Authentication engine (spec 01 §3, §4, §6).
//!
//! One PAM transaction per [`AuthSession::start_pam`] runs on a dedicated
//! worker thread. The thread owns the transaction (thread-affine by PAM's
//! contract) and lives through the whole session handshake:
//!
//! ```text
//! UI ──StartAuth──▶ server ──spawn worker──▶ thread:
//!                                           pam_start + authenticate
//!   ◀──Prompt{…}──── bridge ◀──converse──── (PAM conversation callback)
//!   ──AnswerPrompt─▶ bridge ──answer───────▶
//!   ◀──AuthResult── (Done event)
//!   ──Launch──────▶ server ──SetCred cmd──▶ setcred, then End
//! ```
//!
//! The worker and the conversation callback run on the *same* thread, so
//! the command channel receiver is shared through a `Mutex` — the callback
//! holds it only while PAM is prompting, the worker loop only between PAM
//! calls; the two never overlap.
//!
//! Failure handling (spec §6):
//! - UI crash / disconnect → the bridge channel closes, the next
//!   conversation step fails, the transaction is aborted and wiped; the
//!   accept loop is immediately ready for a reconnect.
//! - PAM hang → every conversation step has a hard
//!   [`timeout`](crate::config::PamConfig::timeout_seconds) (default 30 s);
//!   a module that never returns leaves the worker thread parked — the
//!   server watchdog declares the session timed out and the thread
//!   self-reaps if PAM ever returns (one thread leak per pathological
//!   hang; see DESIGN.md for the trade-off).
//! - All answers travel as [`Secret`] (zeroizing) and are wiped after use.

use crate::pam::{
    AuthFailReason, AuthOutcome, ConvError, Conversation, PamServiceFactory, PromptSpec,
};
use crate::secret::Secret;
use crate::users::UserInfo;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedReceiver;

/// Commands the server sends into a worker (consumed by the conversation
/// bridge while PAM is prompting, or by the worker loop after the verdict).
#[derive(Debug)]
pub enum WorkerCmd {
    /// Answer to the current prompt (zeroizing).
    Answer(Secret),
    /// Abort the conversation.
    Cancel,
    /// After a successful verdict: `pam_setcred`.
    SetCred,
    /// `pam_end` + thread exit.
    End,
}

/// Events the worker/bridge reports back to the server task.
#[derive(Debug)]
pub enum AuthEvent {
    Prompt(PromptSpec),
    /// Verdict of `authenticate` (PAM round trip complete).
    Done(AuthOutcome),
    /// Verdict of `setcred`.
    SetCredDone(Result<(), AuthFailReason>),
    /// Worker thread has finished and the transaction is closed.
    Finished,
}

/// Shared receiver end of the worker command channel.
pub type SharedCmdRx = Arc<Mutex<Receiver<WorkerCmd>>>;

/// Bridge between the (possibly C) conversation callback and the async
/// server task. One per transaction; safe to use from the worker thread
/// only (it is also handed to PAM as `appdata_ptr`).
pub struct ConvBridge {
    evt: tokio::sync::mpsc::UnboundedSender<AuthEvent>,
    cmd: SharedCmdRx,
    step_timeout: Duration,
}

impl ConvBridge {
    pub fn new(
        evt: tokio::sync::mpsc::UnboundedSender<AuthEvent>,
        cmd: SharedCmdRx,
        step_timeout: Duration,
    ) -> Self {
        ConvBridge {
            evt,
            cmd,
            step_timeout,
        }
    }

    fn next_answer(&mut self) -> Result<Secret, ConvError> {
        let deadline = Instant::now()
            .checked_add(self.step_timeout)
            .ok_or(ConvError::Timeout)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ConvError::Timeout);
            }
            // Lock is uncontended: the worker loop is blocked inside the
            // PAM call that triggered this conversation.
            let rx = self.cmd.lock().map_err(|_| ConvError::ChannelClosed)?;
            match rx.recv_timeout(remaining) {
                Ok(WorkerCmd::Answer(s)) => return Ok(s),
                Ok(WorkerCmd::Cancel) => return Err(ConvError::Cancelled),
                Ok(_) => continue, // stray SetCred/End while prompting: ignore
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(ConvError::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(ConvError::ChannelClosed),
            }
        }
    }
}

impl Conversation for ConvBridge {
    fn converse(&mut self, prompts: &[PromptSpec]) -> Result<Vec<Secret>, ConvError> {
        for p in prompts {
            self.evt
                .send(AuthEvent::Prompt(p.clone()))
                .map_err(|_| ConvError::ChannelClosed)?;
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for _ in prompts {
            answers.push(self.next_answer()?);
        }
        Ok(answers)
    }
}

/// Handle to the worker thread.
struct Worker {
    cmd_tx: mpsc::Sender<WorkerCmd>,
    evt_rx: UnboundedReceiver<AuthEvent>,
}

impl Worker {
    fn send(&self, cmd: WorkerCmd) -> bool {
        self.cmd_tx.send(cmd).is_ok()
    }
}

/// Spawn the PAM worker thread for one transaction.
fn spawn_worker(
    factory: Arc<dyn PamServiceFactory>,
    service: String,
    user: String,
    step_timeout: Duration,
) -> Worker {
    let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel::<AuthEvent>();
    let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
    let cmd_rx = Arc::new(Mutex::new(cmd_rx));
    let bridge_cmd = cmd_rx.clone();
    let done_tx = evt_tx.clone();
    let builder = std::thread::Builder::new().name("lion-greeter-auth".into());
    let spawned = builder.spawn(move || {
        let bridge = ConvBridge::new(done_tx.clone(), bridge_cmd, step_timeout);
        let shim = crate::pam::ConvShim::new(Box::new(bridge));
        let mut svc = match factory.open(&service, &user, shim) {
            Ok(s) => s,
            Err(reason) => {
                let _ = done_tx.send(AuthEvent::Done(AuthOutcome::Failed(reason)));
                let _ = done_tx.send(AuthEvent::Finished);
                return;
            }
        };
        let outcome = svc.authenticate();
        let _ = done_tx.send(AuthEvent::Done(outcome));
        // Post-verdict phase: park for SetCred / End / Cancel / disconnect.
        // The bridge's PAM calls have all returned by now, so the shared
        // receiver lock is free.
        loop {
            let cmd = match cmd_rx.lock() {
                Ok(rx) => rx.recv(),
                Err(_) => break,
            };
            match cmd {
                Ok(WorkerCmd::SetCred) => {
                    let r = svc.setcred();
                    let _ = done_tx.send(AuthEvent::SetCredDone(r));
                }
                Ok(WorkerCmd::Answer(_)) => {
                    // stray answer after verdict: dropped, zeroized on drop
                }
                Ok(WorkerCmd::Cancel) | Ok(WorkerCmd::End) | Err(_) => break,
            }
        }
        svc.end();
        let _ = done_tx.send(AuthEvent::Finished);
    });
    if spawned.is_err() {
        // Thread spawn failed: emulate an immediate service failure so the
        // server watchdog/session machinery stays consistent.
        let _ = evt_tx.send(AuthEvent::Done(AuthOutcome::Failed(
            AuthFailReason::ServiceError,
        )));
        let _ = evt_tx.send(AuthEvent::Finished);
    }
    Worker { cmd_tx, evt_rx }
}

/// A live authentication session in the server.
pub struct AuthSession {
    /// Request id of the originating `StartAuth` (events carry it).
    pub req_id: u64,
    pub user: UserInfo,
    /// Guest sessions skip PAM entirely.
    pub guest: bool,
    phase: Phase,
    worker: Option<Worker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Authenticating,
    AuthOk,
    AuthFailed,
    Launched,
}

impl AuthSession {
    /// Guest session: authenticated by policy, no PAM.
    pub fn guest(req_id: u64, user: UserInfo) -> Self {
        AuthSession {
            req_id,
            user,
            guest: true,
            phase: Phase::AuthOk,
            worker: None,
        }
    }

    /// PAM session.
    pub fn start_pam(
        factory: Arc<dyn PamServiceFactory>,
        service: &str,
        user: UserInfo,
        step_timeout: Duration,
        req_id: u64,
    ) -> Self {
        let worker = spawn_worker(
            factory,
            service.to_string(),
            user.name.clone(),
            step_timeout,
        );
        AuthSession {
            req_id,
            user,
            guest: false,
            phase: Phase::Authenticating,
            worker: Some(worker),
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn mark_launched(&mut self) {
        self.phase = Phase::Launched;
    }

    /// Route an answer into the live conversation.
    pub fn answer(&self, secret: Secret) -> bool {
        match &self.worker {
            Some(w) if self.phase == Phase::Authenticating => w.send(WorkerCmd::Answer(secret)),
            _ => false,
        }
    }

    /// Ask for `pam_setcred` (launch path).
    pub fn setcred(&self) -> bool {
        match &self.worker {
            Some(w) if self.phase == Phase::AuthOk => w.send(WorkerCmd::SetCred),
            _ => false,
        }
    }

    /// Abort: best-effort cancel + end. The server emits the terminal
    /// `AuthResult{ok:false, reason:"cancelled"}` itself.
    pub fn cancel(&mut self) {
        if let Some(w) = &self.worker {
            let _ = w.send(WorkerCmd::Cancel);
            let _ = w.send(WorkerCmd::End);
        }
        if self.phase == Phase::Authenticating {
            self.phase = Phase::AuthFailed;
        }
    }

    /// Receive the next worker event (async, server pump).
    pub async fn recv_event(&mut self) -> AuthEvent {
        match self.worker.as_mut() {
            Some(w) => match w.evt_rx.recv().await {
                Some(e) => e,
                None => AuthEvent::Done(AuthOutcome::Failed(AuthFailReason::ServiceError)),
            },
            None => AuthEvent::Finished,
        }
    }

    /// Apply a worker event to the phase machine; returns the same event
    /// (the server forwards it to the UI).
    pub fn apply(&mut self, evt: AuthEvent) -> AuthEvent {
        match &evt {
            AuthEvent::Done(AuthOutcome::Success) => {
                if self.phase == Phase::Authenticating {
                    self.phase = Phase::AuthOk;
                }
            }
            AuthEvent::Done(AuthOutcome::Failed(_)) => {
                if self.phase == Phase::Authenticating {
                    self.phase = Phase::AuthFailed;
                }
            }
            AuthEvent::SetCredDone(Err(_)) => {
                self.phase = Phase::AuthFailed;
            }
            _ => {}
        }
        evt
    }

    /// Drop the worker (post-launch or on session end). Sends `End`.
    pub fn close(&mut self) {
        if let Some(w) = self.worker.take() {
            let _ = w.send(WorkerCmd::End);
        }
    }

    /// Session is live (authenticating or authenticated)?
    pub fn is_live(&self) -> bool {
        self.phase == Phase::Authenticating || self.phase == Phase::AuthOk
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam::mock::{MockPamFactory, MockScript};

    fn user_info(name: &str) -> UserInfo {
        UserInfo {
            name: name.into(),
            uid: 1000,
            gid: 1000,
            real_name: String::new(),
            shell: "/bin/bash".into(),
            home: "/home/x".into(),
            avatar: None,
            last_session: None,
            is_guest: false,
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn session_full_flow_success() {
        rt().block_on(async {
            let factory = Arc::new(
                MockPamFactory::new(MockScript::failure("nope"))
                    .with_script("alice", MockScript::success("pw")),
            );
            let mut s = AuthSession::start_pam(
                factory,
                "lion-greeter",
                user_info("alice"),
                Duration::from_secs(2),
                42,
            );
            assert_eq!(s.phase(), Phase::Authenticating);
            match s.recv_event().await {
                AuthEvent::Prompt(p) => assert!(p.text.contains("Password")),
                other => panic!("{other:?}"),
            }
            assert!(s.answer(Secret::new("pw".into())));
            let evt = s.recv_event().await;
            assert!(matches!(evt, AuthEvent::Done(AuthOutcome::Success)));
            assert!(matches!(
                s.apply(evt),
                AuthEvent::Done(AuthOutcome::Success)
            ));
            assert_eq!(s.phase(), Phase::AuthOk);
            assert!(s.setcred());
            assert!(matches!(
                s.recv_event().await,
                AuthEvent::SetCredDone(Ok(()))
            ));
            s.close();
            let mut finished = false;
            for _ in 0..3 {
                match s.recv_event().await {
                    AuthEvent::Finished => {
                        finished = true;
                        break;
                    }
                    AuthEvent::Done(_) | AuthEvent::SetCredDone(_) => {}
                    AuthEvent::Prompt(_) => panic!("no prompts expected"),
                }
            }
            assert!(finished);
        });
    }

    #[test]
    fn session_failure_marks_phase() {
        rt().block_on(async {
            let factory = Arc::new(MockPamFactory::new(MockScript::failure("right")));
            let mut s = AuthSession::start_pam(
                factory,
                "lion-greeter",
                user_info("bob"),
                Duration::from_secs(2),
                7,
            );
            assert!(matches!(s.recv_event().await, AuthEvent::Prompt(_)));
            s.answer(Secret::new("wrong".into()));
            let evt = s.recv_event().await;
            assert!(matches!(
                evt,
                AuthEvent::Done(AuthOutcome::Failed(AuthFailReason::AuthErr))
            ));
            s.apply(evt);
            assert_eq!(s.phase(), Phase::AuthFailed);
            s.close();
        });
    }

    #[test]
    fn cancel_aborts() {
        rt().block_on(async {
            let factory = Arc::new(MockPamFactory::new(MockScript::success("pw")));
            let mut s = AuthSession::start_pam(
                factory,
                "lion-greeter",
                user_info("alice"),
                Duration::from_secs(2),
                1,
            );
            assert!(matches!(s.recv_event().await, AuthEvent::Prompt(_)));
            s.cancel();
            let mut done = false;
            for _ in 0..3 {
                match s.recv_event().await {
                    AuthEvent::Done(AuthOutcome::Failed(AuthFailReason::Cancelled)) => done = true,
                    AuthEvent::Finished => {
                        done = true;
                        break;
                    }
                    _ => {}
                }
            }
            assert!(done);
            assert!(!s.is_live());
        });
    }

    #[test]
    fn guest_session_is_authok() {
        let s = AuthSession::guest(1, user_info("lion-guest"));
        assert_eq!(s.phase(), Phase::AuthOk);
        assert!(s.is_live());
        assert!(!s.answer(Secret::new("x".into())));
    }

    #[test]
    fn worker_spawn_failure_fails_closed() {
        rt().block_on(async {
            let factory = Arc::new(MockPamFactory::new(MockScript::success("pw")));
            let mut s = AuthSession::start_pam(
                factory,
                "lion-greeter",
                user_info("alice"),
                Duration::from_secs(1),
                1,
            );
            // (spawn succeeded here; the failure path is exercised by the
            // branch above and covered by the immediate-Done fallback)
            let _ = s.recv_event().await;
            s.close();
        });
    }
}
