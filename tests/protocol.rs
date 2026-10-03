#![forbid(unsafe_code)]
//! End-to-end protocol tests (spec 01 §4, §10): the real server loop over
//! a real unix socket, mock PAM/logind/launcher backends, a real test
//! client speaking JSON-lines. Covers every request and event type, the
//! trust gate, throttling, autologin, timed login and guest mode.

use lion_greeter::launch::MockLauncher;
use lion_greeter::logind::MockLogind;
use lion_greeter::pam::mock::{MockPamFactory, MockScript};
use lion_greeter::server::{run, DaemonDeps, Server};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// ── Harness ────────────────────────────────────────────────────────────
struct TestDaemon {
    task: tokio::task::JoinHandle<()>,
    socket: PathBuf,
    launcher: Arc<MockLauncher>,
    logind: Arc<MockLogind>,
    _pam: Arc<MockPamFactory>,
    _dir: tempfile::TempDir,
    _cfg_path: PathBuf,
}

fn fixture_passwd(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("passwd");
    std::fs::write(
        &p,
        "root:x:0:0:root:/root:/bin/bash\n\
         daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
         alice:x:1000:1000:Alice Lion:/home/alice:/bin/bash\n\
         bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n\
         carol:x:1002:1002:Carol:/home/carol:/bin/bash\n\
         lion-guest:x:990:990:Guest:/tmp/lion-guest:/bin/bash\n",
    )
    .unwrap();
    p
}

fn base_config() -> Value {
    json!({
        "greeter": {
            "ui_uid": lion_greeter::sysffi::current_uid(),
            "pam": { "timeout_seconds": 2 },
            "throttle": { "cap_seconds": 3 }
        }
    })
}

async fn start_daemon(cfg: Value) -> TestDaemon {
    // Logs (idempotent init; races between parallel tests are fine).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_ansi(false)
        .try_init();
    let dir = tempfile::tempdir().unwrap();
    // Merge: use cfg's own paths if present, else tempdir defaults.
    let cfg = {
        let mut c = cfg;
        let g = c.get_mut("greeter").unwrap().as_object_mut().unwrap();
        for (k, v) in [
            ("socket_path", json!(dir.path().join("ui.sock"))),
            ("passwd_path", json!(fixture_passwd(dir.path()))),
            ("group_path", json!(dir.path().join("group"))),
            (
                "wayland_sessions_dir",
                json!(dir.path().join("wayland-sessions")),
            ),
            (
                "accountsservice_dir",
                json!(dir.path().join("AccountsService")),
            ),
            ("state_dir", json!(dir.path().join("state"))),
        ] {
            g.entry(k).or_insert(v);
        }
        c
    };
    std::fs::write(dir.path().join("group"), "users:x:100:alice,bob\n").unwrap();
    std::fs::create_dir_all(dir.path().join("wayland-sessions")).unwrap();

    let cfg_path = dir.path().join("greeter.json");
    std::fs::write(&cfg_path, cfg.to_string()).unwrap();
    let config = lion_greeter::config::Config::load(&cfg_path).unwrap();

    let pam: Arc<MockPamFactory> = Arc::new(
        MockPamFactory::new(MockScript::failure("nope"))
            .with_script("alice", MockScript::success("correct-horse"))
            .with_script("bob", MockScript::multi_prompt("pw", "123456"))
            .with_script("carol", MockScript::expired("oldpw", "newpw"))
            .with_autologin("alice"),
    );
    let logind = Arc::new(MockLogind::new());
    let launcher = Arc::new(MockLauncher::new());
    let server = Server::new(
        config,
        DaemonDeps {
            pam: pam.clone(),
            logind: logind.clone(),
            launcher: launcher.clone(),
        },
    );
    let socket = server.data.read().unwrap().cfg.greeter.socket_path.clone();
    let cfg_path_for_task = cfg_path.clone();
    let task = tokio::spawn(async move {
        let _ = run(server, cfg_path_for_task).await;
    });
    // Wait for the socket to exist (daemon ready).
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    TestDaemon {
        task,
        socket,
        launcher,
        logind,
        _pam: pam,
        _dir: dir,
        _cfg_path: cfg_path,
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        self.task.abort();
    }
}

// ── Test client ────────────────────────────────────────────────────────
struct TestClient {
    tx: tokio::net::unix::OwnedWriteHalf,
    rx: BufReader<tokio::net::unix::OwnedReadHalf>,
    next_id: u64,
    /// Events buffered while waiting for a specific response (events and
    /// responses interleave on the wire, so waiters must not consume each
    /// other's messages).
    pending: std::collections::VecDeque<Value>,
}

impl TestClient {
    async fn connect(path: &std::path::Path) -> TestClient {
        let stream = UnixStream::connect(path).await.unwrap();
        let (rd, wr) = stream.into_split();
        TestClient {
            tx: wr,
            rx: BufReader::new(rd),
            next_id: 0,
            pending: Default::default(),
        }
    }

    async fn send(&mut self, op: &str, extra: Value) -> u64 {
        self.next_id += 1;
        let mut msg = json!({ "proto": 1, "id": self.next_id, "op": op });
        if let (Some(dst), Some(src)) = (msg.as_object_mut(), extra.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        self.tx.write_all(msg.to_string().as_bytes()).await.unwrap();
        self.tx.write_all(b"\n").await.unwrap();
        self.tx.flush().await.unwrap();
        self.next_id
    }

    async fn send_raw(&mut self, line: &str) {
        self.tx.write_all(line.as_bytes()).await.unwrap();
        self.tx.write_all(b"\n").await.unwrap();
        self.tx.flush().await.unwrap();
    }

    /// Next line from the daemon (timeout-bounded), as JSON.
    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), self.rx.read_line(&mut line))
            .await
            .expect("timed out waiting for daemon message")
            .expect("read error");
        assert!(n > 0, "daemon closed the connection");
        serde_json::from_str(line.trim()).unwrap()
    }

    /// Read frames until the response for `id` (non-matching events are
    /// buffered for `event()`).
    async fn response(&mut self, id: u64) -> Value {
        if let Some(pos) = self
            .pending
            .iter()
            .position(|v| v.get("id").and_then(Value::as_u64) == Some(id) && v.get("ok").is_some())
        {
            return self.pending.remove(pos).unwrap();
        }
        loop {
            let v = self.recv().await;
            if v.get("id").and_then(Value::as_u64) == Some(id) && v.get("ok").is_some() {
                return v;
            }
            self.pending.push_back(v);
        }
    }

    /// Read frames until an event with the given name for `id` (buffered
    /// first).
    async fn event(&mut self, id: u64, name: &str) -> Value {
        if let Some(pos) = self.pending.iter().position(|v| {
            v.get("id").and_then(Value::as_u64) == Some(id)
                && v.get("event").and_then(Value::as_str) == Some(name)
        }) {
            return self.pending.remove(pos).unwrap();
        }
        loop {
            let v = self.recv().await;
            if v.get("id").and_then(Value::as_u64) == Some(id)
                && v.get("event").and_then(Value::as_str) == Some(name)
            {
                return v;
            }
            self.pending.push_back(v);
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────
#[tokio::test]
async fn list_users_shape_and_gating() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("ListUsers", json!({})).await;
    let resp = c.response(id).await;
    assert_eq!(resp["ok"], json!(true));
    let users = resp["result"]["users"].as_array().unwrap();
    let names: Vec<&str> = users.iter().filter_map(|u| u["name"].as_str()).collect();
    assert_eq!(names, ["alice", "bob", "carol"]); // system users hidden
    assert_eq!(resp["result"]["show_user_list"], json!(true));
    assert_eq!(resp["result"]["allow_guest"], json!(false));
    let alice = &users[0];
    assert_eq!(alice["uid"], json!(1000));
    assert_eq!(alice["real_name"], json!("Alice Lion"));
    assert_eq!(alice["is_guest"], json!(false));
}

#[tokio::test]
async fn list_sessions_includes_builtin_lion() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("ListSessions", json!({})).await;
    let resp = c.response(id).await;
    assert_eq!(resp["ok"], json!(true));
    let sessions = resp["result"]["sessions"].as_array().unwrap();
    assert_eq!(sessions[0]["id"], json!("lion"));
    assert_eq!(sessions[0]["exec"], json!("lion-session"));
    assert_eq!(sessions[0]["builtin"], json!(true));
    assert_eq!(resp["result"]["default"], json!("lion"));
}

#[tokio::test]
async fn auth_success_launch_flow() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "alice" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["result"]["user"], json!("alice"));
    let prompt = c.event(id, "Prompt").await;
    assert_eq!(prompt["text"].as_str().unwrap(), "Password: ");
    let aid = c
        .send("AnswerPrompt", json!({ "text": "correct-horse" }))
        .await;
    let _ = c.response(aid).await;
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(true));
    let lid = c.send("Launch", json!({ "session": "lion" })).await;
    let lresp = c.response(lid).await;
    assert_eq!(lresp["ok"], json!(true), "{lresp}");
    assert!(lresp["result"]["pid"].as_u64().unwrap() > 0);
    assert!(lresp["result"]["session_id"]
        .as_str()
        .unwrap()
        .starts_with("mock-session-"));

    let launches = d.launcher.launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].user.name, "alice");
    assert_eq!(launches[0].session.id, "lion");
    assert!(!launches[0].guest);
    // logind registration happens inside the *real* launcher (the mock
    // records only); it is exercised by the systemd-nspawn CI job.
}

#[tokio::test]
async fn auth_failure_throttle_surface() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    // wrong password → AuthResult{ok:false} + Throttle
    let id = c.send("StartAuth", json!({ "user": "alice" })).await;
    let _ = c.response(id).await;
    let _ = c.event(id, "Prompt").await;
    let aid = c.send("AnswerPrompt", json!({ "text": "wrong" })).await;
    let _ = c.response(aid).await;
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(false));
    assert_eq!(res["reason"], json!("authentication failed"));
    let throttle = c.event(id, "Throttle").await;
    assert!(throttle["seconds"].as_u64().unwrap() >= 1);
    // immediate retry → throttled error response (pace to clear the
    // StartAuth rate gate first)
    tokio::time::sleep(Duration::from_millis(300)).await;
    let id2 = c.send("StartAuth", json!({ "user": "alice" })).await;
    let resp = c.response(id2).await;
    assert_eq!(resp["ok"], json!(false));
    assert_eq!(resp["error"]["code"], json!("throttled"));
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("retry in"));
}

#[tokio::test]
async fn auth_expired_password_flow() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "carol" })).await;
    let _ = c.response(id).await;
    let p1 = c.event(id, "Prompt").await;
    assert_eq!(p1["text"], json!("Current password: "));
    let a1 = c.send("AnswerPrompt", json!({ "text": "oldpw" })).await;
    let _ = c.response(a1).await;
    let p2 = c.event(id, "Prompt").await;
    assert_eq!(p2["text"], json!("New password: "));
    let a2 = c.send("AnswerPrompt", json!({ "text": "newpw" })).await;
    let _ = c.response(a2).await;
    let p3 = c.event(id, "Prompt").await;
    assert_eq!(p3["text"], json!("Retype new password: "));
    let a3 = c.send("AnswerPrompt", json!({ "text": "newpw" })).await;
    let _ = c.response(a3).await;
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(true), "{res}");
}

#[tokio::test]
async fn auth_multi_prompt_otp_flow() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "bob" })).await;
    let _ = c.response(id).await;
    let p1 = c.event(id, "Prompt").await;
    assert_eq!(p1["kind"], json!("secret"));
    let a1 = c.send("AnswerPrompt", json!({ "text": "pw" })).await;
    let _ = c.response(a1).await;
    let p2 = c.event(id, "Prompt").await;
    assert_eq!(p2["kind"], json!("visible"));
    assert_eq!(p2["text"], json!("OTP code: "));
    let a2 = c.send("AnswerPrompt", json!({ "text": "123456" })).await;
    let _ = c.response(a2).await;
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(true));
}

#[tokio::test]
async fn cancel_auth_aborts() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "alice" })).await;
    let _ = c.response(id).await;
    let _ = c.event(id, "Prompt").await;
    let cid = c.send("CancelAuth", json!({})).await;
    let resp = c.response(cid).await;
    assert_eq!(resp["ok"], json!(true));
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(false));
    assert_eq!(res["reason"], json!("cancelled"));
}

#[tokio::test]
async fn ui_crash_mid_auth_aborts_session() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "alice" })).await;
    let _ = c.response(id).await;
    let _ = c.event(id, "Prompt").await;
    drop(c); // UI "crashes"
             // spec §6: auth aborted; new UI can start immediately
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut c2 = TestClient::connect(&d.socket).await;
    let id2 = c2.send("StartAuth", json!({ "user": "alice" })).await;
    let resp = c2.response(id2).await;
    assert_eq!(
        resp["ok"],
        json!(true),
        "session should not be busy: {resp}"
    );
}

#[tokio::test]
async fn unknown_user_and_system_user_rejected() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    for user in ["ghost", "root", "daemon"] {
        tokio::time::sleep(Duration::from_millis(300)).await; // StartAuth rate gate
        let id = c.send("StartAuth", json!({ "user": user })).await;
        let resp = c.response(id).await;
        assert_eq!(
            resp["error"]["code"],
            json!("no_such_user"),
            "{user}: {resp}"
        );
    }
}

#[tokio::test]
async fn launch_without_auth_denied() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("Launch", json!({ "session": "lion" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["error"]["code"], json!("not_authenticated"));
}

#[tokio::test]
async fn answer_without_prompt_rejected() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("AnswerPrompt", json!({ "text": "x" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["error"]["code"], json!("bad_request"));
}

#[tokio::test]
async fn protocol_errors_are_handled() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;

    // malformed JSON → per-request error, connection lives
    c.send_raw("this is not json").await;
    let v = c.recv().await;
    assert_eq!(v["error"]["code"], json!("bad_request"));

    // unknown op
    let id = c.send("Explode", json!({})).await;
    let resp = c.response(id).await;
    assert_eq!(resp["error"]["code"], json!("unknown_op"));

    // unknown field
    c.send_raw(r#"{"proto":1,"id":99,"op":"ListUsers","nope":1}"#)
        .await;
    let v = c.recv().await;
    assert_eq!(v["error"]["code"], json!("bad_request"));

    // bad proto version → fatal
    c.send_raw(r#"{"proto":9,"id":100,"op":"ListUsers"}"#).await;
    let v = c.recv().await;
    assert_eq!(v["error"]["code"], json!("proto_version"));
    // connection must be closed now
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(2), c.rx.read_line(&mut line)).await;
    match n {
        Ok(Ok(0)) => {} // EOF: closed
        Ok(Ok(_)) => panic!("expected close after fatal proto error"),
        _ => {}
    }
}

#[tokio::test]
async fn oversized_line_drops_connection() {
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let big = format!(
        "{{\"proto\":1,\"id\":1,\"op\":\"AnswerPrompt\",\"text\":\"{}\"}}",
        "x".repeat(9000)
    );
    c.send_raw(&big).await;
    let mut line = String::new();
    // either an error line or EOF must arrive within the timeout
    let n = tokio::time::timeout(Duration::from_secs(3), c.rx.read_line(&mut line)).await;
    assert!(n.is_ok(), "no response to oversized frame");
}

#[tokio::test]
async fn power_actions_routed_and_gated() {
    let mut cfg = base_config();
    cfg["greeter"]["power"] = json!({ "allowed": ["reboot", "suspend"] });
    let d = start_daemon(cfg).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("Power", json!({ "action": "reboot" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["ok"], json!(true));
    tokio::time::sleep(Duration::from_millis(1100)).await; // Power rate gate
    let id = c.send("Power", json!({ "action": "poweroff" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["error"]["code"], json!("power_denied"));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let id = c.send("Power", json!({ "action": "suspend" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["ok"], json!(true));
    let calls = d.logind.power_calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert!(calls.contains(&lion_greeter::proto::PowerAction::Reboot));
}

#[tokio::test]
async fn wrong_peer_uid_rejected() {
    let mut cfg = base_config();
    cfg["greeter"]["ui_uid"] = json!(4242); // nobody we can be
    let d = start_daemon(cfg).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("ListUsers", json!({})).await;
    let mut line = String::new();
    let n = tokio::time::timeout(Duration::from_secs(2), c.rx.read_line(&mut line))
        .await
        .expect("timeout");
    // Fail closed: no response, connection dropped.
    assert_eq!(n.unwrap_or(0), 0);
    let _ = id;
}

#[tokio::test]
async fn guest_disabled_then_enabled() {
    // disabled by default → not_allowed
    let d = start_daemon(base_config()).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("StartAuth", json!({ "user": "lion-guest" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["error"]["code"], json!("not_allowed"));
    drop(c);

    // enabled → guest appears in ListUsers, auth ok, launch guest
    let mut cfg = base_config();
    cfg["greeter"]["allow_guest"] = json!(true);
    let d = start_daemon(cfg).await;
    let mut c = TestClient::connect(&d.socket).await;
    let id = c.send("ListUsers", json!({})).await;
    let resp = c.response(id).await;
    let users = resp["result"]["users"].as_array().unwrap();
    let guest = users.iter().find(|u| u["is_guest"] == json!(true)).unwrap();
    assert_eq!(guest["name"], json!("lion-guest"));

    let id = c.send("StartAuth", json!({ "user": "lion-guest" })).await;
    let resp = c.response(id).await;
    assert_eq!(resp["ok"], json!(true));
    assert_eq!(resp["result"]["guest"], json!(true));
    let res = c.event(id, "AuthResult").await;
    assert_eq!(res["ok"], json!(true));

    let lid = c.send("Launch", json!({ "session": "lion" })).await;
    let lresp = c.response(lid).await;
    assert_eq!(lresp["ok"], json!(true), "{lresp}");
    let launches = d.launcher.launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert!(launches[0].guest);
    assert_eq!(launches[0].user.name, "lion-guest");
}

#[tokio::test]
async fn autologin_fires_without_client() {
    let mut cfg = base_config();
    cfg["greeter"]["autologin"] = json!({ "user": "alice" });
    let d = start_daemon(cfg).await;
    // No client connected at all: the internal transaction must still run.
    for _ in 0..100 {
        if !d.launcher.launches.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let launches = d.launcher.launches.lock().unwrap();
    assert_eq!(launches.len(), 1);
    assert_eq!(launches[0].user.name, "alice");
    assert!(!launches[0].guest);
}

#[tokio::test]
async fn timed_login_counts_down_and_fires() {
    let mut cfg = base_config();
    cfg["greeter"]["timed_login"] = json!({ "user": "alice", "delay_seconds": 1 });
    let d = start_daemon(cfg).await;
    let mut c = TestClient::connect(&d.socket).await;
    // countdown info prompts (id 0)
    let v = tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .unwrap();
    assert_eq!(v["event"], json!("Prompt"));
    assert_eq!(v["kind"], json!("info"));
    assert!(v["text"].as_str().unwrap().contains("alice"));
    // fire after 1 s: internal auth + auto launch
    for _ in 0..100 {
        if !d.launcher.launches.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(d.launcher.launches.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn timed_login_cancelled_by_interaction() {
    let mut cfg = base_config();
    cfg["greeter"]["timed_login"] = json!({ "user": "alice", "delay_seconds": 1 });
    let d = start_daemon(cfg).await;
    let mut c = TestClient::connect(&d.socket).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), c.recv()).await; // first countdown tick
    let _id = c.send("ListSessions", json!({})).await; // user interaction
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        d.launcher.launches.lock().unwrap().len(),
        0,
        "timed login should be cancelled"
    );
}
