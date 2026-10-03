//! lion-bench hooks (spec 01 §7): startup, auth round-trip overhead,
//! protocol decode throughput, idle RSS. Emits JSON (one object per line)
//! so `lion-bench` can consume it and CI can fail on >10% regression.
//!
//! Run: `cargo bench` (harness = false; plain timings, no criterion).

use std::io::{BufRead, Write};
use std::time::Instant;

fn main() {
    let json_mode = std::env::args().any(|a| a == "--json");
    let out = std::io::stdout();
    let mut out = out.lock();

    // ── 1. daemon startup: config load + user + session scan ──────────
    let dir = tempfile::tempdir().expect("tmpdir");
    let cfg_path = dir.path().join("greeter.json");
    let sessions_dir = dir.path().join("wayland-sessions");
    std::fs::create_dir_all(&sessions_dir).unwrap();
    std::fs::write(
        sessions_dir.join("sway.desktop"),
        "[Desktop Entry]\nName=Sway\nExec=sway\n",
    )
    .unwrap();
    std::fs::write(&cfg_path, "{}").unwrap();
    {
        let mut passwd = String::new();
        for i in 0..50 {
            passwd.push_str(&format!(
                "user{i}:x:{}:{}::/home/user{i}:/bin/bash\n",
                1000 + i,
                1000 + i
            ));
        }
        // Note: the bench measures the real /etc/passwd scan cost
        // (machine-local, acceptable for relative CI runs).
        let _ = passwd;
    }

    let t0 = Instant::now();
    let cfg = lion_greeter::config::Config::load(&cfg_path).expect("config");
    let userdb = lion_greeter::users::UserDb::from_config(&cfg);
    let n_users = userdb.list().map(|u| u.len()).unwrap_or(0);
    let sessions = lion_greeter::sessions::SessionDb::new(&cfg);
    let n_sessions = sessions.list().map(|s| s.len()).unwrap_or(0);
    let startup = t0.elapsed();

    // ── 2. PAM round-trip overhead over a 2-prompt mock ───────────────
    // (baseline: the conversation machinery only — the target is
    //  "< 20 ms over PAM's own time", measured here as pure bridge cost.)
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let auth_overhead = rt.block_on(async {
        use lion_greeter::auth::AuthSession;
        use lion_greeter::pam::mock::{MockPamFactory, MockScript};
        use lion_greeter::pam::AuthOutcome;
        use lion_greeter::secret::Secret;
        use std::sync::Arc;
        use std::time::Duration;

        let factory = Arc::new(
            MockPamFactory::new(MockScript::failure("no"))
                .with_script("bench", MockScript::multi_prompt("pw", "123456")),
        );
        let user = lion_greeter::users::UserInfo {
            name: "bench".into(),
            uid: 1000,
            gid: 1000,
            real_name: String::new(),
            shell: "/bin/bash".into(),
            home: "/home/bench".into(),
            avatar: None,
            last_session: None,
            is_guest: false,
        };
        let best = std::time::Duration::from_secs(10);
        let mut total = std::time::Duration::ZERO;
        let runs = 50u32;
        for _ in 0..runs {
            let t = Instant::now();
            let mut s = AuthSession::start_pam(
                factory.clone(),
                "lion-greeter",
                user.clone(),
                Duration::from_secs(5),
                1,
            );
            if let Ok(lion_greeter::auth::AuthEvent::Prompt(_)) =
                tokio::time::timeout(Duration::from_secs(1), s.recv_event()).await
            {
                s.answer(Secret::new("pw".into()));
                s.answer(Secret::new("123456".into()));
            }
            loop {
                match s.recv_event().await {
                    lion_greeter::auth::AuthEvent::Done(AuthOutcome::Success) => break,
                    lion_greeter::auth::AuthEvent::Done(_) => break,
                    lion_greeter::auth::AuthEvent::Prompt(_) => {
                        s.answer(Secret::new("x".into()));
                    }
                    _ => break,
                }
            }
            s.close();
            total += t.elapsed();
        }
        total.div_f64(runs as f64).min(best)
    });

    // ── 3. protocol decode throughput ─────────────────────────────────
    let line = r#"{"proto":1,"id":42,"op":"StartAuth","user":"benchmark-user"}"#;
    let t = Instant::now();
    let iters = 100_000u32;
    let mut ok = 0u32;
    for _ in 0..iters {
        if lion_greeter::proto::decode_request(line).is_ok() {
            ok += 1;
        }
    }
    let decode = t.elapsed();
    let decode_per_msg_ns = decode.as_nanos() as f64 / iters as f64;

    // ── 4. idle RSS ───────────────────────────────────────────────────
    let rss_kb = rss_kb();

    if json_mode {
        let _ = writeln!(
            out,
            "{}",
            serde_json::json!({
                "bench": "lion-greeter",
                "version": env!("CARGO_PKG_VERSION"),
                "startup_us": startup.as_micros() as u64,
                "users_scanned": n_users,
                "sessions_scanned": n_sessions,
                "auth_roundtrip_us": auth_overhead.as_micros() as u64,
                "decode_ns_per_msg": decode_per_msg_ns as u64,
                "decode_ok": ok,
                "idle_rss_kb": rss_kb,
            })
        );
    } else {
        let _ = writeln!(out, "lion-greeter bench");
        let _ = writeln!(out, "  startup (config+users+sessions): {:?}", startup);
        let _ = writeln!(
            out,
            "  auth round-trip (mock, 2 prompts): {:?}",
            auth_overhead
        );
        let _ = writeln!(
            out,
            "  decode: {:.0} ns/msg ({ok}/{iters} ok)",
            decode_per_msg_ns
        );
        let _ = writeln!(out, "  idle RSS: {} KiB", rss_kb);
    }
}

fn rss_kb() -> u64 {
    if let Ok(f) = std::fs::File::open("/proc/self/status") {
        for line in std::io::BufReader::new(f).lines().map_while(Result::ok) {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let num: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(v) = num.parse() {
                    return v;
                }
            }
        }
    }
    0
}
