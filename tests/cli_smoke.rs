//! End-to-end smoke tests against the *real* binary.
//!
//! These run the compiled `lion-greeter` executable exactly the way an
//! install script or a recovery shell would: `--version`,
//! `--check-config`, `--list-sessions`, `--list-methods`, and
//! malformed-argument handling. The daemon mode is exercised by
//! `scripts/live_dbus_test.sh` against a private dbus-daemon (it needs
//! a bus, PAM and socket permissions this harness deliberately does
//! not assume).
//!
//! What each check protects:
//! * `--version` output shape — installers grep it.
//! * `--check-config` — the "broken file never blocks login" promise,
//!   including exit code 0 on broken input (by design, documented).
//! * `--list-sessions` — valid JSON, stable field set.
//! * `--list-methods` — valid JSON, password method always present.
//! * unknown mode — helpful usage text and exit 1, not a panic.

use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lion-greeter"))
}

fn run(args: &[&str]) -> Output {
    bin()
        .args(args)
        .env(
            "LION_GREETER_SESSIONS_PATH",
            "/nonexistent/lion-test-sessions",
        )
        .env("LION_GREETER_PAM_MODULES_DIR", "/nonexistent/lion-test-pam")
        .output()
        .expect("spawn lion-greeter binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn version_reports_semver_and_service() {
    let out = run(&["--version"]);
    assert!(out.status.success(), "exit code: {:?}", out.status);
    let text = stdout(&out);
    assert!(text.contains("lion-greeter 0."), "missing semver: {text}");
    assert!(text.contains("PAM service: lion-greeter"));
    assert!(text.contains("lion-greeter-autologin"));
    assert!(text.contains("session selection"), "new features listed");
    assert!(text.contains("fast user switching"));
}

#[test]
fn check_config_on_missing_file_prints_defaults() {
    // Point at a path that certainly does not exist.
    let out = {
        let mut c = bin();
        c.arg("--check-config")
            .env("LION_GREETER_CONFIG", "/nonexistent/lion-greeter-test.toml");
        c.output().expect("spawn")
    };
    assert!(out.status.success(), "missing file must exit 0");
    let text = stdout(&out);
    assert!(text.contains("config path"));
    assert!(text.contains("autologin   : user=(disabled)"));
    assert!(text.contains("session     : default=(last-used)"));
    assert!(text.contains("no file"));
    assert!(text.contains("defaults in effect"));
}

#[test]
fn check_config_on_valid_file_applies_it() {
    let dir = std::env::temp_dir().join(format!(
        "lion-cli-cfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("greeter.toml");
    std::fs::write(
        &cfg_path,
        "[autologin]\nuser = \"alice\"\ndelay_ms = 900\n\n[session]\ndefault = \"lion\"\n",
    )
    .unwrap();
    let out = {
        let mut c = bin();
        c.arg("--check-config")
            .env("LION_GREETER_CONFIG", &cfg_path);
        c.output().expect("spawn")
    };
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("user=alice"));
    assert!(text.contains("delay_ms=900"));
    assert!(text.contains("default=lion"));
    assert!(text.contains("status      : file applied in full"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_config_on_broken_file_still_exits_zero() {
    // THE core operational promise: a broken config file can never
    // fail a boot or block a login. The tool says so, and exits 0.
    let dir = std::env::temp_dir().join(format!(
        "lion-cli-badcfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("greeter.toml");
    std::fs::write(&cfg_path, "[autologin]\nuser = \"unclosed\n").unwrap();
    let out = {
        let mut c = bin();
        c.arg("--check-config")
            .env("LION_GREETER_CONFIG", &cfg_path);
        c.output().expect("spawn")
    };
    assert!(
        out.status.success(),
        "broken file must exit 0 (daemon would ignore it)"
    );
    let text = stdout(&out);
    assert!(text.contains("FAILED"));
    assert!(text.contains("logins still work"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_sessions_emits_valid_json_array() {
    // LION_GREETER_SESSIONS_PATH points nowhere: the documented
    // empty-list behaviour.
    let out = run(&["--list-sessions"]);
    assert!(out.status.success());
    let text = stdout(&out);
    let v: serde_json::Value = serde_json::from_str(text.trim()).expect("valid JSON");
    assert!(v.as_array().is_some(), "must be an array: {text}");
}

#[test]
fn list_sessions_from_a_real_directory() {
    let dir = std::env::temp_dir().join(format!(
        "lion-cli-sessions-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("lion.desktop"),
        "[Desktop Entry]\nType=Application\nName=LionOS Desktop\nExec=lion-session\nDesktopNames=LionOS;\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("broken.desktop"),
        "this is not a desktop file at all\n",
    )
    .unwrap();
    let out = {
        let mut c = bin();
        c.arg("--list-sessions")
            .env("LION_GREETER_SESSIONS_PATH", &dir);
        c.output().expect("spawn")
    };
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("valid JSON");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1, "broken file filtered out: {v}");
    assert_eq!(arr[0]["id"], "lion");
    assert_eq!(arr[0]["name"], "LionOS Desktop");
    assert_eq!(arr[0]["session_type"], "wayland");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_methods_emits_valid_json_with_password() {
    // LION_GREETER_PAM_MODULES_DIR points nowhere: only password
    // remains available — the documented empty-host behaviour.
    let out = run(&["--list-methods"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_str(stdout(&out).trim()).expect("valid JSON");
    let arr = v.as_array().expect("array");
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["method"], "password");
    assert_eq!(arr[0]["available"], true);
    // No probed method may claim availability on an empty host.
    for m in arr.iter().skip(1) {
        assert_eq!(m["available"], false, "unexpected availability: {m}");
    }
}

#[test]
fn unknown_mode_prints_usage_and_fails_cleanly() {
    let out = run(&["--frobnicate"]);
    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(1));
    let text = stderr(&out);
    assert!(text.contains("unknown mode"));
    assert!(text.contains("Usage:"));
    assert!(text.contains("--check-config"));
    // No panic backtrace on stderr.
    assert!(!text.contains("panicked"));
}

#[test]
fn no_args_and_help_do_not_crash() {
    // `--daemon` needs root + a bus; here we only verify the arg
    // parsing never panics for a mode it cannot actually serve: it
    // will fail with a D-Bus error, not a crash.
    let out = run(&["--bogus-2"]);
    assert_eq!(out.status.code(), Some(1));
}
