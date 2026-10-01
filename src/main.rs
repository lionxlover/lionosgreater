//! lion-greeter binary: CLI modes + daemon bootstrap.
//!
//! All actual logic lives in the `lion_greeter` library (see
//! `src/lib.rs`); this file only parses arguments, builds the runtime,
//! and dispatches to the library. The modes:
//!
//! * (no args / `--daemon` / `--serve`) — run the long-lived D-Bus
//!   service
//! * `--version` — version + build info
//! * `--list-users` — print local-user JSON (install smoke tests)
//! * `--list-sessions` — print installed XDG sessions (0.6.0)
//! * `--list-methods` — print available auth methods (0.6.0)
//! * `--check-pam` — probe the PAM stack
//! * `--check-config` — parse greeter.toml and print the result

use anyhow::Result;
use lion_greeter::{auth, config, ipc, methods, mlock, pam_ffi, sessions, users_enum};
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    install_panic_hook();

    // Parse args manually — a 30-line arg parser is fine for a daemon
    // that only knows a handful of modes, and avoids a `clap`/`lexopt`
    // dep (and the ~100 KB of binary size that would add).
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("--daemon");

    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("lion-greeter: could not build runtime: {e}");
            return ExitCode::from(1);
        }
    };

    let result = runtime.block_on(async move {
        match mode {
            "--daemon" | "--serve" | "" => run_daemon().await,
            "--version" => {
                println!(
                    "lion-greeter {} (LionOS login daemon)\n\
                     Edition 2021, MSRV rustc {}\n\
                     PAM service: lion-greeter (interactive, conversation-forwarding)\n\
                     PAM service: lion-greeter-autologin (passwordless)\n\
                     Session binary: /usr/bin/lion-session\n\
                     Features: 2FA/smartcard conversation relay, autologin,\n\
                                XDG session selection, fast user switching\n\
                                (logind seats), auth-method probing, mlockall\n\
                                secret pinning, per-user throttle, metrics",
                    env!("CARGO_PKG_VERSION"),
                    env!("CARGO_PKG_RUST_VERSION"),
                );
                Ok(())
            }
            "--list-users" => {
                let users = users_enum::enumerate_users_cached();
                let json = serde_json::to_string_pretty(&users).unwrap_or_else(|_| "[]".into());
                println!("{json}");
                Ok(())
            }
            "--list-sessions" => {
                let list = sessions::enumerate();
                let json = serde_json::to_string_pretty(&list).unwrap_or_else(|_| "[]".into());
                println!("{json}");
                Ok(())
            }
            "--list-methods" => {
                // Without the daemon's bus connection the live fprintd
                // probe is unavailable; module presence is the
                // install-time answer and the daemon refines it.
                let list = methods::auth_methods(false);
                let json = serde_json::to_string_pretty(&list).unwrap_or_else(|_| "[]".into());
                println!("{json}");
                Ok(())
            }
            "--check-pam" => check_pam().await,
            "--check-config" => check_config(),
            other => {
                eprintln!("lion-greeter: unknown mode `{other}`");
                eprintln!(
                    "Usage:\n  \
                     lion-greeter [--daemon]       Run the long-lived D-Bus service (default)\n  \
                     lion-greeter --version        Print version info and exit\n  \
                     lion-greeter --list-users     Print local-user JSON and exit\n  \
                     lion-greeter --list-sessions  Print installed sessions JSON and exit\n  \
                     lion-greeter --list-methods   Print auth-method availability JSON and exit\n  \
                     lion-greeter --check-pam      Probe the PAM stack and exit\n  \
                     lion-greeter --check-config   Parse greeter.toml and print it"
                );
                Err(anyhow::anyhow!("unknown mode"))
            }
        }
    });

    match result {
        Ok(()) => ExitCode::from(0),
        Err(e) => {
            eprintln!("lion-greeter: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Build the tokio runtime with parameters appropriate for a login
/// daemon: few worker threads (no parallel auth, no parallel D-Bus
/// calls worth mentioning), a small blocking pool (at most two
/// `spawn_blocking`s in flight at any time: ListUsers + find_eligible).
///
/// Keeping the runtime small has two benefits:
/// 1. Each worker thread costs ~8 MB of virtual address space for its
///    stack guard + ~2 MB RSS for the stack itself. On a low-RAM first-
///    boot device, defaulting to `num_cpus()` workers (16 on a typical
///    desktop) is wasteful for a daemon whose entire job is to handle
///    one login at a time.
/// 2. Fewer threads = fewer context switches during idle, which is the
///    dominant state for a greeter that's never on screen for long.
fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .thread_name("lion-greeter-rt")
        // The login worker spawns its OWN std::thread outside tokio —
        // we don't need time or signal drivers, but enabling them is
        // cheap and we do use them (signal::unix, tokio::time::sleep).
        .enable_all()
        .build()
        .map_err(Into::into)
}

async fn run_daemon() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lion_greeter=info".into()),
        )
        .init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "lion-greeter starting");

    // Pin secrets into RAM before the runtime grows the heap (see
    // mlock.rs for the RLIMIT-safe, never-fatal design). Skipped or
    // failed locks are logged and reported through Capabilities.
    let cfg = config::Config::load();
    if cfg.security.mlock {
        let outcome = mlock::apply();
        tracing::info!(outcome = outcome.tag(), "memory lock phase complete");
    } else {
        tracing::info!("mlock disabled by [security] mlock=false");
    }

    let _conn = ipc::serve().await?;

    // Run until systemd asks us to stop. SIGTERM (systemd's default) gets
    // the cleaner shutdown path; SIGINT (Ctrl-C) is supported for dev runs.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    tracing::info!("shutting down");
    Ok(())
}

/// Probe the PAM stack so a sysadmin can verify (post-install or after
/// a config edit) that `lion-greeter` can load the `lion-greeter` PAM
/// service and that none of the modules in the stack are broken.
///
/// We do this by calling `pam_start` with a sentinel user and immediately
/// `pam_end`. No `pam_authenticate` is called — this exercises only the
/// module load + init path, not any account checks. The password is
/// blank; no real authentication is attempted.
async fn check_pam() -> Result<()> {
    let probe = "lion-greeter-probe";
    let pw = zeroize::Zeroizing::new(String::new());
    match pam_ffi::PamContext::start(auth::pam_service(), probe, pw) {
        Ok(_ctx) => {
            // Context drops immediately, calling pam_end(PAM_SUCCESS).
            // If the modules' init hooks ran without panic, the stack is
            // loadable. The actual account probe is best done with a
            // real user, but that requires root + a password.
            println!("PAM service `{}` loads cleanly", auth::pam_service());
            Ok(())
        }
        Err(code) => {
            eprintln!(
                "PAM service `{}` failed to start (code {code}).\n\
                 Check /etc/pam.d/lion-greeter and the modules it includes.",
                auth::pam_service()
            );
            Err(anyhow::anyhow!("PAM probe failed (code {code})"))
        }
    }
}

/// Parse the configuration file and print the effective result — the
/// fastest way for an operator (or an install script) to verify that
/// `/etc/lionos/greeter.toml` means what they think it means. Prints
/// the exact path consulted and whether the file parsed. Exits 0 even
/// when the file is broken (the daemon would ignore it too); the
/// output text makes the problem obvious without failing a boot.
fn check_config() -> Result<()> {
    let path = config::Config::path();
    let cfg = config::Config::load();
    println!("config path : {}", path.display());
    println!(
        "autologin   : user={} delay_ms={} relogin={}",
        cfg.autologin.user.as_deref().unwrap_or("(disabled)"),
        cfg.autologin.delay_ms,
        cfg.autologin.relogin
    );
    println!(
        "session     : default={}",
        cfg.session.default.as_deref().unwrap_or("(last-used)")
    );
    println!("security    : mlock={}", cfg.security.mlock);
    match std::fs::read_to_string(&path) {
        Ok(text) => match config::parse(&text) {
            Ok(_) => {
                println!("parse       : ok ({} lines)", text.lines().count());
                println!("status      : file applied in full");
            }
            Err(line) => {
                println!("parse       : FAILED at line {line} — file ignored, defaults in effect");
                println!("status      : logins still work; fix the file at leisure");
            }
        },
        Err(e) => {
            println!("parse       : no file ({e}) — defaults in effect");
        }
    }
    Ok(())
}

/// Replace the default panic hook so panics go through `tracing` with
/// location, payload and a (truncated) backtrace, instead of writing
/// directly to stderr (which on a greeter is the journal and is fine,
/// but tracing gives us structured fields + redaction control).
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".into());
        let payload = info.payload();
        let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_owned()
        };
        // Use stderr directly because the tracing subscriber may not
        // be initialised yet (e.g. if we panic during init). The journal
        // will pick this up via stderr.
        let _ = writeln!(std::io::stderr(), "lion-greeter panic at {loc}: {msg}");
        tracing::error!(panic.location = %loc, panic.message = %msg, "panic");
    }));
}
