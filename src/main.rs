#![forbid(unsafe_code)]
//! Daemon entry point.
//!
//! The real backends (dlopen'd libpam, zbus logind, privileged launcher)
//! are feature-gated: `--no-default-features` builds a binary that
//! refuses to start rather than silently running on mocks (fail closed,
//! spec §8). The library itself remains fully testable with mocks.

use lion_greeter::cli::Cli;
use lion_greeter::config::{Config, SCHEMA_JSON};
use std::process::ExitCode;
#[cfg(all(feature = "real-pam", feature = "real-logind"))]
use std::sync::Arc;

#[cfg(all(feature = "real-pam", feature = "real-logind"))]
fn init_tracing(verbose: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let level = if verbose { "debug" } else { "info" };
        // component-tuned defaults: PAM backend is chatty at debug
        tracing_subscriber::EnvFilter::new(format!("{level},pam=info"))
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr) // the journal captures stderr
        .with_ansi(false) // no escapes in the journal
        .compact()
        .init();
}

fn main() -> ExitCode {
    let cli = Cli::default();
    if cli.help {
        print!("{}", Cli::usage());
        return ExitCode::SUCCESS;
    }
    if cli.version {
        println!("lion-greeter {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if cli.print_schema {
        println!("{SCHEMA_JSON}");
        return ExitCode::SUCCESS;
    }

    let path = cli.config_path();
    if cli.check_config {
        return match Config::load(&path) {
            Ok(cfg) => {
                // Also prove the PAM backend loads when the feature is on:
                // fail closed *before* the service claims readiness.
                #[cfg(feature = "real-pam")]
                match lion_greeter::pam::real::RealPamFactory::new() {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("error: {e}");
                        return ExitCode::FAILURE;
                    }
                }
                let n = cfg.greeter;
                println!(
                    "OK: {} (autologin={}, show_user_list={}, allow_guest={}, default_session={}, ui_user={}, socket={})",
                    path.display(),
                    n.autologin.user.as_deref().unwrap_or("<disabled>"),
                    n.show_user_list,
                    n.allow_guest,
                    n.default_session,
                    n.ui_user,
                    n.socket_path.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        };
    }

    #[cfg(not(all(feature = "real-pam", feature = "real-logind")))]
    {
        eprintln!(
            "error: this binary was built without the real backends \
             (real-pam, real-logind); a greeter must not run on mock auth"
        );
        return ExitCode::FAILURE;
    }

    #[cfg(all(feature = "real-pam", feature = "real-logind"))]
    {
        use lion_greeter::server::{run, DaemonDeps};
        init_tracing(cli.verbose);

        let cfg = match Config::load(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
        };

        // Fail closed on unavailable security-relevant backends (spec §8):
        // PAM must load before we accept a single connection.
        let pam: Arc<dyn lion_greeter::pam::PamServiceFactory> =
            match lion_greeter::pam::real::RealPamFactory::new() {
                Ok(f) => Arc::new(f),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
        let logind = Arc::new(lion_greeter::logind::RealLogind::new());
        let mounts: Arc<dyn lion_greeter::launch::Mounter> =
            Arc::new(lion_greeter::launch::RealMounter);
        let launcher = Arc::new(lion_greeter::launch::RealLauncher::new(
            logind.clone(),
            mounts,
            cfg.clone(),
        ));

        let server = lion_greeter::server::Server::new(
            cfg,
            DaemonDeps {
                pam,
                logind,
                launcher,
            },
        );

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("tokio runtime");

        return rt.block_on(async move {
            match run(server, path).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    tracing::error!(target: "boot", error = %e, "fatal error");
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        });
    }

    #[allow(unreachable_code)]
    ExitCode::FAILURE
}
