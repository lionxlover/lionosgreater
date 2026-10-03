#![forbid(unsafe_code)]
//! Command line surface (spec 01 §9): `--version`, `--check-config`,
//! `--print-schema`, plus `--config` and `--verbose` for operation.

use crate::config::DEFAULT_CONFIG_PATH;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Cli {
    pub config: Option<PathBuf>,
    pub check_config: bool,
    pub print_schema: bool,
    pub version: bool,
    pub verbose: bool,
    pub help: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli::from_args(std::env::args().skip(1)).unwrap_or_default()
    }
}

impl Cli {
    /// Parse args; unknown flags produce a help request rather than an
    /// error exit so the usage text is always reachable.
    pub fn from_args<I: Iterator<Item = String>>(args: I) -> Option<Cli> {
        let mut cli = Cli {
            config: None,
            check_config: false,
            print_schema: false,
            version: false,
            verbose: false,
            help: false,
        };
        let mut it = args.peekable();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--version" | "-V" => cli.version = true,
                "--check-config" => cli.check_config = true,
                "--print-schema" => cli.print_schema = true,
                "--verbose" | "-v" => cli.verbose = true,
                "--help" | "-h" => cli.help = true,
                "--config" | "-c" => match it.next() {
                    Some(p) => cli.config = Some(PathBuf::from(p)),
                    None => cli.help = true,
                },
                _ => {
                    // `--config=path` form
                    if let Some(p) = a.strip_prefix("--config=") {
                        cli.config = Some(PathBuf::from(p));
                    } else {
                        cli.help = true;
                    }
                }
            }
        }
        Some(cli)
    }

    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .or_else(|| std::env::var_os("LION_GREETER_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    pub fn usage() -> String {
        format!(
            "lion-greeter {} — LionOS login backend (spec 01)

USAGE:
    lion-greeter [OPTIONS]

OPTIONS:
    -c, --config <PATH>   Configuration file [default: {}]
        --check-config    Validate the configuration and exit
        --print-schema    Print the lion-config JSON schema and exit
    -V, --version         Print version and exit
    -v, --verbose         Verbose (debug) logging
    -h, --help            This help

The daemon speaks a JSON-lines protocol on its UI socket (see
docs/PROTOCOL.md); the UI is a separate component (lion-login-ui).
",
            env!("CARGO_PKG_VERSION"),
            DEFAULT_CONFIG_PATH
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::from_args(args.iter().map(|s| s.to_string())).unwrap()
    }

    #[test]
    fn parses_all_flags() {
        let c = parse(&["--config", "/tmp/a.json", "--check-config", "--verbose"]);
        assert_eq!(c.config_path(), PathBuf::from("/tmp/a.json"));
        assert!(c.check_config && c.verbose);
        let c = parse(&["--config=/tmp/b.json"]);
        assert_eq!(c.config_path(), PathBuf::from("/tmp/b.json"));
        let c = parse(&["--version"]);
        assert!(c.version);
    }

    #[test]
    fn unknown_flag_falls_back_to_help() {
        let c = parse(&["--frobnicate"]);
        assert!(c.help);
    }
}
