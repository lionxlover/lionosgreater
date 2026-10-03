#![forbid(unsafe_code)]
//! Unified error type for `lion-greeter`.
//!
//! Error strings are treated as untrusted-ish surface area: they must never
//! contain secret material (passwords, answers) — see `crate::secret`. The
//! [`Error`] enum keeps variants data-only so the display layer can produce
//! stable, generic, user-facing messages.

use std::fmt;

/// Top-level error for the greeter daemon and library.
#[derive(Debug)]
pub enum Error {
    /// Configuration could not be loaded or failed validation (fail closed).
    Config(String),
    /// An I/O error with context.
    Io(String, std::io::Error),
    /// The PAM backend failed before/at authentication start.
    Pam(String),
    /// The logind (D-Bus) backend failed.
    Logind(String),
    /// The session launcher failed (fork/exec/privilege step).
    Launch(String),
    /// Protocol-level error (bad frame, bad version, unknown op).
    Protocol(String),
    /// Request denied by policy (throttle, permissions, not authenticated).
    Denied(String),
    /// Anything else.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "config error: {m}"),
            Error::Io(ctx, e) => write!(f, "io error ({ctx}): {e}"),
            Error::Pam(m) => write!(f, "pam error: {m}"),
            Error::Logind(m) => write!(f, "logind error: {m}"),
            Error::Launch(m) => write!(f, "launch error: {m}"),
            Error::Protocol(m) => write!(f, "protocol error: {m}"),
            Error::Denied(m) => write!(f, "denied: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io("unspecified".into(), e)
    }
}

/// Convenience result alias.
pub type Result<T> = std::result::Result<T, Error>;
