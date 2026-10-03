//! `lion-greeter` — LionOS login backend (spec 01).
//!
//! Owns user enumeration, PAM authentication and session launch. It never
//! draws anything; `lion-login-ui` does. See `DESIGN.md` for decisions
//! and `docs/PROTOCOL.md` for the wire protocol.
//!
//! Unsafe policy (spec 01 §8): every module file carries its own
//! `#![forbid(unsafe_code)]` EXCEPT the two audited FFI modules —
//! `pam::sys` (dlopen'd libpam) and `sysffi` (libc syscall wrappers),
//! which are `#![allow(unsafe_code)]` with a documented audit contract.
//! (A crate-level forbid would forbid unsafe in the FFI leaves too,
//! which is not what the spec asks for.)

pub mod auth;
pub mod cli;
pub mod codec;
pub mod config;
pub mod error;
pub mod launch;
pub mod logind;
pub mod notify;
pub mod pam;
pub mod proto;
pub mod secret;
pub mod server;
pub mod sessions;
pub mod sysffi;
pub mod throttle;
pub mod users;

pub use config::Config;
pub use error::{Error, Result};
pub use server::{run, DaemonDeps, Server};
