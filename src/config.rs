#![forbid(unsafe_code)]
//! Configuration loading and validation (the `lion-config` client).
//!
//! In the LionOS workspace this module is backed by the `lion-config` crate;
//! in this standalone build it reads the same `greeter.*` key tree from a
//! JSON keyfile (default `/etc/lion/greeter.json`). The JSON Schema shipped
//! at `packaging/lion-config/greeter.schema.json` is the canonical schema
//! (`--print-schema`); the loader mirrors it with strict, unknown-field
//! rejection (fail closed on anything unexpected).
//!
//! Spec 01 §5 keys: `greeter.autologin.user`, `greeter.show_user_list`,
//! `greeter.allow_guest`, `greeter.default_session` — plus documented,
//! namespaced extensions for the v1-partial milestone (timed login, guest,
//! throttle, socket path, PAM service, uid range, paths).

use crate::error::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Canonical schema, embedded so `--print-schema` never depends on the
/// installation having the packaging tree present.
pub const SCHEMA_JSON: &str = include_str!("../packaging/lion-config/greeter.schema.json");

pub const DEFAULT_CONFIG_PATH: &str = "/etc/lion/greeter.json";

/// `greeter.autologin`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutologinConfig {
    /// User to log in automatically; `None` disables autologin (default).
    #[serde(default)]
    pub user: Option<String>,
    /// Session id to launch; falls back to last choice / default.
    #[serde(default)]
    pub session: Option<String>,
    /// PAM service used for the passwordless transaction.
    #[serde(default = "default_autologin_service")]
    pub service: String,
}

impl Default for AutologinConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_autologin_service() -> String {
    "lion-greeter-autologin".into()
}

/// `greeter.timed_login`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimedLoginConfig {
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_timed_delay")]
    pub delay_seconds: u64,
}

impl Default for TimedLoginConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_timed_delay() -> u64 {
    30
}

/// `greeter.guest`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestConfig {
    #[serde(default = "default_guest_user")]
    pub user: String,
    #[serde(default = "default_guest_home")]
    pub home: String,
    #[serde(default = "default_guest_size")]
    pub tmpfs_size: String,
}

impl Default for GuestConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_guest_user() -> String {
    "lion-guest".into()
}
fn default_guest_home() -> String {
    "/tmp/lion-guest".into()
}
fn default_guest_size() -> String {
    "64m".into()
}

/// `greeter.pam`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PamConfig {
    #[serde(default = "default_pam_service")]
    pub service: String,
    #[serde(default = "default_pam_timeout")]
    pub timeout_seconds: u64,
}

impl Default for PamConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_pam_service() -> String {
    "lion-greeter".into()
}
fn default_pam_timeout() -> u64 {
    30
}

/// `greeter.throttle`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_throttle_cap")]
    pub cap_seconds: u64,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_throttle_cap() -> u64 {
    60
}
fn default_true() -> bool {
    true
}

/// `greeter.power`
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PowerConfig {
    #[serde(default = "default_power_allowed")]
    pub allowed: Vec<String>,
}

impl Default for PowerConfig {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_power_allowed() -> Vec<String> {
    vec!["reboot".into(), "poweroff".into(), "suspend".into()]
}

/// Root config: the `greeter` object.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub greeter: GreeterSection,
}

impl Default for Config {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

/// The `greeter.*` tree.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GreeterSection {
    #[serde(default)]
    pub autologin: AutologinConfig,
    #[serde(default)]
    pub timed_login: TimedLoginConfig,
    #[serde(default = "default_true")]
    pub show_user_list: bool,
    #[serde(default)]
    pub allow_guest: bool,
    #[serde(default)]
    pub guest: GuestConfig,
    #[serde(default = "default_session")]
    pub default_session: String,
    #[serde(default = "default_ui_user")]
    pub ui_user: String,
    #[serde(default)]
    pub ui_uid: Option<u32>,
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    #[serde(default)]
    pub pam: PamConfig,
    #[serde(default)]
    pub throttle: ThrottleConfig,
    #[serde(default = "default_min_uid")]
    pub min_uid: u32,
    #[serde(default = "default_max_uid")]
    pub max_uid: u32,
    #[serde(default = "default_wayland_sessions_dir")]
    pub wayland_sessions_dir: PathBuf,
    #[serde(default = "default_accountsservice_dir")]
    pub accountsservice_dir: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    /// User database source (text passwd). Configurable so nspawn fixtures
    /// and tests can use synthetic files.
    #[serde(default = "default_passwd_path")]
    pub passwd_path: PathBuf,
    /// Group database source (supplementary groups at launch).
    #[serde(default = "default_group_path")]
    pub group_path: PathBuf,
    #[serde(default = "default_seat")]
    pub seat: String,
    #[serde(default)]
    pub power: PowerConfig,
}

impl Default for GreeterSection {
    fn default() -> Self {
        serde_json::from_str("{}").expect("static defaults parse")
    }
}

fn default_session() -> String {
    "lion".into()
}
fn default_ui_user() -> String {
    "lion-greeter".into()
}
fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/lion-greeter/ui.sock")
}
fn default_min_uid() -> u32 {
    1000
}
fn default_max_uid() -> u32 {
    60000
}
fn default_wayland_sessions_dir() -> PathBuf {
    PathBuf::from("/usr/share/wayland-sessions")
}
fn default_accountsservice_dir() -> PathBuf {
    PathBuf::from("/var/lib/AccountsService")
}
fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/lion-greeter")
}
fn default_passwd_path() -> PathBuf {
    PathBuf::from("/etc/passwd")
}
fn default_group_path() -> PathBuf {
    PathBuf::from("/etc/group")
}
fn default_seat() -> String {
    "seat0".into()
}

impl Config {
    /// Load from a JSON file. Unknown keys, wrong types, or out-of-range
    /// values are hard errors (fail closed, spec §8).
    pub fn load(path: &Path) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("cannot read {}: {e}", path.display())))?;
        let cfg: Config = serde_json::from_str(&raw)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Semantic validation beyond shape (ranges, cross-field rules).
    pub fn validate(&self) -> Result<()> {
        let g = &self.greeter;
        if g.min_uid < 500 {
            return Err(Error::Config(format!(
                "greeter.min_uid ({}) is below the safe system-account floor (500)",
                g.min_uid
            )));
        }
        if g.max_uid <= g.min_uid || g.max_uid > 65535 {
            return Err(Error::Config(format!(
                "greeter.max_uid ({}) must be > min_uid ({}) and <= 65535",
                g.max_uid, g.min_uid
            )));
        }
        if g.pam.timeout_seconds < 1 || g.pam.timeout_seconds > 600 {
            return Err(Error::Config(
                "greeter.pam.timeout_seconds must be 1..=600".into(),
            ));
        }
        if g.timed_login.delay_seconds < 1 || g.timed_login.delay_seconds > 3600 {
            return Err(Error::Config(
                "greeter.timed_login.delay_seconds must be 1..=3600".into(),
            ));
        }
        for p in &g.power.allowed {
            if !matches!(p.as_str(), "reboot" | "poweroff" | "suspend") {
                return Err(Error::Config(format!(
                    "greeter.power.allowed: unknown action {p:?}"
                )));
            }
        }
        if g.guest.tmpfs_size.is_empty()
            || !g
                .guest
                .tmpfs_size
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
        {
            return Err(Error::Config(
                "greeter.guest.tmpfs_size must be alphanumeric (e.g. \"64m\")".into(),
            ));
        }
        if g.socket_path.as_os_str().is_empty() {
            return Err(Error::Config(
                "greeter.socket_path must not be empty".into(),
            ));
        }
        Ok(())
    }

    /// PAM conversation step timeout (spec §6: 30 s hard timeout).
    pub fn conv_timeout(&self) -> Duration {
        Duration::from_secs(self.greeter.pam.timeout_seconds)
    }

    /// Effective uid allowed to connect to the UI socket, resolved either
    /// from `ui_uid` (explicit) or later from `ui_user` (see `users`).
    pub fn ui_uid(&self) -> Option<u32> {
        self.greeter.ui_uid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn defaults_parse_and_validate() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.greeter.show_user_list);
        assert!(!c.greeter.allow_guest);
        assert_eq!(c.greeter.default_session, "lion");
        assert!(c.greeter.autologin.user.is_none());
        assert_eq!(c.conv_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn unknown_keys_rejected() {
        let dir = tmp();
        let p = dir.path().join("c.json");
        std::fs::write(&p, r#"{"greeter":{"shoe_size":44}}"#).unwrap();
        assert!(Config::load(&p).is_err());
    }

    #[test]
    fn spec_keys_roundtrip() {
        let dir = tmp();
        let p = dir.path().join("c.json");
        std::fs::write(
            &p,
            r#"{"greeter":{"autologin":{"user":"alice"},"show_user_list":false,
                "allow_guest":true,"default_session":"lion-wayland"}}"#,
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.greeter.autologin.user.as_deref(), Some("alice"));
        assert!(!c.greeter.show_user_list);
        assert!(c.greeter.allow_guest);
        assert_eq!(c.greeter.default_session, "lion-wayland");
    }

    #[test]
    fn range_validation() {
        let mut c = Config::default();
        c.greeter.min_uid = 1;
        assert!(c.validate().is_err());
        let mut c = Config::default();
        c.greeter.max_uid = 999;
        assert!(c.validate().is_err());
        let mut c = Config::default();
        c.greeter.power.allowed = vec!["halt".into()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn schema_is_valid_json() {
        let v: serde_json::Value = serde_json::from_str(SCHEMA_JSON).unwrap();
        assert!(v["title"].as_str().unwrap().contains("Lion Greeter"));
    }
}
