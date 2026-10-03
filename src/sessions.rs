#![forbid(unsafe_code)]
//! Session type detection and per-user last choice (spec 01 §3).
//!
//! The `lion` session (exec `lion-session`) is always offered and is the
//! default. Additionally every `*.desktop` file in
//! `/usr/share/wayland-sessions` is parsed (INI subset, bounded) and offered
//! when its `TryExec` (if any) resolves to an executable.
//!
//! The last chosen session per user is persisted in
//! `<state_dir>/last-session/<user>` (mode 0600, root-owned) — written only
//! after a successful launch, read at `ListSessions`/launch time. Reading
//! AccountsService `Session=` is handled in `crate::users`; this store is
//! the greeter's own (see DESIGN.md for the trade-off).

use crate::config::Config;
use crate::error::{Error, Result};
use crate::users::parse_keyfile;
use std::path::{Path, PathBuf};

/// Maximum entries ever enumerated.
const MAX_SESSIONS: usize = 64;
const MAX_DESKTOP_FILE: usize = 64 * 1024;

/// One installable session type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    /// Session id: file stem (or `lion` for the built-in).
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Exec line.
    pub exec: String,
    /// Whether this is the greeter's built-in Lion session.
    pub builtin: bool,
}

/// Registry of installable sessions.
pub struct SessionDb {
    builtin_id: String,
    builtin_exec: String,
    builtin_name: String,
    wayland_dir: PathBuf,
    state_dir: PathBuf,
}

impl SessionDb {
    pub fn new(cfg: &Config) -> Self {
        SessionDb {
            builtin_id: cfg.greeter.default_session.clone(),
            builtin_exec: "lion-session".into(),
            builtin_name: "Lion".into(),
            wayland_dir: cfg.greeter.wayland_sessions_dir.clone(),
            state_dir: cfg.greeter.state_dir.clone(),
        }
    }

    /// All installable sessions, built-in first, then desktop entries
    /// sorted by id, capped.
    pub fn list(&self) -> Result<Vec<SessionInfo>> {
        let mut out = vec![SessionInfo {
            id: self.builtin_id.clone(),
            name: self.builtin_name.clone(),
            exec: self.builtin_exec.clone(),
            builtin: true,
        }];
        let mut dir_entries: Vec<String> = std::fs::read_dir(&self.wayland_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".desktop"))
                    .collect()
            })
            .unwrap_or_default();
        dir_entries.sort();
        for name in dir_entries {
            if out.len() >= MAX_SESSIONS {
                break;
            }
            if let Some(s) = self.parse_desktop(&self.wayland_dir.join(&name)) {
                // A desktop file may override the built-in by id; keep the
                // file version (it is the same "lion" session, richer).
                out.retain(|x| x.id != s.id);
                out.push(s);
            }
        }
        Ok(out)
    }

    fn parse_desktop(&self, path: &Path) -> Option<SessionInfo> {
        let text = std::fs::read_to_string(path).ok()?;
        if text.len() > MAX_DESKTOP_FILE {
            return None;
        }
        let kv = parse_keyfile(&text, 64);
        let get = |k: &str| {
            kv.get(&("Desktop Entry".to_string(), k.to_string()))
                .cloned()
        };
        let exec = get("Exec")?;
        if exec.is_empty() || exec.len() > 512 {
            return None;
        }
        let id = path.file_stem()?.to_str()?.to_string();
        if id.is_empty() || id.len() > 64 {
            return None;
        }
        if let Some(tryexec) = get("TryExec").filter(|t| !t.is_empty()) {
            if !self.is_executable(&tryexec) {
                return None; // fail closed: not actually installed
            }
        }
        if get("Hidden").as_deref() == Some("true") {
            return None;
        }
        if get("NoDisplay").as_deref() == Some("true") {
            return None;
        }
        let name = get("Name")
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| id.clone());
        Some(SessionInfo {
            id,
            name: crate::proto::sanitize_text(&name, 128),
            exec: crate::proto::sanitize_text(&exec, 512),
            builtin: false,
        })
    }

    fn is_executable(&self, candidate: &str) -> bool {
        let p = Path::new(candidate);
        if p.is_absolute() {
            return p.is_file();
        }
        let path_env = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin".into());
        std::env::split_paths(&path_env).any(|dir| dir.join(candidate).is_file())
    }

    /// Look up one session id.
    pub fn find(&self, id: &str) -> Result<Option<SessionInfo>> {
        Ok(self.list()?.into_iter().find(|s| s.id == id))
    }

    /// Effective session for a user: explicit id, else last choice, else
    /// default. Errors if an explicit id is not installed (fail closed).
    pub fn resolve_for_user(&self, id: Option<&str>, user: &str) -> Result<String> {
        if let Some(id) = id.filter(|s| !s.is_empty()) {
            if self.find(id)?.is_none() {
                return Err(Error::Protocol(format!("unknown session {id:?}")));
            }
            return Ok(id.to_string());
        }
        if let Some(last) = self.last_session(user) {
            if self.find(&last)?.is_some() {
                return Ok(last);
            }
        }
        Ok(self.builtin_id.clone())
    }

    /// Read the user's remembered last session id.
    pub fn last_session(&self, user: &str) -> Option<String> {
        if !valid_user_component(user) {
            return None;
        }
        let s = std::fs::read_to_string(self.state_dir.join("last-session").join(user)).ok()?;
        let s = s.trim();
        if s.is_empty() || s.len() > 64 {
            return None;
        }
        Some(s.to_string())
    }

    /// Remember the user's last session (called after a successful launch).
    /// Best-effort: failures are logged by the caller, never fatal.
    pub fn set_last_session(&self, user: &str, session: &str) -> std::io::Result<()> {
        if !valid_user_component(user) || !valid_user_component(session) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid user or session name",
            ));
        }
        let dir = self.state_dir.join("last-session");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(user), session)
    }
}

/// The username is used as a path component — strictly bound charset.
fn valid_user_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !s.starts_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(dir: &Path) -> (Config, SessionDb) {
        let mut cfg = Config::default();
        cfg.greeter.wayland_sessions_dir = dir.join("wayland-sessions");
        cfg.greeter.state_dir = dir.join("state");
        let db = SessionDb::new(&cfg);
        (cfg, db)
    }

    fn write_session(dir: &Path, file: &str, body: &str) {
        let d = dir.join("wayland-sessions");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(file), body).unwrap();
    }

    #[test]
    fn builtin_lion_always_listed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, db) = setup(dir.path());
        let list = db.list().unwrap();
        assert_eq!(list[0].id, "lion");
        assert!(list[0].builtin);
        assert_eq!(list[0].exec, "lion-session");
    }

    #[test]
    fn parses_desktop_entries() {
        let dir = tempfile::tempdir().unwrap();
        write_session(
            dir.path(),
            "sway.desktop",
            "[Desktop Entry]\nName=Sway\nExec=sway\nType=Application\n",
        );
        let (_, db) = setup(dir.path());
        let list = db.list().unwrap();
        assert_eq!(list.len(), 2);
        let sway = list.iter().find(|s| s.id == "sway").unwrap();
        assert_eq!(
            (sway.name.as_str(), sway.exec.as_str(), sway.builtin),
            ("Sway", "sway", false)
        );
    }

    #[test]
    fn tryexec_missing_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        write_session(
            dir.path(),
            "gone.desktop",
            "[Desktop Entry]\nName=Gone\nExec=gone-wm\nTryExec=/nonexistent/gone-wm\n",
        );
        let (_, db) = setup(dir.path());
        assert!(db.list().unwrap().iter().all(|s| s.id != "gone"));
    }

    #[test]
    fn hidden_and_nodisplay_filtered() {
        let dir = tempfile::tempdir().unwrap();
        write_session(
            dir.path(),
            "h.desktop",
            "[Desktop Entry]\nName=H\nExec=h\nHidden=true\n",
        );
        write_session(
            dir.path(),
            "n.desktop",
            "[Desktop Entry]\nName=N\nExec=n\nNoDisplay=true\n",
        );
        let (_, db) = setup(dir.path());
        let list = db.list().unwrap();
        let ids: Vec<&str> = list.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["lion"]);
    }

    #[test]
    fn last_session_roundtrip_and_resolution() {
        let dir = tempfile::tempdir().unwrap();
        write_session(
            dir.path(),
            "sway.desktop",
            "[Desktop Entry]\nName=Sway\nExec=sway\n",
        );
        let (_, db) = setup(dir.path());
        assert!(db.last_session("alice").is_none());
        db.set_last_session("alice", "sway").unwrap();
        assert_eq!(db.last_session("alice").as_deref(), Some("sway"));
        // resolve: no explicit id → last choice
        assert_eq!(db.resolve_for_user(None, "alice").unwrap(), "sway");
        // explicit unknown id → error
        assert!(db.resolve_for_user(Some("nope"), "alice").is_err());
        // no last choice → default
        assert_eq!(db.resolve_for_user(None, "bob").unwrap(), "lion");
    }

    #[test]
    fn path_traversal_user_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (_, db) = setup(dir.path());
        assert!(db.set_last_session("../evil", "lion").is_err());
        assert!(db.last_session("../../etc/passwd").is_none());
        assert!(db.set_last_session("ok-user", ".hidden").is_err());
    }

    #[test]
    fn overrides_builtin_by_id() {
        let dir = tempfile::tempdir().unwrap();
        write_session(
            dir.path(),
            "lion.desktop",
            "[Desktop Entry]\nName=Lion (wayland-session)\nExec=lion-session-wrapper\n",
        );
        let (_, db) = setup(dir.path());
        let list = db.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].exec, "lion-session-wrapper");
        assert!(!list[0].builtin);
    }
}
