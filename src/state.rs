//! Tiny persisted state: which user logged in last, so the UI can
//! pre-select them and skip a click; which session (desktop) they
//! picked, so the gear menu defaults to what they actually use; and
//! when the last successful login happened, so the UI can show
//! "signed in 2 days ago" type hints.
//!
//! All writes are atomic (write-tmp + fsync + rename) and the files are
//! created with mode 0644 so the unprivileged `lion-login` UI can read
//! them without needing a database lookup every time the greeter starts.

use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn dir() -> PathBuf {
    std::env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/lion-greeter"))
}

fn last_user_path() -> PathBuf {
    dir().join("last-user")
}

fn last_session_path() -> PathBuf {
    dir().join("last-session")
}

/// Path of the last *chosen desktop session* ("lion", "gnome", …).
/// Distinct from `last-session` above, which is the login timestamp.
fn last_session_id_path() -> PathBuf {
    dir().join("last-session-id")
}

pub fn last_user() -> Option<String> {
    let s = fs::read_to_string(last_user_path()).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_owned())
}

/// Unix timestamp (seconds since epoch) of the last successful login,
/// or `None` if never recorded. Used for "logged in N days ago" hints.
#[allow(dead_code)] // exposed for future UI use; touch_last_session writes it
pub fn last_session_ts() -> Option<u64> {
    let s = fs::read_to_string(last_session_path()).ok()?;
    s.trim().parse::<u64>().ok()
}

/// The id of the session (desktop) chosen on the last successful
/// login, so the UI can pre-select it in the session list. The value
/// is re-validated by the caller against the installed sessions before
/// use, so a removed package degrades to the default instead of
/// breaking the next login. Implausible stored values are ignored —
/// the file is root-owned, but defense costs three lines.
pub fn last_session() -> Option<String> {
    let s = fs::read_to_string(last_session_id_path()).ok()?;
    let s = s.trim();
    let ok = !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    ok.then(|| s.to_owned())
}

/// Record the session chosen on a successful login (called by the IPC
/// layer). Best-effort: a state-dir failure degrades to "no memory",
/// never to a failed login.
pub fn set_last_session(id: &str) {
    if !id.is_empty() {
        let _ = atomic_write(&last_session_id_path(), id.as_bytes(), 0o644);
    }
}

/// Update the last-session timestamp to "now". Called by the IPC layer
/// on successful auth.
pub fn touch_last_session() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _ = atomic_write(&last_session_path(), now.to_string().as_bytes(), 0o644);
}

/// Atomic write (tmp + sync + rename) so a crash never leaves a torn file.
/// The new file is created with the requested mode; if the file already
/// exists, it is replaced (rename is atomic on the same filesystem).
fn atomic_write(path: &std::path::Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let res = (|| -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Best-effort: fsync the directory so the rename is durable too.
        if let Some(dir) = path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        fs::rename(&tmp, path)
    })();
    if let Err(ref e) = res {
        // Best-effort cleanup of the tmp file on failure.
        let _ = fs::remove_file(&tmp);
        tracing::warn!(error = %e, path = %path.display(), "could not persist state");
    }
    res.map(|_| ())
}

pub fn set_last_user(username: &str) {
    let _ = atomic_write(&last_user_path(), username.as_bytes(), 0o644);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_user_round_trip() {
        // Serializes with every other env-mutating test (see
        // `test_env_lock`): STATE_DIRECTORY is process-global.
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!(
            "lion-greeter-state-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("STATE_DIRECTORY", &dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(last_user().is_none());
        set_last_user("alice");
        assert_eq!(last_user().as_deref(), Some("alice"));

        // Overwrite.
        set_last_user("bob");
        assert_eq!(last_user().as_deref(), Some("bob"));

        // The empty string is treated as "no user".
        assert!(!matches!(last_user(), Some(s) if s.is_empty()));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_session_id_round_trip() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!(
            "lion-greeter-sessid-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("STATE_DIRECTORY", &dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(last_session().is_none());
        set_last_session("lion");
        assert_eq!(last_session().as_deref(), Some("lion"));

        // Overwrite.
        set_last_session("gnome");
        assert_eq!(last_session().as_deref(), Some("gnome"));

        // Empty is a no-op, not a reset to "".
        set_last_session("");
        assert_eq!(last_session().as_deref(), Some("gnome"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn implausible_session_ids_are_ignored_on_read() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!(
            "lion-greeter-sessid-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("STATE_DIRECTORY", &dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("last-session-id"), "../etc/passwd").unwrap();
        assert!(last_session().is_none(), "path traversal rejected");

        std::fs::write(dir.join("last-session-id"), "has space").unwrap();
        assert!(last_session().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_session_round_trip() {
        let _g = crate::test_env_lock();
        let dir = std::env::temp_dir().join(format!(
            "lion-greeter-session-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::env::set_var("STATE_DIRECTORY", &dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(last_session_ts().is_none());
        touch_last_session();
        let ts = last_session_ts().expect("timestamp written");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Allow for some scheduling skew.
        assert!(ts <= now && ts + 5 >= now, "ts={ts} now={now}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
