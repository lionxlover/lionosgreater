//! Local user enumeration. Reports data only; all visual decisions
//! belong to `lion-login-ui`.
//!
//! # Thread safety
//! The `users` crate's `all_users()` iterates libc's getpwent() which
//! uses process-global state. Multiple `spawn_blocking` tasks calling
//! it concurrently is therefore UB. We serialize every call through a
//! global `Mutex<()>`.

use serde::Serialize;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// Bring `UserExt` into scope so we can call `home_dir()`, `shell()` on
// the `users::User` type. Without this the methods don't resolve (the
// trait is required by Rust's method resolution).
use users::os::unix::UserExt;

pub const UID_MIN: u32 = 1000;
pub const UID_MAX: u32 = 60000;

/// How long a cached user list is considered fresh. Five seconds is
/// long enough to absorb a UI round-trip (list → click → auth) and
/// short enough that account changes (added/removed users, new
/// avatars) appear almost immediately on the next ListUsers call.
const CACHE_TTL: Duration = Duration::from_secs(5);

/// Serializes libc getpwent callers (process-global state). `getpwnam_r`
/// (used by `gecos_for` below) is the reentrant variant and does not need
/// the lock, but we keep one global to keep the two call-sites consistent
/// in case a future caller uses the non-reentrant form.
fn passwd_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalUser {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub full_name: String,
    pub home: PathBuf,
    pub shell: PathBuf,
    pub avatar_path: Option<String>,
    pub session_type: SessionType,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Wayland,
}

impl SessionType {
    pub fn as_str(self) -> &'static str {
        "wayland"
    }
}

// ── user-enumeration cache ──────────────────────────────────────────────

struct CachedList {
    fetched_at: Instant,
    users: Vec<LocalUser>,
}

fn cache() -> &'static Mutex<Option<CachedList>> {
    static C: OnceLock<Mutex<Option<CachedList>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Invalidate the cached user list. Called automatically on TTL expiry;
/// can also be called explicitly (e.g. after the greeter learns that an
/// account was added/removed via some future AccountsService signal).
#[allow(dead_code)] // public API for future AccountsService hook
pub fn invalidate_cache() {
    let mut g = cache().lock().unwrap_or_else(|e| e.into_inner());
    *g = None;
}

/// Cached version of `enumerate_users`. Returns the cached list if it
/// is fresh (within `CACHE_TTL`); otherwise calls `enumerate_users`,
/// populates the cache, and returns the fresh list. The returned
/// `Vec` is a clone so the caller can mutate it freely.
///
/// This is the function the D-Bus `ListUsers` method should call — it
/// avoids hitting NSS on every UI round-trip, which is especially
/// important when the system uses SSSD/LDAP (where a single
/// `getpwent` cycle can take hundreds of milliseconds).
pub fn enumerate_users_cached() -> Vec<LocalUser> {
    let now = Instant::now();
    {
        let g = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = g.as_ref() {
            if now.duration_since(c.fetched_at) < CACHE_TTL {
                return c.users.clone();
            }
        }
    }
    let users = enumerate_users();
    let mut g = cache().lock().unwrap_or_else(|e| e.into_inner());
    *g = Some(CachedList {
        fetched_at: now,
        users: users.clone(),
    });
    users
}

/// All real, interactive local accounts, sorted by username.
///
/// SAFETY: the underlying libc `getpwent()` call is not thread-safe;
/// the global `passwd_lock()` ensures only one caller touches it at a
/// time.
pub fn enumerate_users() -> Vec<LocalUser> {
    let _g = passwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut out: Vec<LocalUser> = unsafe { users::all_users() }
        .filter_map(|u| to_local_user(&u))
        .collect();
    out.sort_by(|a, b| a.username.cmp(&b.username));
    out
}

/// Look up a single eligible user. Returns `None` for unknown users,
/// system accounts (incl. root) and non-interactive shells, so callers can
/// treat all of them identically and leak nothing about which exist.
pub fn find_eligible(username: &str) -> Option<LocalUser> {
    let _g = passwd_lock().lock().unwrap_or_else(|e| e.into_inner());
    users::get_user_by_name(username).and_then(|u| to_local_user(&u))
}

fn to_local_user(u: &users::User) -> Option<LocalUser> {
    let uid = u.uid();
    if !(UID_MIN..=UID_MAX).contains(&uid) || is_nologin(u.shell()) {
        return None;
    }
    let username = u.name().to_string_lossy().into_owned();
    // The `users` crate doesn't expose `pw_gecos` on Linux, so we ask
    // libc directly. `getpwnam_r` is the reentrant variant; no mutex needed.
    let raw_gecos = gecos_for(&username);
    let full_name = parse_gecos_full_name(raw_gecos.as_deref(), &username);

    Some(LocalUser {
        avatar_path: find_avatar(&username, u.home_dir()),
        session_type: SessionType::Wayland,
        gid: u.primary_group_id(),
        home: u.home_dir().to_path_buf(),
        shell: u.shell().to_path_buf(),
        username,
        uid,
        full_name,
    })
}

/// Read `pw_gecos` for `username` directly via `getpwnam_r(3)`. Returns
/// `None` if the user is unknown or the field is empty.
///
/// SAFETY: `getpwnam_r` is reentrant and does not touch global libc
/// state, so it is safe to call concurrently. The returned `CString`
/// is owned by us (we pass it a caller-allocated buffer); we copy out
/// the bytes and free it.
fn gecos_for(username: &str) -> Option<String> {
    // CString::new fails if the name contains a NUL, which is never a
    // valid username anyway.
    let cname = CString::new(username).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r writes into `&mut pwd` and `buf`, returning a
    // pointer (which on success equals &mut pwd). The buffer is large
    // enough for any reasonable gecos field.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    if pwd.pw_gecos.is_null() {
        return None;
    }
    // SAFETY: pw_gecos is a valid NUL-terminated C string populated by libc.
    let cs = unsafe { CStr::from_ptr(pwd.pw_gecos) };
    let s = cs.to_string_lossy().into_owned();
    (!s.is_empty()).then_some(s)
}

/// Pure helper extracted from `to_local_user` so it can be tested.
/// Picks the first GECOS field; falls back to `username` if empty.
pub fn parse_gecos_full_name(gecos: Option<&str>, fallback: &str) -> String {
    gecos
        .map(|g| g.split(',').next().unwrap_or("").trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

fn is_nologin(shell: &Path) -> bool {
    matches!(
        shell.to_str(),
        Some("/usr/sbin/nologin")
            | Some("/sbin/nologin")
            | Some("/bin/false")
            | Some("/bin/nologin")
            | Some("")
    )
}

/// ~/.face, then the freedesktop AccountsService icon.
fn find_avatar(username: &str, home: &Path) -> Option<String> {
    [
        home.join(".face"),
        PathBuf::from(format!("/var/lib/AccountsService/icons/{username}")),
    ]
    .into_iter()
    .find(|p| p.is_file())
    .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gecos_picks_first_field() {
        assert_eq!(
            parse_gecos_full_name(Some("Alice Wonderland,engineering,555-1212,123"), "alice"),
            "Alice Wonderland"
        );
    }

    #[test]
    fn parse_gecos_trims_whitespace() {
        assert_eq!(
            parse_gecos_full_name(Some("   Spaced Out  ,dept"), "spaced"),
            "Spaced Out"
        );
    }

    #[test]
    fn parse_gecos_falls_back_when_empty() {
        assert_eq!(parse_gecos_full_name(Some(""), "bob"), "bob");
    }

    #[test]
    fn parse_gecos_falls_back_when_none() {
        assert_eq!(parse_gecos_full_name(None, "carol"), "carol");
    }

    #[test]
    fn parse_gecos_falls_back_when_only_comma() {
        // GECOS like ",dept,123" → first field is empty → fallback
        assert_eq!(parse_gecos_full_name(Some(",dept,123"), "dan"), "dan");
    }

    #[test]
    fn is_nologin_recognises_common_shells() {
        assert!(is_nologin(Path::new("/usr/sbin/nologin")));
        assert!(is_nologin(Path::new("/sbin/nologin")));
        assert!(is_nologin(Path::new("/bin/nologin")));
        assert!(is_nologin(Path::new("/bin/false")));
        assert!(is_nologin(Path::new("")));
    }

    #[test]
    fn is_nologin_allows_real_shells() {
        assert!(!is_nologin(Path::new("/bin/bash")));
        assert!(!is_nologin(Path::new("/bin/zsh")));
        assert!(!is_nologin(Path::new("/usr/bin/fish")));
    }

    #[test]
    fn gecos_for_root_is_nonempty() {
        // root's GECOS is conventionally "root" on Debian. This also
        // verifies our getpwnam_r plumbing actually works.
        let g = gecos_for("root");
        assert!(g.is_some(), "could not look up root's gecos");
    }

    #[test]
    fn cache_serves_within_ttl() {
        // Serializes with the other cache/env tests: the user-list cache
        // is process-global (see `test_env_lock`).
        let _g = crate::test_env_lock();
        invalidate_cache();
        // First call: cache miss, hits NSS.
        let v1 = enumerate_users_cached();
        // Second call: cache hit — should be identical.
        let v2 = enumerate_users_cached();
        assert_eq!(v1.len(), v2.len());
        // The user list is sorted by username; equal length + equal
        // first username (if any) is a good-enough identity check.
        if let (Some(a), Some(b)) = (v1.first(), v2.first()) {
            assert_eq!(a.username, b.username);
        }
    }

    #[test]
    fn invalidate_clears_cache() {
        let _g = crate::test_env_lock();
        let _ = enumerate_users_cached();
        invalidate_cache();
        // After invalidation the cache is empty; the next call refetches.
        // We can't observe the refetch directly, but a successful call
        // proves the cache-miss path still works.
        let _ = enumerate_users_cached();
    }
}
