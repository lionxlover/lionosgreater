//! XDG session discovery: `/usr/share/wayland-sessions/*.desktop` and
//! `/usr/share/x11-sessions/*.desktop` (the same format SDDM, LightDM,
//! GDM and every display-manager lister uses).
//!
//! The greeter *lists and validates* sessions; which compositor actually
//! runs is `lion-session`'s decision (it receives the chosen id via
//! `--session`). This split keeps the root daemon free of any
//! session-launching logic while still giving the UI the standard
//! "gear menu" every other greeter has — the capability GDM, SDDM and
//! LightDM all expose and lion-greeter 0.5.0 lacked.
//!
//! # Parser
//! A desktop-entry subset: `[Desktop Entry]` section, `Key=Value`
//! lines, quoted values with the spec's five escapes, `#` comments,
//! locale-suffixed keys (`Name[de]`) ignored in favour of the plain
//! key. Missing `Type`/`Name`/`Exec`, `NoDisplay=true`, `Hidden=true`
//! or a failed `TryExec` drop the entry — exactly the rules the
//! desktop-entry and display-manager specs ask listers to apply.
//! Hand-written for the same reason as the TOML subset in
//! `config.rs`: zero new dependencies, total audit surface control.
//!
//! # Failure policy
//! Everything here is read-only and cache-based; any I/O or parse
//! problem yields "no sessions" (the UI falls back to the default
//! session) and one journal line. A broken session file can never
//! affect authentication.

use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Standard session directories, most-preferred first. When the same
/// id appears in both, the wayland entry wins (a compositor that ships
/// both wants wayland chosen on a wayland-first OS).
pub const WAYLAND_SESSIONS_DIR: &str = "/usr/share/wayland-sessions";
pub const X11_SESSIONS_DIR: &str = "/usr/share/x11-sessions";

/// Override for tests, alt roots and recovery shells:
/// colon-separated list of directories to scan instead of the
/// standard pair.
const SESSIONS_DIR_ENV: &str = "LION_GREETER_SESSIONS_PATH";

const CACHE_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionEntry {
    /// The id a UI refers to the session by: file stem, e.g. "lion".
    pub id: String,
    /// Display name from the desktop file ("LionOS Desktop").
    pub name: String,
    /// Raw Exec line (validated to exist, not executed here).
    pub exec: String,
    /// Comment line, "" when absent.
    pub comment: String,
    /// "wayland" or "x11" depending on the directory it came from.
    pub session_type: &'static str,
    /// `DesktopNames=` split into components ("LionOS", "GNOME"...).
    pub desktop_names: Vec<String>,
}

// ── cache ──────────────────────────────────────────────────────────────

struct Cached {
    at: Instant,
    sessions: Vec<SessionEntry>,
}

fn cache() -> &'static Mutex<Option<Cached>> {
    static C: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Invalidate the session list cache (unit tests, future
/// package-install hooks).
pub fn invalidate_cache() {
    let mut g = cache().lock().unwrap_or_else(|e| e.into_inner());
    *g = None;
}

/// Enumerate the standard session directories, cached for
/// `CACHE_TTL` seconds. Returns an empty vec (never an error) when
/// nothing is installed — a fresh machine with no desktop files still
/// gets a working login with the default session.
pub fn enumerate() -> Vec<SessionEntry> {
    let mut g = cache().lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = g.as_ref() {
        if c.at.elapsed() < CACHE_TTL {
            return c.sessions.clone();
        }
    }
    let dirs = configured_dirs();
    let sessions = enumerate_from(&dirs);
    *g = Some(Cached {
        at: Instant::now(),
        sessions: sessions.clone(),
    });
    sessions
}

/// The directories to scan: `$LION_GREETER_SESSIONS_PATH` if set, else
/// the standard pair.
fn configured_dirs() -> Vec<PathBuf> {
    if let Some(p) = std::env::var_os(SESSIONS_DIR_ENV) {
        return std::env::split_paths(&p).collect();
    }
    vec![
        PathBuf::from(WAYLAND_SESSIONS_DIR),
        PathBuf::from(X11_SESSIONS_DIR),
    ]
}

/// Scan `dirs` in order (earlier wins on id collisions) and return the
/// filtered, name-sorted session list.
pub fn enumerate_from(dirs: &[PathBuf]) -> Vec<SessionEntry> {
    // BTreeMap: dedup by id keeping the first (preferred) entry and
    // giving us a stable, id-sorted iteration for free.
    let mut by_id: BTreeMap<String, SessionEntry> = BTreeMap::new();
    for dir in dirs {
        let session_type = if dirs_prefer_wayland(dirs, dir) {
            "wayland"
        } else {
            "x11"
        };
        let entries = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => continue, // no dir = no sessions from it; normal
        };
        for file in entries.flatten() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            // First directory wins: wayland-sessions scanned first.
            if by_id.contains_key(id) {
                continue;
            }
            if let Some(entry) = parse_desktop_file(&path, id, session_type) {
                by_id.insert(id.to_owned(), entry);
            }
        }
    }
    // Sort by display name for the UI (id as tiebreaker); ids stay
    // unique so the sort is total.
    let mut v: Vec<SessionEntry> = by_id.into_values().collect();
    v.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    v
}

/// True when `dir` is (or is aliased to) the wayland directory.
fn dirs_prefer_wayland(dirs: &[PathBuf], dir: &Path) -> bool {
    // The session type is a property of the *directory name*, not the
    // scan position, so an alt-root override still classifies right.
    match dir.file_name().and_then(|s| s.to_str()) {
        Some("wayland-sessions") => true,
        Some("x11-sessions") => false,
        // Unknown override dir: infer from scan order — first dir is
        // the wayland-preferred one by convention.
        _ => dirs.first().map(|d| d == dir).unwrap_or(false),
    }
}

/// Find one session by id (bypasses the cache on miss so a
/// just-installed session is found immediately).
pub fn find(id: &str) -> Option<SessionEntry> {
    if !is_plausible_id(id) {
        return None;
    }
    enumerate().into_iter().find(|s| s.id == id)
}

/// Session ids become `XDG_SESSION_DESKTOP` values and `--session`
/// arguments, so they get the same scrubbing as usernames: plain
/// ASCII file-stem characters only, bounded length.
pub fn is_plausible_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

// ── desktop-file parsing ───────────────────────────────────────────────

/// Parse one .desktop file into an entry, applying the lister rules
/// (Type/Name/Exec required; NoDisplay/Hidden skip; TryExec must
/// resolve). Returns None when the file should not be listed.
fn parse_desktop_file(path: &Path, id: &str, session_type: &'static str) -> Option<SessionEntry> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "session file unreadable");
            return None;
        }
    };
    let kv = parse_key_values(&text)?;
    build_entry(kv, id, session_type)
}

/// Parse `[Desktop Entry]` into a key map. Returns None when the file
/// has no `[Desktop Entry]` section at all.
fn parse_key_values(text: &str) -> Option<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    let mut in_entry_section = false;
    let mut saw_section = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            saw_section = true;
            in_entry_section = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry_section {
            continue; // locale groups, other sections: ignored
        }
        let Some((key, value)) = line.split_once('=') else {
            continue; // malformed line: skip, don't reject the file
        };
        let key = key.trim();
        // Locale-suffixed keys (Name[de]) are dropped: the greeter
        // renders the default (English) name; per-locale session names
        // are a UI-layer concern.
        if key.contains('[') || !is_valid_key(key) {
            continue;
        }
        map.insert(key.to_owned(), unquote(value.trim()));
    }
    if !saw_section {
        return None;
    }
    Some(map)
}

fn is_valid_key(key: &str) -> bool {
    !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Apply the spec's value rules: strip surrounding double quotes and
/// interpret the five standard escapes (`\n`, `\t`, `\s`, `\\`, and
/// a bare trailing backslash is left alone — spec says invalid escapes
/// are data).
fn unquote(v: &str) -> String {
    let b = v.as_bytes();
    if b.len() >= 2 && b[0] == b'"' && b[b.len() - 1] == b'"' {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('s') => out.push(' '),
                    Some('\\') => out.push('\\'),
                    // Unknown escape: keep both characters (spec:
                    // not a valid escape, treated as literal).
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else {
        v.to_owned()
    }
}

/// Turn the parsed key map into a listed entry (or None when the
/// lister rules exclude it).
fn build_entry(
    kv: BTreeMap<String, String>,
    id: &str,
    session_type: &'static str,
) -> Option<SessionEntry> {
    // Only Application-type entries are valid sessions per spec.
    if kv.get("Type").map(String::as_str) != Some("Application") {
        return None;
    }
    let name = kv.get("Name")?.clone();
    let exec = kv.get("Exec")?.clone();
    if name.is_empty() || exec.is_empty() {
        return None;
    }
    // Hidden=true means "deleted by the admin"; NoDisplay=true means
    // "installed but not offered". Both are lister exclusions.
    if kv.get("Hidden").map(String::as_str) == Some("true") {
        return None;
    }
    if kv.get("NoDisplay").map(String::as_str) == Some("true") {
        return None;
    }
    // TryExec: the entry only applies when the binary resolves. This
    // is how distros ship "the same file, different backends".
    if let Some(try_exec) = kv.get("TryExec") {
        if !try_exec.is_empty() && !resolves(try_exec) {
            return None;
        }
    }
    let desktop_names: Vec<String> = kv
        .get("DesktopNames")
        .map(|v| {
            v.split(';')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(SessionEntry {
        id: id.to_owned(),
        name,
        exec,
        comment: kv.get("Comment").cloned().unwrap_or_default(),
        session_type,
        desktop_names,
    })
}

/// True when `prog` is an executable absolute path, or resolves to an
/// executable file inside `PATH`.
fn resolves(prog: &str) -> bool {
    if prog.is_empty() {
        return false;
    }
    if prog.contains('/') {
        return is_exec_file(Path::new(prog));
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            if is_exec_file(&dir.join(prog)) {
                return true;
            }
        }
    }
    false
}

fn is_exec_file(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "lion-sessions-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn parses_a_standard_wayland_session() {
        let d = tmpdir("std");
        write(
            &d,
            "lion.desktop",
            "[Desktop Entry]\nName=LionOS Desktop\nExec=lion-session\nComment=The LionOS session\nDesktopNames=LionOS;\nType=Application\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.id, "lion");
        assert_eq!(s.name, "LionOS Desktop");
        assert_eq!(s.exec, "lion-session");
        assert_eq!(s.comment, "The LionOS session");
        assert_eq!(s.desktop_names, vec!["LionOS".to_string()]);
        assert_eq!(s.session_type, "wayland"); // first dir = wayland
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn quoted_values_and_escapes() {
        let d = tmpdir("quote");
        write(
            &d,
            "q.desktop",
            "[Desktop Entry]\nName=\"My \\sSession\"\nExec=foo\nType=Application\nComment=\"line\\nbreak\"\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions[0].name, "My  Session");
        assert_eq!(sessions[0].comment, "line\nbreak");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_required_keys_excluded() {
        let d = tmpdir("req");
        write(&d, "no-type.desktop", "[Desktop Entry]\nName=X\nExec=foo\n");
        write(
            &d,
            "no-name.desktop",
            "[Desktop Entry]\nType=Application\nExec=foo\n",
        );
        write(
            &d,
            "no-exec.desktop",
            "[Desktop Entry]\nType=Application\nName=X\n",
        );
        write(
            &d,
            "wrong-type.desktop",
            "[Desktop Entry]\nType=Link\nName=X\nExec=foo\n",
        );
        assert_eq!(enumerate_from(std::slice::from_ref(&d)), vec![]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nodisplay_and_hidden_excluded() {
        let d = tmpdir("hidden");
        write(
            &d,
            "hidden.desktop",
            "[Desktop Entry]\nType=Application\nName=H\nExec=foo\nHidden=true\n",
        );
        write(
            &d,
            "nodisplay.desktop",
            "[Desktop Entry]\nType=Application\nName=N\nExec=foo\nNoDisplay=true\n",
        );
        write(
            &d,
            "shown.desktop",
            "[Desktop Entry]\nType=Application\nName=S\nExec=foo\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "shown");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn tryexec_must_resolve() {
        let d = tmpdir("tryexec");
        // TryExec to something that certainly exists.
        write(
            &d,
            "good.desktop",
            "[Desktop Entry]\nType=Application\nName=G\nExec=foo\nTryExec=/bin/sh\n",
        );
        write(
            &d,
            "bad.desktop",
            "[Desktop Entry]\nType=Application\nName=B\nExec=foo\nTryExec=/nonexistent/lion/definitely-not\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "good");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn wayland_dir_wins_id_collision_and_type_named() {
        let wl = tmpdir("wl").join("wayland-sessions");
        let x11 = tmpdir("x11").join("x11-sessions");
        std::fs::create_dir_all(&wl).unwrap();
        std::fs::create_dir_all(&x11).unwrap();
        write(
            &wl,
            "both.desktop",
            "[Desktop Entry]\nType=Application\nName=Wayland one\nExec=way\n",
        );
        write(
            &x11,
            "both.desktop",
            "[Desktop Entry]\nType=Application\nName=X11 one\nExec=x11\n",
        );
        write(
            &x11,
            "onlyx.desktop",
            "[Desktop Entry]\nType=Application\nName=Only X\nExec=x11\n",
        );
        let sessions = enumerate_from(&[wl.clone(), x11.clone()]);
        assert_eq!(sessions.len(), 2);
        let both = sessions.iter().find(|s| s.id == "both").unwrap();
        assert_eq!(both.name, "Wayland one");
        assert_eq!(both.session_type, "wayland");
        let onlyx = sessions.iter().find(|s| s.id == "onlyx").unwrap();
        assert_eq!(onlyx.session_type, "x11");
        let _ = std::fs::remove_dir_all(wl.parent().unwrap());
        let _ = std::fs::remove_dir_all(x11.parent().unwrap());
    }

    #[test]
    fn locale_suffixed_keys_ignored() {
        let d = tmpdir("locale");
        write(
            &d,
            "l.desktop",
            "[Desktop Entry]\nName=Plain\nName[de]=Deutsch\nType=Application\nExec=foo\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions[0].name, "Plain");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn missing_directories_are_quietly_empty() {
        let sessions = enumerate_from(&[PathBuf::from("/nonexistent/lion-sessions")]);
        assert_eq!(sessions, vec![]);
    }

    #[test]
    fn empty_dir_gives_empty_list() {
        let d = tmpdir("empty");
        assert_eq!(enumerate_from(std::slice::from_ref(&d)), vec![]);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn malformed_lines_skipped_not_fatal() {
        let d = tmpdir("malformed");
        write(
            &d,
            "m.desktop",
            "[Desktop Entry]\nName=M\nType=Application\nExec=foo\nthis line has no equals\nKey With Space=1\nComment=still works\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].comment, "still works");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn id_plausibility() {
        assert!(is_plausible_id("lion"));
        assert!(is_plausible_id("gnome-wayland-2"));
        assert!(!is_plausible_id(""));
        assert!(!is_plausible_id("has space"));
        assert!(!is_plausible_id("no/slash"));
        assert!(!is_plausible_id(&"x".repeat(65)));
    }

    #[test]
    fn sorted_by_name_for_stable_ui() {
        let d = tmpdir("sort");
        write(
            &d,
            "zeta.desktop",
            "[Desktop Entry]\nType=Application\nName=AAA\nExec=a\n",
        );
        write(
            &d,
            "alpha.desktop",
            "[Desktop Entry]\nType=Application\nName=ZZZ\nExec=z\n",
        );
        let sessions = enumerate_from(std::slice::from_ref(&d));
        assert_eq!(sessions[0].id, "zeta"); // name AAA first
        assert_eq!(sessions[1].id, "alpha");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unquote_plain_and_unknown_escape() {
        assert_eq!(unquote("plain"), "plain");
        assert_eq!(unquote("\"quoted\""), "quoted");
        assert_eq!(unquote("\"a\\\\b\""), "a\\b");
        // Unknown escape kept literally.
        assert_eq!(unquote("\"a\\qb\""), "a\\qb");
        // Lone trailing backslash preserved.
        assert_eq!(unquote("\"tail\\\\\""), "tail\\");
    }
}
