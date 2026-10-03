#![forbid(unsafe_code)]
//! User enumeration (spec 01 §3 "Users and sessions").
//!
//! Reads `/etc/passwd` (text parse — no NSS round-trips, so enumeration can
//! never hang on a flaky SSSD/LDAP setup; remote users are a v2 milestone)
//! and merges accountsservice-compatible per-user data from
//! `/var/lib/AccountsService/users/<name>` (INI-ish keyfile: `[User]`
//! `Session=`, `Icon=`, plus GECOS for the real name and
//! `/var/lib/AccountsService/icons/<name>` as the avatar).
//!
//! System accounts (UID outside `min_uid..=max_uid`, `nologin`/`false`
//! shells) are hidden. Everything is bounded: passwd line caps, username
//! charset checks, avatar path is passed through as data only.

use crate::config::Config;
use crate::error::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Hard cap on a passwd line we are willing to parse.
const MAX_PASSWD_LINE: usize = 4096;
/// Hard cap on an AccountsService user file.
const MAX_USER_FILE: usize = 8192;
/// Maximum number of users ever returned.
const MAX_USERS: usize = 512;

/// One enumerated login candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub real_name: String,
    pub shell: String,
    pub home: PathBuf,
    /// AccountsService icon path, if present.
    pub avatar: Option<PathBuf>,
    /// AccountsService `Session=` (last session choice), if present.
    pub last_session: Option<String>,
    /// True for the synthetic guest entry (only when guest is enabled).
    pub is_guest: bool,
}

/// Shells that never offer an interactive session.
fn is_nologin_shell(shell: &str) -> bool {
    matches!(
        shell.rsplit('/').next().unwrap_or(""),
        "nologin" | "false" | "sync" | "halt" | "shutdown"
    )
}

/// Parse one passwd line. Fields: name:passwd:uid:gid:gecos:home:shell
fn parse_passwd_line(line: &str) -> Option<(String, u32, u32, String, PathBuf, String)> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut it = line.splitn(7, ':');
    let name = it.next()?;
    let _pw = it.next()?;
    let uid: u32 = it.next()?.parse().ok()?;
    let gid: u32 = it.next()?.parse().ok()?;
    let gecos = it.next().unwrap_or("");
    let home = PathBuf::from(it.next().unwrap_or(""));
    let shell = it.next().unwrap_or("").trim().to_string();
    if name.is_empty() || name.len() > 64 || shell.is_empty() {
        return None; // no shell → no interactive session → not a login user
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'))
    {
        return None;
    }
    Some((name.to_string(), uid, gid, gecos.to_string(), home, shell))
}

/// Parse a tiny INI subset: `[Section]` headers + `Key=Value` lines.
/// Returns `(section, key) -> value`.
pub(crate) fn parse_keyfile(text: &str, max_entries: usize) -> BTreeMap<(String, String), String> {
    let mut out = BTreeMap::new();
    let mut section = String::new();
    for line in text.lines().take(1024) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = inner.trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if out.len() >= max_entries {
                break;
            }
            out.insert(
                (section.clone(), k.trim().to_string()),
                v.trim().to_string(),
            );
        }
    }
    out
}

/// User database: passwd + AccountsService merge, bounded and cached per
/// request by the caller if desired.
pub struct UserDb {
    min_uid: u32,
    max_uid: u32,
    accountsservice_dir: PathBuf,
    passwd_path: PathBuf,
}

impl UserDb {
    pub fn from_config(cfg: &Config) -> Self {
        UserDb {
            min_uid: cfg.greeter.min_uid,
            max_uid: cfg.greeter.max_uid,
            accountsservice_dir: cfg.greeter.accountsservice_dir.clone(),
            passwd_path: cfg.greeter.passwd_path.clone(),
        }
    }

    /// Override the passwd source (tests, nspawn fixtures).
    pub fn with_passwd_path(mut self, p: PathBuf) -> Self {
        self.passwd_path = p;
        self
    }

    /// Enumerate interactive login candidates, sorted by uid, capped.
    pub fn list(&self) -> Result<Vec<UserInfo>> {
        let raw = std::fs::read_to_string(&self.passwd_path)
            .map_err(|e| Error::Io(format!("reading {}", self.passwd_path.display()), e))?;
        let mut users: Vec<UserInfo> = Vec::new();
        for line in raw.lines().take(4096) {
            if line.len() > MAX_PASSWD_LINE {
                continue;
            }
            let Some((name, uid, gid, gecos, home, shell)) = parse_passwd_line(line) else {
                continue;
            };
            if uid < self.min_uid || uid > self.max_uid || uid >= 65534 {
                continue; // system / nobody accounts stay hidden
            }
            if is_nologin_shell(&shell) {
                continue;
            }
            if users.len() >= MAX_USERS {
                break;
            }
            let (last_session, avatar) = self.accountsservice_data(&name);
            users.push(UserInfo {
                name,
                uid,
                gid,
                real_name: sanitize_gecos(&gecos),
                shell,
                home,
                avatar,
                last_session,
                is_guest: false,
            });
        }
        users.sort_by(|a, b| (a.uid, &a.name).cmp(&(b.uid, &b.name)));
        Ok(users)
    }

    /// Look up one user by name (also for hidden-user / type-your-username
    /// mode). Follows the same visibility rules.
    pub fn find(&self, name: &str) -> Result<Option<UserInfo>> {
        // Cheap: reuse list() — the file is small and this is not hot.
        Ok(self.list()?.into_iter().find(|u| u.name == name))
    }

    /// Resolve a user entry by name even if hidden (needed to resolve the
    /// configured `ui_user` or guest account, which may be a system user).
    pub fn find_raw(&self, name: &str) -> Option<UserInfo> {
        let raw = std::fs::read_to_string(&self.passwd_path).ok()?;
        for line in raw.lines().take(4096) {
            if line.len() > MAX_PASSWD_LINE {
                continue;
            }
            if let Some((n, uid, gid, gecos, home, shell)) = parse_passwd_line(line) {
                if n == name {
                    let (last_session, avatar) = self.accountsservice_data(&n);
                    return Some(UserInfo {
                        name: n,
                        uid,
                        gid,
                        real_name: sanitize_gecos(&gecos),
                        shell,
                        home,
                        avatar,
                        last_session,
                        is_guest: false,
                    });
                }
            }
        }
        None
    }

    fn accountsservice_data(&self, name: &str) -> (Option<String>, Option<PathBuf>) {
        let path = self.accountsservice_dir.join("users").join(name);
        let session = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| {
                if text.len() > MAX_USER_FILE {
                    return None;
                }
                parse_keyfile(&text, 64)
                    .get(&("User".to_string(), "Session".to_string()))
                    .cloned()
            })
            .filter(|s| !s.is_empty());
        let icon = {
            let icon_path = self.accountsservice_dir.join("icons").join(name);
            icon_path.is_file().then_some(icon_path)
        };
        (session, icon)
    }
}

fn sanitize_gecos(g: &str) -> String {
    let first = g.split(',').next().unwrap_or("").trim();
    crate::proto::sanitize_text(first, 128)
}

/// Supplementary group ids for `user` from `/etc/group` (an initgroups
/// equivalent, bounded to 64 groups). Text-parsed like the passwd path so
/// it can never hang on NSS.
pub fn supplementary_groups(user: &str) -> Vec<u32> {
    supplementary_groups_from(Path::new("/etc/group"), user)
}

/// Test/configurable variant of [`supplementary_groups`].
pub fn supplementary_groups_from(path: &Path, user: &str) -> Vec<u32> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let mut out = Vec::new();
    for line in raw.lines().take(2048) {
        if line.len() > MAX_PASSWD_LINE {
            continue;
        }
        // group_name:passwd:gid:members(,member…)
        let mut it = line.splitn(4, ':');
        let Some(_name) = it.next() else { continue };
        let Some(_pw) = it.next() else { continue };
        let Some(gid) = it.next().and_then(|g| g.parse::<u32>().ok()) else {
            continue;
        };
        let members = it.next().unwrap_or("");
        let candidate = members.split(',').any(|m| m.trim() == user);
        if candidate && out.len() < 64 && !out.contains(&gid) {
            out.push(gid);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_passwd(dir: &Path) -> PathBuf {
        let p = dir.join("passwd");
        std::fs::write(
            &p,
            "root:x:0:0:root:/root:/bin/bash\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             alice:x:1000:1000:Alice Lion,,,:/home/alice:/bin/bash\n\
             bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n\
             svc-bot:x:900:900:bot:/var/bot:/usr/sbin/nologin\n\
             odd:x:1200:1200:Tab\tGuy:/home/odd:/bin/bash\n",
        )
        .unwrap();
        p
    }

    fn db(dir: &Path) -> UserDb {
        let mut cfg = Config::default();
        cfg.greeter.accountsservice_dir = dir.join("AccountsService");
        UserDb::from_config(&cfg).with_passwd_path(fixture_passwd(dir))
    }

    #[test]
    fn hides_system_accounts_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        fixture_passwd(dir.path());
        let users = db(dir.path()).list().unwrap();
        let names: Vec<&str> = users.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["alice", "bob", "odd"]); // root, daemon, svc-bot hidden
        assert!(users.iter().all(|u| u.uid >= 1000));
    }

    #[test]
    fn merges_accountsservice_data() {
        let dir = tempfile::tempdir().unwrap();
        fixture_passwd(dir.path());
        let as_dir = dir.path().join("AccountsService");
        std::fs::create_dir_all(as_dir.join("users")).unwrap();
        std::fs::create_dir_all(as_dir.join("icons")).unwrap();
        std::fs::write(
            as_dir.join("users").join("alice"),
            "[User]\nSession=lion-wayland\nIcon=/icon.png\n",
        )
        .unwrap();
        std::fs::write(as_dir.join("icons").join("alice"), b"png").unwrap();
        let users = db(dir.path()).list().unwrap();
        let alice = users.iter().find(|u| u.name == "alice").unwrap();
        assert_eq!(alice.last_session.as_deref(), Some("lion-wayland"));
        assert_eq!(
            alice.avatar.as_deref(),
            Some(as_dir.join("icons").join("alice").as_path())
        );
        assert_eq!(alice.real_name, "Alice Lion");
        let bob = users.iter().find(|u| u.name == "bob").unwrap();
        assert!(bob.last_session.is_none() && bob.avatar.is_none());
    }

    #[test]
    fn find_hidden_mode_lookup() {
        let dir = tempfile::tempdir().unwrap();
        fixture_passwd(dir.path());
        let d = db(dir.path());
        assert!(d.find("alice").unwrap().is_some());
        assert!(d.find("root").unwrap().is_none());
        assert!(d.find("ghost").unwrap().is_none());
        assert!(d.find_raw("root").is_some());
    }

    #[test]
    fn passwd_malformed_lines_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("passwd");
        std::fs::write(
            &p,
            "garbage no colons\nx:1:2:3\nbad:uid:x:z:0:0:a:/h:/bin/sh\nok:x:5:5::/h:/bin/sh\n",
        )
        .unwrap();
        let mut cfg = Config::default();
        cfg.greeter.min_uid = 0;
        let d = UserDb::from_config(&cfg).with_passwd_path(p);
        let users = d.list().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "ok");
    }

    #[test]
    fn keyfile_parser_subset() {
        let m = parse_keyfile(
            "[User]\nSession=lion\n# c\n; c\n\nEmpty=\n[Shadow]\nK = V",
            16,
        );
        assert_eq!(
            m.get(&("User".into(), "Session".into()))
                .map(String::as_str),
            Some("lion")
        );
        assert_eq!(
            m.get(&("User".into(), "Empty".into())).map(String::as_str),
            Some("")
        );
        assert_eq!(
            m.get(&("Shadow".into(), "K".into())).map(String::as_str),
            Some("V")
        );
    }

    #[test]
    fn supplementary_groups_from_group_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("group");
        std::fs::write(
            &p,
            "sudo:x:27:alice\nvideo:x:44:alice,bob\naudio:x:29:pulse\nbad:x:x:99\nnomembers:x:1000:\n",
        )
        .unwrap();
        let g = supplementary_groups_from(&p, "alice");
        assert_eq!(g, vec![27, 44]);
        assert_eq!(supplementary_groups_from(&p, "bob"), vec![44]);
        assert!(supplementary_groups_from(&p, "nobody").is_empty());
    }
}
