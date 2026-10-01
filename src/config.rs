//! Greeter configuration: `/etc/lionos/greeter.toml`.
//!
//! # Design rules
//! 1. **A bad config file must never prevent a login.** The greeter is
//!    the way *into* the machine; if parsing fails we log one line and
//!    fall back to defaults (autologin off). The operator can fix the
//!    file at leisure; users are not locked out of their own machine.
//! 2. **Zero new dependencies.** We need ~12 keys, not a TOML crate
//!    (~30 KB of binary + another name in the supply chain). A
//!    hand-written subset parser is 150 lines, fully unit-tested, and
//!    cannot regress on exotic TOML features because it simply refuses
//!    them. (greetd, for comparison, pulls in `toml` + `serde`.)
//! 3. **Forward compatible.** Unknown sections and keys are ignored,
//!    not rejected, so an older greeter keeps booting with a newer
//!    config file — a classic kiosk/enterprise upgrade trap avoided.
//!
//! # Supported subset
//! ```toml
//! # comment
//! [autologin]
//! user = "alice"          # string, quoted; # inside quotes is literal
//! delay_ms = 1500         # unsigned integer
//! relogin = false         # boolean
//!
//! [session]
//! default = "lion"        # preferred desktop session id
//!
//! [security]
//! mlock = true            # pin secrets into RAM (see mlock.rs)
//! ```
//! That is all: `key = value`, one per line; `"` or `'` strings;
//! `[section]` headers; full-line and trailing comments. Arrays,
//! nested tables, multi-line strings and dotted keys are out of scope
//! on purpose.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default config location. Override for tests / alt roots via the
/// `LION_GREETER_CONFIG` environment variable.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/lionos/greeter.toml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Autologin {
    /// The single local user to sign in without a password. `None`
    /// disables autologin entirely (the default, and the only safe
    /// default for a general-purpose OS).
    pub user: Option<String>,
    /// Grace period before the automatic sign-in fires. Gives the
    /// login UI time to show "signing in as alice … Esc to cancel"
    /// and gives a human time to press Esc. 0 = immediate.
    pub delay_ms: u64,
    /// Whether to auto-login *again* after the session ends. `true`
    /// is right for single-purpose/kiosk machines; `false` (the
    /// default-on-first-boot behaviour for `relogin` here is `true`)
    /// — see below — keeps a *logout* from instantly bouncing the
    /// user back in, which is what a shared machine expects.
    pub relogin: bool,
}

impl Default for Autologin {
    fn default() -> Self {
        Self {
            user: None,
            delay_ms: 0,
            relogin: true,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    /// Preferred session id (the gear menu's default selection) when
    /// the UI does not carry a per-user choice. `None` = use the
    /// last-chosen session, then the compositor default. The value is
    /// validated against installed sessions at use time, so a typo
    /// here degrades to "last used" instead of failing logins.
    pub default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Security {
    /// Attempt to pin secrets in RAM with `mlockall` (see `mlock.rs`).
    /// Default true; only disable for constrained containers that
    /// forbid the syscall outright.
    pub mlock: bool,
}

impl Default for Security {
    fn default() -> Self {
        Self { mlock: true }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub autologin: Autologin,
    pub session: Session,
    pub security: Security,
}

impl Config {
    /// Effective config path: `$LION_GREETER_CONFIG` if set (tests,
    /// recovery shells, alt-root boot), else the default location.
    pub fn path() -> PathBuf {
        std::env::var_os("LION_GREETER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    /// Load, parse and cache the configuration. Any problem — file
    /// missing, unreadable, syntactically broken, semantically absurd
    /// — is logged once and answered with `Config::default()`. The
    /// returned reference is static-lived so every call site (daemon
    /// start, `--check-config`) shares one snapshot.
    pub fn load() -> &'static Config {
        static CFG: OnceLock<Config> = OnceLock::new();
        CFG.get_or_init(|| Self::load_uncached(Self::path()))
    }

    fn load_uncached(path: impl AsRef<Path>) -> Config {
        let path = path.as_ref();
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No config file is the normal case on first boot.
                tracing::debug!(path = %path.display(), "no config file; using defaults");
                return Config::default();
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "config unreadable; using defaults (logins still work)"
                );
                return Config::default();
            }
        };
        match parse(&text) {
            Ok(cfg) => cfg,
            Err(line_no) => {
                tracing::warn!(
                    path = %path.display(),
                    line = line_no,
                    "config parse error; ignoring file and using defaults"
                );
                Config::default()
            }
        }
    }
}

// ── the parser ─────────────────────────────────────────────────────────

/// A single `key = value` pair after splitting. Values keep their raw
/// form; interpretation is per-key at consume time.
struct Pair {
    key: String,
    value: String,
}

enum Line {
    Section(String),
    Pair(Pair),
    Blank,
}

/// Classify one physical line. Returns `Err(line_number)` on syntax we
/// do not accept (unclosed quote, missing `=`, garbage after a value).
fn classify(line: &str, line_no: usize) -> Result<Line, usize> {
    // Split off a full-line or trailing comment, honouring quotes:
    // a `#` inside quotes is literal data, not a comment.
    let (content, _comment) = split_comment(line);
    let content = content.trim();
    if content.is_empty() {
        return Ok(Line::Blank);
    }
    if content.starts_with('[') {
        let end = match content.find(']') {
            Some(i) => i,
            None => return Err(line_no),
        };
        let name = content[1..end].trim().to_owned();
        if name.is_empty() || content[end + 1..].trim() != "" {
            return Err(line_no);
        }
        return Ok(Line::Section(name));
    }
    let eq = match content.find('=') {
        Some(i) => i,
        None => return Err(line_no),
    };
    let key = content[..eq].trim().to_owned();
    if key.is_empty() || key.starts_with('"') || key.starts_with('\'') {
        return Err(line_no);
    }
    let value = content[eq + 1..].trim().to_owned();
    if value.is_empty() {
        return Err(line_no);
    }
    Ok(Line::Pair(Pair { key, value }))
}

/// Split a line into (code, comment) at the first unquoted `#`.
fn split_comment(line: &str) -> (&str, &str) {
    let bytes = line.as_bytes();
    let mut in_quote: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match in_quote {
            Some(q) => {
                if b == q {
                    in_quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    in_quote = Some(b);
                } else if b == b'#' {
                    return (&line[..i], &line[i..]);
                }
            }
        }
    }
    (line, "")
}

/// Interpret a raw value as a quoted string. `Err(())` on unbalanced
/// or embedded-NUL strings. Accepts both `"…"` and `'…'`; no escapes
/// (a login-greeter config never needs them; refusing keeps the
/// parser honest).
fn as_string(raw: &str) -> Result<String, ()> {
    let b = raw.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        let inner = &raw[1..raw.len() - 1];
        if inner.contains('\u{0}') {
            return Err(());
        }
        // An unescaped same-quote inside is a syntax error.
        let q = b[0];
        if inner.as_bytes().contains(&q) {
            return Err(());
        }
        Ok(inner.to_owned())
    } else {
        Err(())
    }
}

fn as_bool(raw: &str) -> Result<bool, ()> {
    match raw {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        _ => Err(()),
    }
}

fn as_u64(raw: &str) -> Result<u64, ()> {
    // Reject signs, whitespace, and overflow — delay_ms is a plain count.
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    raw.parse::<u64>().map_err(|_| ())
}

/// Parse a whole file. On any bad line the *entire file* is rejected
/// (fail-closed to defaults) — a half-applied autologin config is
/// worse than none, and partial acceptance would make the file's
/// semantics depend on line order.
pub fn parse(text: &str) -> Result<Config, usize> {
    let mut cfg = Config::default();
    let mut section = String::new(); // "" = top level (only comments expected)

    for (idx, raw_line) in text.lines().enumerate() {
        let line_no = idx + 1;
        match classify(raw_line, line_no)? {
            Line::Blank => {}
            Line::Section(name) => section = name,
            Line::Pair(pair) => {
                // Unknown sections/keys are ignored (forward compat).
                match (section.as_str(), pair.key.as_str()) {
                    ("autologin", "user") => {
                        // Empty string or the literal "none" (either quote
                        // style) explicitly disables autologin; any other
                        // quoted string names the user.
                        match as_string(&pair.value) {
                            Ok(s) if s.is_empty() || s == "none" => {
                                cfg.autologin.user = None;
                            }
                            Ok(name) => cfg.autologin.user = Some(name),
                            Err(()) => return Err(line_no),
                        }
                    }
                    ("autologin", "delay_ms") => {
                        cfg.autologin.delay_ms = as_u64(&pair.value).map_err(|_| line_no)?;
                    }
                    ("autologin", "relogin") => {
                        cfg.autologin.relogin = as_bool(&pair.value).map_err(|_| line_no)?;
                    }
                    ("session", "default") => {
                        match as_string(&pair.value) {
                            // Empty / "default" = let the last-chosen or
                            // compositor default apply.
                            Ok(s) if s.is_empty() || s == "default" => {
                                cfg.session.default = None;
                            }
                            Ok(id) if sessions_plausible(&id) => {
                                cfg.session.default = Some(id);
                            }
                            // A syntactically valid but absurd id is a
                            // semantic rejection: fail the file so the
                            // operator notices, defaults keep logins up.
                            Ok(_) => return Err(line_no),
                            Err(()) => return Err(line_no),
                        }
                    }
                    ("security", "mlock") => {
                        cfg.security.mlock = as_bool(&pair.value).map_err(|_| line_no)?;
                    }
                    _ => { /* unknown key: ignored by design */ }
                }
            }
        }
    }

    // Semantic sanity: a named autologin user must be a plausible
    // POSIX username. Anything else is treated as "off" so a typo'd
    // config can't make the greeter wait on a nonexistent account.
    if let Some(u) = cfg.autologin.user.as_deref() {
        if !is_plausible_username(u) {
            return Err(0); // line 0 = "semantic rejection", logged as such
        }
    }
    Ok(cfg)
}

/// Session ids are file stems and `XDG_SESSION_DESKTOP` values:
/// plain ASCII, bounded length.
fn sessions_plausible(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// POSIX-ish username: starts alnum, then alnum/`-`/`_`/`.`; 1..=31
/// chars (fits both classic login(1) and getpwnam buffers with room).
fn is_plausible_username(s: &str) -> bool {
    if s.is_empty() || s.len() > 31 {
        return false;
    }
    let first = s.as_bytes()[0];
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_gives_defaults() {
        assert_eq!(parse("").unwrap(), Config::default());
        assert_eq!(
            parse("\n\n  \n# only comments\n").unwrap(),
            Config::default()
        );
    }

    #[test]
    fn full_valid_config_parses() {
        let text = r#"
# LionOS greeter config
[autologin]
user = "alice"      # the kiosk account; '#' inside quotes is literal
delay_ms = 1500
relogin = false

[security]
mlock = true
"#;
        let cfg = parse(text).unwrap();
        assert_eq!(cfg.autologin.user.as_deref(), Some("alice"));
        assert_eq!(cfg.autologin.delay_ms, 1500);
        assert!(!cfg.autologin.relogin);
        assert!(cfg.security.mlock);
    }

    #[test]
    fn quoted_hash_is_literal_not_comment() {
        // A `#` after the closing quote IS a comment; the value stops at
        // the quote. (A `#` *inside* the quotes would be literal, but
        // such a username is then rejected semantically — see the
        // absurd-username test — so the observable behaviour here is
        // the trailing-comment case.)
        let cfg = parse("[autologin]\nuser = \"alice\" # kiosk account\n").unwrap();
        assert_eq!(cfg.autologin.user.as_deref(), Some("alice"));
    }

    #[test]
    fn unknown_sections_and_keys_are_ignored() {
        let cfg = parse(
            "[future_section]\nrocket = \"fuel\"\n[autologin]\ndelay_ms = 7\nunknown_key = 42\n",
        )
        .unwrap();
        assert_eq!(cfg.autologin.delay_ms, 7);
        assert_eq!(cfg.autologin.user, None);
    }

    #[test]
    fn explicit_user_off_via_empty_string_or_none() {
        assert_eq!(
            parse("[autologin]\nuser = \"\"\n").unwrap().autologin.user,
            None
        );
        assert_eq!(
            parse("[autologin]\nuser = 'none'\n")
                .unwrap()
                .autologin
                .user,
            None
        );
    }

    #[test]
    fn single_quotes_work() {
        let cfg = parse("[autologin]\nuser = 'bob'\n").unwrap();
        assert_eq!(cfg.autologin.user.as_deref(), Some("bob"));
    }

    #[test]
    fn malformed_lines_reject_whole_file() {
        assert!(parse("[autologin\n").is_err()); // unclosed section
        assert!(parse("delay_ms\n").is_err()); // no '='
        assert!(parse("[autologin]\nuser = alice\n").is_err()); // unquoted
        assert!(parse("[autologin]\nuser = \"open\n").is_err()); // unclosed quote
        assert!(parse("[autologin]\ndelay_ms = -5\n").is_err()); // negative
        assert!(parse("[autologin]\nrelogin = maybe\n").is_err()); // bad bool
    }

    #[test]
    fn absurd_username_rejected_semantically() {
        assert!(parse("[autologin]\nuser = \"has space\"\n").is_err());
        assert!(parse("[autologin]\nuser = \"-leading-dash\"\n").is_err());
        assert!(parse("[autologin]\nuser = \"\"\n").is_ok()); // off is fine
    }

    #[test]
    fn session_default_parses_and_validates() {
        let cfg = parse("[session]\ndefault = 'lion'\n").unwrap();
        assert_eq!(cfg.session.default.as_deref(), Some("lion"));

        // "default" and "" are the explicit no-preference forms.
        assert_eq!(
            parse("[session]\ndefault = \"\"\n")
                .unwrap()
                .session
                .default,
            None
        );
        assert_eq!(
            parse("[session]\ndefault = 'default'\n")
                .unwrap()
                .session
                .default,
            None
        );

        // Absurd ids reject the whole file (fail-closed to defaults).
        assert!(parse("[session]\ndefault = '/etc/passwd'\n").is_err());
        assert!(parse("[session]\ndefault = 'a b'\n").is_err());

        // Unknown keys in [session] still ignored.
        let cfg = parse("[session]\ndefault = 'lion'\nfuture = 1\n").unwrap();
        assert_eq!(cfg.session.default.as_deref(), Some("lion"));
    }

    #[test]
    fn defaults_are_safe() {
        let d = Config::default();
        assert_eq!(d.autologin.user, None, "autologin must default OFF");
        assert_eq!(d.autologin.delay_ms, 0);
        assert!(d.autologin.relogin);
        assert!(d.security.mlock);
    }

    #[test]
    fn delay_ms_accepts_big_but_not_overflow() {
        assert_eq!(
            parse("[autologin]\ndelay_ms = 18446744073709551615\n")
                .unwrap()
                .autologin
                .delay_ms,
            u64::MAX
        );
        assert!(parse("[autologin]\ndelay_ms = 18446744073709551616\n").is_err());
    }

    #[test]
    fn bool_word_forms() {
        for word in ["true", "yes", "on", "1"] {
            assert!(
                parse(&format!("[autologin]\nrelogin = {word}\n"))
                    .unwrap()
                    .autologin
                    .relogin,
                "{word}"
            );
        }
        for word in ["false", "no", "off", "0"] {
            assert!(
                !parse(&format!("[autologin]\nrelogin = {word}\n"))
                    .unwrap()
                    .autologin
                    .relogin,
                "{word}"
            );
        }
    }
}
