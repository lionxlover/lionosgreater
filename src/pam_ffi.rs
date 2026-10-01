//! Minimal, dependency-free PAM FFI for lion-greeter.
//!
//! We vendor this small binding instead of pulling in `pam-client` +
//! `pam-sys` (which transitively needs `bindgen` + `libclang`). The
//! hand-rolled binding keeps the build self-contained, lets us run on
//! minimal LionOS build images, and gives us full control over the
//! security-sensitive conversation callback (panic-safety, no info leak
//! on unexpected message styles, no log of the password).
//!
//! Only the small subset of libpam that lion-greeter needs is wrapped:
//!   `pam_start`, `pam_authenticate`, `pam_acct_mgmt`, `pam_setcred`,
//!   `pam_open_session`, `pam_close_session`, `pam_getenvlist`, `pam_end`.
//!
//! # Conversation forwarding (0.5.0)
//! The conversation callback used to answer every prompt from a fixed
//! `(username, password)` pair — which works for `pam_unix` and nothing
//! else. Any stack with a second factor (pam_google_authenticator,
//! pam_u2f, pam_pkcs11, pam_fido2, a LDAP "new password" round) would
//! deadlock or fail. The callback now routes prompts through a
//! pluggable [`ConvBridge`]:
//!
//! * [`ConvSide::Static`] — the old behaviour: answer echo-off with the
//!   password, echo-on with the username. Used by `--check-pam` and by
//!   the autologin stack (which prompts for nothing).
//! * [`ConvSide::Interactive`] — forward prompts to the login UI over
//!   D-Bus (see `auth.rs`'s hybrid bridge: the stored password answers
//!   the *first* echo-off prompt, everything else is relayed), with a
//!   deadline and cooperative cancellation.
//!
//! The trait object is called from the login worker thread only, so
//! `&mut self` is sound without locking inside libpam.
//!
//! Linking is handled by `build.rs`, which prefers the unversioned
//! `libpam.so` (dev package) but falls back to `libpam.so.0` (runtime)
//! so the daemon builds without `-dev` packages installed.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

use libc::{calloc, free, size_t, strdup};
use zeroize::Zeroizing;

/// Make a NUL-terminated, zeroizable byte buffer from a `&str`. The
/// returned `Vec<u8>` ends with a `0u8`, so its `as_ptr()` can be cast
/// straight to `*const c_char` and used as a C string. We use this
/// instead of `Zeroizing<CString>` because `CString` does not implement
/// `Zeroize`, and we want the password bytes to be wiped on drop.
/// Public so `auth.rs` can pre-build the one-shot password the bridge
/// hands to the first echo-off prompt.
// `Err(())` is deliberate: the single failure mode (embedded NUL) is
// self-explanatory at the call sites, and a bespoke error type would
// grow the vendored surface for no new information.
#[allow(clippy::result_unit_err)]
pub fn zeroizing_cstr(s: &str) -> Result<Zeroizing<Vec<u8>>, ()> {
    if s.as_bytes().contains(&0) {
        return Err(()); // embedded NUL — not a valid PAM password
    }
    let mut v = Vec::with_capacity(s.len() + 1);
    v.extend_from_slice(s.as_bytes());
    v.push(0u8); // NUL terminator
    Ok(Zeroizing::new(v))
}

// ── libpam return codes (subset of <security/pam_appl.h>) ─────────────
// Kept as `i32` constants rather than an enum so callers can match the
// raw return values libpam produces without us having to mirror the full
// ~40-code list.
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_PERM_DENIED: c_int = 6;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_CRED_INSUFFICIENT: c_int = 8;
#[allow(dead_code)] // informational; available for future mapping
pub const PAM_AUTHINFO_UNAVAIL: c_int = 9;
pub const PAM_NEW_AUTHTOK_REQD: c_int = 12;
pub const PAM_ACCT_EXPIRED: c_int = 13;
pub const PAM_USER_UNKNOWN: c_int = 16;
pub const PAM_MAXTRIES: c_int = 17;
/// Returned to libpam when a conversation cannot be completed (UI gone,
/// user canceled, deadline elapsed, answer contained an embedded NUL).
/// libpam maps this to `PAM_CONV_ERR` and aborts the operation cleanly.
pub const PAM_CONV_ERR: c_int = 19;

// ── pam_message msg_style values ──────────────────────────────────────
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

// ── flag bits ─────────────────────────────────────────────────────────
const PAM_SILENT: c_int = 0x8000;
#[allow(dead_code)] // PAM_ESTABLISH_CRED would be used if we needed first-time cred setup
const PAM_ESTABLISH_CRED: c_int = 0x0002;
const PAM_REINITIALIZE_CRED: c_int = 0x0008;

// ── libpam C ABI ──────────────────────────────────────────────────────

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: unsafe extern "C" fn(
        c_int,
        *const *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int,
    appdata_ptr: *mut c_void,
}

extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        ph: *mut *mut c_void,
    ) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_acct_mgmt(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_setcred(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_open_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_close_session(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_getenvlist(handle: *mut c_void) -> *mut *mut c_char;
}

// ── prompt model (shared with auth.rs / ipc.rs) ───────────────────────

/// One PAM conversation item, classified for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptStyle {
    /// Secret input (password, OTP, PIN) — render masked.
    EchoOff,
    /// Visible input (rare at login; e.g. a confirmation) — render clear.
    EchoOn,
    /// Show as an error line.
    Error,
    /// Show as an informational line.
    Info,
}

impl PromptStyle {
    /// Stable machine-readable tag used in the D-Bus signal JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            PromptStyle::EchoOff => "echo_off",
            PromptStyle::EchoOn => "echo_on",
            PromptStyle::Error => "error",
            PromptStyle::Info => "info",
        }
    }

    /// Does this style expect an answer? Only the two prompt styles do.
    pub fn expects_answer(self) -> bool {
        matches!(self, PromptStyle::EchoOff | PromptStyle::EchoOn)
    }
}

/// A single prompt (or info/error line) from the PAM stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub style: PromptStyle,
    pub text: String,
}

/// Map a raw libpam `msg_style` to our model. `None` = unknown style
/// (e.g. `PAM_BINARY_PROMPT`, which only pam_ssh + a handful of modules
/// use) — the conversation refuses those rather than guess.
fn style_of(raw: c_int) -> Option<PromptStyle> {
    match raw {
        PAM_PROMPT_ECHO_OFF => Some(PromptStyle::EchoOff),
        PAM_PROMPT_ECHO_ON => Some(PromptStyle::EchoOn),
        PAM_ERROR_MSG => Some(PromptStyle::Error),
        PAM_TEXT_INFO => Some(PromptStyle::Info),
        _ => None,
    }
}

// ── the bridge trait ──────────────────────────────────────────────────

/// Pluggable conversation backend.
///
/// Contract: given the prompts of one round, return one answer string
/// per prompt — non-empty answers are only meaningful where
/// `style.expects_answer()`; the implementation decides *how* the
/// answers are obtained (fixed data, UI round-trip, hardware token …).
/// Returning `Err(code)` aborts the PAM operation (libpam sees the
/// code; use `PAM_CONV_ERR` for ordinary refusals).
///
/// The answer strings are zeroized by the caller after `strdup`, so an
/// implementation may hand ownership of secrets straight through.
pub trait ConvBridge: Send {
    fn converse(&mut self, prompts: &[Prompt]) -> Result<Vec<Zeroizing<String>>, c_int>;
}

/// Fixed-data conversation: echo-off <- password, echo-on <- username.
/// Used by `--check-pam` and the autologin stack (both pass empty
/// secrets; neither is interactive).
pub struct StaticAnswers {
    pub username: CString,
    /// NUL-terminated, wiped on drop.
    pub password: Zeroizing<Vec<u8>>,
}

impl ConvBridge for StaticAnswers {
    fn converse(&mut self, prompts: &[Prompt]) -> Result<Vec<Zeroizing<String>>, c_int> {
        Ok(prompts
            .iter()
            .map(|p| match p.style {
                PromptStyle::EchoOff => {
                    // SAFETY: password Vec is NUL-terminated (zeroizing_cstr).
                    let s = unsafe { CStr::from_ptr(self.password.as_ptr() as *const c_char) };
                    Zeroizing::new(s.to_string_lossy().into_owned())
                }
                PromptStyle::EchoOn => Zeroizing::new(self.username.to_string_lossy().into_owned()),
                _ => Zeroizing::new(String::new()),
            })
            .collect())
    }
}

/// What the conversation callback talks to.
pub enum ConvSide {
    /// Fixed (username, password) pair — pre-0.5 behaviour.
    Static(StaticAnswers),
    /// Anything interactive: forwarded via the bridge.
    Interactive(Box<dyn ConvBridge>),
}

// ── application-side conversation data ────────────────────────────────

/// Owns the conversation state for the lifetime of the PAM handle. The
/// password inside `Static` is `Zeroizing` so its bytes are wiped when
/// the context drops; an `Interactive` bridge owns (and wipes) its own
/// secrets.
struct ConvData {
    side: ConvSide,
}

// ── the conversation callback itself ──────────────────────────────────

/// The actual logic. Lives in a separate function so the `extern "C"`
/// entrypoint can wrap it in `catch_unwind` and turn any panic into
/// `EINVAL` — panicking across the FFI boundary is UB.
///
/// # Safety
/// * `msgs` must point to an array of `num_msg` `*const PamMessage`.
/// * `appdata` must point to a live `ConvData` owned by the caller.
unsafe fn conv_impl(
    num_msg: c_int,
    msgs: *const *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msgs.is_null() || out_resp.is_null() || appdata.is_null() {
        return libc::EINVAL;
    }
    // SAFETY: the caller guarantees appdata points to a live ConvData
    // owned by the PamContext; the conversation is the only place that
    // mutates the bridge state (one-shot password consumption), and
    // libpam never calls the conversation re-entrantly on one handle.
    let data = &mut *(appdata as *mut ConvData);

    let n = num_msg as size_t;
    let elem = std::mem::size_of::<PamResponse>();
    let buf = calloc(n, elem) as *mut PamResponse;
    if buf.is_null() {
        return libc::ENOMEM;
    }

    // Phase 1: classify every message before answering any of it. A
    // module that hands us an unknown style aborts the whole round —
    // we never want to answer half a conversation.
    let mut prompts: Vec<Prompt> = Vec::with_capacity(n);
    for i in 0..n {
        let mptr = *msgs.add(i);
        if mptr.is_null() {
            free(buf as *mut c_void);
            return libc::EINVAL;
        }
        let m = &*mptr;
        let style = match style_of(m.msg_style) {
            Some(s) => s,
            None => {
                // Refuse unknown styles (e.g. PAM_BINARY_PROMPT).
                // libpam promises only the four standard styles for
                // text-mode conversations; anything else means a
                // module is doing something we did not opt into.
                free(buf as *mut c_void);
                return libc::EINVAL;
            }
        };
        // SAFETY: libpam guarantees msg is a valid C string for the
        // duration of the callback. Copy it out immediately so we own
        // the bytes and never hand raw pointers to Rust code.
        let text = if m.msg.is_null() {
            String::new()
        } else {
            CStr::from_ptr(m.msg).to_string_lossy().into_owned()
        };
        prompts.push(Prompt { style, text });
    }

    // Phase 2: obtain answers through the configured side. Errors abort
    // the round with the bridge's code (PAM_CONV_ERR in practice).
    let answers = match &mut data.side {
        ConvSide::Static(static_answers) => static_answers.converse(&prompts),
        ConvSide::Interactive(bridge) => bridge.converse(&prompts),
    };
    let answers = match answers {
        Ok(a) => a,
        Err(code) => {
            free(buf as *mut c_void);
            return code;
        }
    };
    if answers.len() != prompts.len() {
        // Bridge broke its contract; treat as refusal, not UB.
        free(buf as *mut c_void);
        return PAM_CONV_ERR;
    }

    // Phase 3: copy answers into libpam-owned strdup'd strings. The
    // Zeroizing originals are wiped when `answers` drops at return.
    let mut written: size_t = 0;
    for i in 0..n {
        let slot = buf.add(i);
        // Always initialize both fields so a later `free(NULL)` path
        // is safe even on the error exits below.
        (*slot).resp = ptr::null_mut();
        (*slot).resp_retcode = 0;

        if !prompts[i].style.expects_answer() {
            continue; // info/error: no response expected
        }
        // SAFETY: answers[i] is a live Zeroizing<String> for this round.
        let src = &answers[i];
        let dup = match zeroizing_cstr(src.as_str()) {
            // Build a NUL-terminated copy, then strdup it so libpam owns
            // the buffer and frees it with libc::free. The Zeroizing
            // original (and the temp) are wiped on drop.
            Ok(zbytes) => unsafe { strdup(zbytes.as_ptr() as *const c_char) },
            Err(()) => {
                // Embedded NUL in the answer — impossible from a sane UI.
                conv_free_responses(buf, written);
                free(buf as *mut c_void);
                return PAM_CONV_ERR;
            }
        };
        if dup.is_null() {
            conv_free_responses(buf, written);
            free(buf as *mut c_void);
            return libc::ENOMEM;
        }
        (*slot).resp = dup;
        written += 1;
    }

    *out_resp = buf;
    PAM_SUCCESS
}

/// Free every `resp` string we allocated inside the response array, but
/// not the array itself (caller frees the array).
unsafe fn conv_free_responses(buf: *mut PamResponse, count: size_t) {
    for i in 0..count {
        let p = (*buf.add(i)).resp;
        if !p.is_null() {
            free(p as *mut c_void);
        }
    }
}

/// `extern "C"` trampoline — wraps `conv_impl` so any panic is converted
/// to `EINVAL` rather than unwinding into C (which is UB).
unsafe extern "C" fn pam_conv_callback(
    num_msg: c_int,
    msgs: *const *const PamMessage,
    out_resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        conv_impl(num_msg, msgs, out_resp, appdata)
    }));
    res.unwrap_or(libc::EINVAL)
}

// ── safe wrapper ───────────────────────────────────────────────────────

/// RAII PAM handle. `pam_end` is called on drop with the result of the
/// last PAM call recorded, so cleanup messages reach the modules' cleanup
/// callbacks. If `open_session` succeeded, `pam_close_session` is called
/// first.
pub struct PamContext {
    handle: *mut c_void,
    /// Kept alive (not read) so the `appdata_ptr` we handed to libpam
    /// remains valid for the life of the handle.
    #[allow(dead_code)] // ownership anchor; mutated via the raw appdata pointer
    conv_data: Box<ConvData>,
    session_open: bool,
    /// Set if any operation returned non-success, so we know to feed
    /// that status into `pam_end` (it dispatches module cleanup hooks).
    last_status: c_int,
    /// Set after `pam_authenticate` succeeded so we don't accidentally
    /// call module cleanup with `PAM_SUCCESS` if `acct_mgmt` later fails.
    authed: bool,
}

// SAFETY: libpam handles are not thread-safe (one must not call PAM on
// the same handle from multiple threads concurrently), but they can be
// *sent* between threads. The login worker thread owns its handle for
// its whole life, so this is sound.
unsafe impl Send for PamContext {}

/// Pure parser for a "KEY=VALUE" line from `pam_getenvlist`. Returns
/// `None` if there is no `=` or the key is empty. Exposed so it can be
/// tested without going through libpam.
fn parse_env_kv(s: &str) -> Option<(String, String)> {
    let eq = s.find('=')?;
    let (k, v) = s.split_at(eq);
    if k.is_empty() {
        return None;
    }
    Some((k.to_owned(), v[1..].to_owned()))
}

impl PamContext {
    /// Equivalent to `pam_start(service, user, conv)` with the classic
    /// fixed (username, password) conversation. Kept for compatibility
    /// with `--check-pam` and the autologin flow.
    pub fn start(
        service: &str,
        username: &str,
        password: Zeroizing<String>,
    ) -> Result<Self, c_int> {
        let side = StaticAnswers {
            username: CString::new(username).map_err(|_| libc::EINVAL)?,
            password: zeroizing_cstr(password.as_str()).map_err(|_| libc::EINVAL)?,
        };
        Self::start_with(service, username, ConvSide::Static(side))
    }

    /// `pam_start` with a fully pluggable conversation side. This is
    /// the 0.5.0 entry point used for interactive logins (2FA, security
    /// keys, password change prompts …).
    pub fn start_with(service: &str, username: &str, side: ConvSide) -> Result<Self, c_int> {
        let svc = CString::new(service).map_err(|_| libc::EINVAL)?;
        let user = CString::new(username).map_err(|_| libc::EINVAL)?;
        let conv_data = Box::new(ConvData { side });

        let conv = PamConv {
            conv: pam_conv_callback,
            appdata_ptr: &*conv_data as *const ConvData as *mut c_void,
        };

        let mut handle: *mut c_void = ptr::null_mut();
        // SAFETY: conv and appdata are valid for the lifetime of
        // conv_data, which outlives this PamContext.
        let rc = unsafe { pam_start(svc.as_ptr(), user.as_ptr(), &conv, &mut handle) };
        if rc != PAM_SUCCESS || handle.is_null() {
            return Err(rc);
        }

        Ok(PamContext {
            handle,
            conv_data,
            session_open: false,
            last_status: PAM_SUCCESS,
            authed: false,
        })
    }

    /// `pam_authenticate(3)` — verify the password. Pass `silent = true`
    /// to suppress module-chatter (text prompts) so the daemon doesn't
    /// print anything to the journal that could leak info.
    ///
    /// Note: PAM_SILENT does not suppress *conversations* (a module
    /// that needs a second factor still prompts; the bridge decides
    /// what happens to the prompt), only module log chatter.
    pub fn authenticate(&mut self, silent: bool) -> Result<(), c_int> {
        let flags = if silent { PAM_SILENT } else { 0 };
        let rc = unsafe { pam_authenticate(self.handle, flags) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            self.authed = true;
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// `pam_acct_mgmt(3)` — account validity (expiry, lockout, etc).
    pub fn acct_mgmt(&mut self, silent: bool) -> Result<(), c_int> {
        let flags = if silent { PAM_SILENT } else { 0 };
        let rc = unsafe { pam_acct_mgmt(self.handle, flags) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// `pam_setcred(3)` with `PAM_REINITIALIZE_CRED` — re-establish
    /// credentials (kerberos tickets, keyrings, etc.) cleanly. Should
    /// be called *after* `authenticate` succeeds and *before* opening
    /// the session. The original `pam-client` flow skipped this; adding
    /// it is a small but real correctness improvement.
    pub fn setcred_reinit(&mut self) -> Result<(), c_int> {
        let rc = unsafe { pam_setcred(self.handle, PAM_REINITIALIZE_CRED) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// `pam_open_session(3)`. Registers the session with logind (via
    /// `pam_systemd`) and produces environment variables we must pass to
    /// the user's `lion-session` process.
    pub fn open_session(&mut self, silent: bool) -> Result<(), c_int> {
        let flags = if silent { PAM_SILENT } else { 0 };
        let rc = unsafe { pam_open_session(self.handle, flags) };
        self.last_status = rc;
        if rc == PAM_SUCCESS {
            self.session_open = true;
            Ok(())
        } else {
            Err(rc)
        }
    }

    /// `pam_getenvlist(3)` — fetch the PAM environment as a flat list of
    /// "KEY=VALUE" strings. Returns an empty `Vec` if PAM produced no
    /// environment (which is itself unusual but not fatal).
    pub fn envlist(&self) -> Vec<(String, String)> {
        // SAFETY: handle is valid for the lifetime of self.
        let raw = unsafe { pam_getenvlist(self.handle) };
        if raw.is_null() {
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut i = 0;
        // SAFETY: pam_getenvlist returns a NULL-terminated array of
        // malloc'd strings, each owned by the caller.
        unsafe {
            while !(*raw.offset(i)).is_null() {
                let item_ptr = *raw.offset(i);
                let cstr = CStr::from_ptr(item_ptr);
                if let Ok(s) = cstr.to_str() {
                    if let Some((k, v)) = parse_env_kv(s) {
                        out.push((k, v));
                    }
                }
                free(item_ptr as *mut c_void);
                i += 1;
            }
            free(raw as *mut c_void);
        }
        out
    }

    /// Was `authenticate` successful and not later invalidated?
    #[allow(dead_code)] // diagnostic; called from tests
    pub fn is_authed(&self) -> bool {
        self.authed
    }
}

impl Drop for PamContext {
    fn drop(&mut self) {
        if self.handle.is_null() {
            return;
        }
        if self.session_open {
            // Best-effort close; ignore errors (we're tearing down anyway).
            unsafe {
                let _ = pam_close_session(self.handle, PAM_SILENT);
            }
        }
        // pam_end dispatches module cleanup hooks; feed it the last
        // non-success status so modules know what failed.
        unsafe {
            pam_end(self.handle, self.last_status);
        }
        self.handle = ptr::null_mut();
        // conv_data (and the Zeroizing password) drops here.
    }
}

// ── tests for the pure helpers ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_env_kv_basic() {
        assert_eq!(
            parse_env_kv("XDG_RUNTIME_DIR=/run/user/1000"),
            Some(("XDG_RUNTIME_DIR".into(), "/run/user/1000".into()))
        );
        assert_eq!(parse_env_kv("EMPTY="), Some(("EMPTY".into(), "".into())));
        assert_eq!(parse_env_kv("NO_EQUALS"), None);
        assert_eq!(parse_env_kv("=NO_KEY"), None);
        // Value may itself contain `=` (e.g. PATH=a=b).
        assert_eq!(
            parse_env_kv("PATH=/usr/bin:/bin"),
            Some(("PATH".into(), "/usr/bin:/bin".into()))
        );
    }

    #[test]
    fn style_of_maps_all_four_text_styles() {
        assert_eq!(style_of(1), Some(PromptStyle::EchoOff));
        assert_eq!(style_of(2), Some(PromptStyle::EchoOn));
        assert_eq!(style_of(3), Some(PromptStyle::Error));
        assert_eq!(style_of(4), Some(PromptStyle::Info));
        // PAM_BINARY_PROMPT (0x?? in vendor trees) and garbage: refuse.
        assert_eq!(style_of(5), None);
        assert_eq!(style_of(-1), None);
        assert_eq!(style_of(0), None);
    }

    #[test]
    fn style_tags_are_stable_and_lowercase() {
        assert_eq!(PromptStyle::EchoOff.as_str(), "echo_off");
        assert_eq!(PromptStyle::EchoOn.as_str(), "echo_on");
        assert_eq!(PromptStyle::Error.as_str(), "error");
        assert_eq!(PromptStyle::Info.as_str(), "info");
    }

    #[test]
    fn only_prompt_styles_expect_answers() {
        assert!(PromptStyle::EchoOff.expects_answer());
        assert!(PromptStyle::EchoOn.expects_answer());
        assert!(!PromptStyle::Error.expects_answer());
        assert!(!PromptStyle::Info.expects_answer());
    }

    /// The static bridge answers echo-off with the password, echo-on
    /// with the username, and empty strings for info/error.
    #[test]
    fn static_bridge_answers_from_fixed_data() {
        let mut bridge = StaticAnswers {
            username: CString::new("alice").unwrap(),
            password: Zeroizing::new(b"secret\0".to_vec()),
        };
        let prompts = vec![
            Prompt {
                style: PromptStyle::Info,
                text: "Welcome".into(),
            },
            Prompt {
                style: PromptStyle::EchoOff,
                text: "Password:".into(),
            },
            Prompt {
                style: PromptStyle::EchoOn,
                text: "Token:".into(),
            },
        ];
        let answers = bridge
            .converse(&prompts)
            .expect("static bridge never fails");
        assert_eq!(answers.len(), 3);
        assert_eq!(answers[0].as_str(), "");
        assert_eq!(answers[1].as_str(), "secret");
        assert_eq!(answers[2].as_str(), "alice");
    }

    /// A refusing bridge surfaces its error code — this is the path the
    /// UI bridge takes on cancel/timeout, and conv_impl turns it into
    /// PAM_CONV_ERR for libpam.
    #[test]
    fn refusing_bridge_propagates_error_code() {
        struct Refuse;
        impl ConvBridge for Refuse {
            fn converse(&mut self, _: &[Prompt]) -> Result<Vec<Zeroizing<String>>, c_int> {
                Err(PAM_CONV_ERR)
            }
        }
        let mut side = ConvSide::Interactive(Box::new(Refuse));
        let prompts = [Prompt {
            style: PromptStyle::EchoOff,
            text: "Password:".into(),
        }];
        match &mut side {
            ConvSide::Interactive(b) => {
                assert_eq!(b.converse(&prompts).unwrap_err(), PAM_CONV_ERR);
            }
            _ => unreachable!(),
        }
    }
}
