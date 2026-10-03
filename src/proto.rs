#![forbid(unsafe_code)]
//! UI socket protocol, version 1 (spec 01 §4).
//!
//! Wire format: one JSON object per line (JSON-lines), UTF-8, LF-delimited.
//! Every message carries `proto` (must be `1`) and a `request id`.
//!
//! Client → daemon (requests):
//! `{"proto":1,"id":1,"op":"ListUsers"}`
//! `{"proto":1,"id":2,"op":"ListSessions"}`
//! `{"proto":1,"id":3,"op":"StartAuth","user":"alice"}`
//! `{"proto":1,"id":4,"op":"AnswerPrompt","text":"…"}`   (text → [`Secret`])
//! `{"proto":1,"id":5,"op":"CancelAuth"}`
//! `{"proto":1,"id":6,"op":"Launch","session":"lion"}`
//! `{"proto":1,"id":7,"op":"Power","action":"poweroff"}`
//!
//! Daemon → client:
//! response `{"proto":1,"id":1,"ok":true,"result":{…}}`
//! error     `{"proto":1,"id":1,"ok":false,"error":{"code":"…","message":"…"}}`
//! event     `{"proto":1,"id":3,"event":"Prompt","kind":"secret","text":"Password:"}`
//!           `AuthResult{ok,reason}`, `Throttle{seconds}`
//!
//! Decoding is hand-validated (not derive-based) so every field is explicitly
//! bounded and unknown fields are rejected — this is the parser the fuzz
//! target exercises (spec §10).

use crate::secret::Secret;
use serde_json::{json, Value};

/// Protocol version implemented by this daemon.
pub const PROTO_VERSION: u64 = 1;

/// Hard cap on a single wire line (request) — passwords are bounded to 1024
/// bytes by `Secret`; 8 KiB leaves room for JSON overhead only.
pub const MAX_LINE_BYTES: usize = 8 * 1024;

/// Cap for identifier-ish strings (user names, session ids, actions).
pub const MAX_IDENT_BYTES: usize = 64;

/// Error codes used in `error.code`.
pub mod codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const BAD_PROTO: &str = "proto_version";
    pub const UNKNOWN_OP: &str = "unknown_op";
    pub const RATE_LIMITED: &str = "rate_limited";
    pub const BUSY: &str = "busy";
    pub const NO_SUCH_USER: &str = "no_such_user";
    pub const NOT_AUTHENTICATED: &str = "not_authenticated";
    pub const THROTTLED: &str = "throttled";
    pub const NOT_ALLOWED: &str = "not_allowed";
    pub const NO_SUCH_SESSION: &str = "no_such_session";
    pub const LAUNCH_FAILED: &str = "launch_failed";
    pub const POWER_DENIED: &str = "power_denied";
    pub const INTERNAL: &str = "internal";
}

/// `Power{reboot|poweroff|suspend}`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    Reboot,
    PowerOff,
    Suspend,
}

impl PowerAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            PowerAction::Reboot => "reboot",
            PowerAction::PowerOff => "poweroff",
            PowerAction::Suspend => "suspend",
        }
    }
}

/// A decoded client request. `id` is echoed back on the response and on
/// events belonging to that conversation — spec §4: "every message has a
/// request id".
#[derive(Debug, Clone)]
pub enum Request {
    ListUsers { id: u64 },
    ListSessions { id: u64 },
    StartAuth { id: u64, user: String },
    AnswerPrompt { id: u64, text: Secret },
    CancelAuth { id: u64 },
    Launch { id: u64, session: String },
    Power { id: u64, action: PowerAction },
}

impl Request {
    pub fn id(&self) -> u64 {
        match self {
            Request::ListUsers { id }
            | Request::ListSessions { id }
            | Request::StartAuth { id, .. }
            | Request::AnswerPrompt { id, .. }
            | Request::CancelAuth { id }
            | Request::Launch { id, .. }
            | Request::Power { id, .. } => *id,
        }
    }
}

/// Prompt kinds (spec §4): secret (echo off), visible (echo on),
/// info (informational), error (error message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind {
    Secret,
    Visible,
    Info,
    Error,
}

impl PromptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PromptKind::Secret => "secret",
            PromptKind::Visible => "visible",
            PromptKind::Info => "info",
            PromptKind::Error => "error",
        }
    }
}

/// Daemon → client event.
#[derive(Debug, Clone)]
pub enum Event {
    Prompt { kind: PromptKind, text: String },
    AuthResult { ok: bool, reason: String },
    Throttle { seconds: u64 },
}

impl Event {
    /// Serialise to a wire line (without trailing newline).
    pub fn to_wire(&self, id: u64) -> String {
        let ev = match self {
            Event::Prompt { kind, text } => json!({
                "event": "Prompt",
                "kind": kind.as_str(),
                "text": sanitize_text(text, 1024),
            }),
            Event::AuthResult { ok, reason } => json!({
                "event": "AuthResult",
                "ok": ok,
                "reason": sanitize_text(reason, 256),
            }),
            Event::Throttle { seconds } => json!({
                "event": "Throttle",
                "seconds": seconds,
            }),
        };
        let mut v = json!({ "proto": PROTO_VERSION, "id": id });
        if let (Some(dst), Some(src)) = (v.as_object_mut(), ev.as_object()) {
            for (k, val) in src {
                dst.insert(k.clone(), val.clone());
            }
        }
        v.to_string()
    }
}

/// Daemon → client response.
#[derive(Debug, Clone)]
pub enum Response {
    Ok {
        id: u64,
        result: Value,
    },
    Err {
        id: u64,
        code: &'static str,
        message: String,
    },
}

impl Response {
    pub fn ok(id: u64, result: Value) -> Self {
        Response::Ok { id, result }
    }

    pub fn err(id: u64, code: &'static str, message: impl Into<String>) -> Self {
        Response::Err {
            id,
            code,
            message: message.into(),
        }
    }

    pub fn to_wire(&self) -> String {
        match self {
            Response::Ok { id, result } => json!({
                "proto": PROTO_VERSION, "id": id, "ok": true, "result": result,
            })
            .to_string(),
            Response::Err { id, code, message } => json!({
                "proto": PROTO_VERSION, "id": id, "ok": false,
                "error": { "code": code, "message": sanitize_text(message, 256) },
            })
            .to_string(),
        }
    }
}

/// Decode failure: `fatal` errors (bad proto) close the connection;
/// field-level failures are per-request. `id` is the request id when it
/// could be parsed (0 otherwise) so responses can echo it.
#[derive(Debug, Clone)]
pub struct DecodeError {
    pub fatal: bool,
    pub code: &'static str,
    pub message: String,
    pub id: u64,
}

/// Decode one request line. Strict: validates `proto`, bounds every field,
/// rejects unknown ops and unknown fields. Never allocates unbounded.
pub fn decode_request(line: &str) -> std::result::Result<Request, DecodeError> {
    let bad = |fatal: bool, code: &'static str, m: &str| {
        Err(DecodeError {
            fatal,
            code,
            message: m.to_string(),
            id: 0,
        })
    };

    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return bad(false, codes::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let map = match v {
        Value::Object(m) => m,
        _ => return bad(false, codes::BAD_REQUEST, "message must be a JSON object"),
    };

    let proto = match map.get("proto") {
        Some(Value::Number(n)) if n.as_u64() == Some(PROTO_VERSION) => PROTO_VERSION,
        Some(Value::Number(n)) => {
            return Err(DecodeError {
                fatal: true,
                code: codes::BAD_PROTO,
                message: format!("unsupported proto {} (server speaks {PROTO_VERSION})", n),
                id: 0,
            })
        }
        _ => return bad(true, codes::BAD_PROTO, "missing or non-numeric proto field"),
    };
    let _ = proto;

    let id = match map.get("id") {
        Some(Value::Number(n)) => match n.as_u64() {
            Some(i) => i,
            None => return bad(false, codes::BAD_REQUEST, "id must be an unsigned integer"),
        },
        _ => return bad(false, codes::BAD_REQUEST, "missing or non-numeric id field"),
    };
    // From here on errors can echo the parsed id.
    let bad_with_id = |fatal: bool, code: &'static str, m: String| {
        Err(DecodeError {
            fatal,
            code,
            message: m,
            id,
        })
    };

    let op = match map.get("op") {
        Some(Value::String(s)) => s.clone(),
        _ => {
            return bad_with_id(
                false,
                codes::BAD_REQUEST,
                "missing or non-string op field".into(),
            )
        }
    };

    match op.as_str() {
        "ListUsers" => {
            only_fields(&map, &["proto", "id", "op"], id)?;
            Ok(Request::ListUsers { id })
        }
        "ListSessions" => {
            only_fields(&map, &["proto", "id", "op"], id)?;
            Ok(Request::ListSessions { id })
        }
        "StartAuth" => {
            only_fields(&map, &["proto", "id", "op", "user"], id)?;
            let user = get_ident(&map, "user", id)?;
            Ok(Request::StartAuth { id, user })
        }
        "AnswerPrompt" => {
            only_fields(&map, &["proto", "id", "op", "text"], id)?;
            let text = match map.get("text") {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return bad_with_id(false, codes::BAD_REQUEST, "text must be a string".into())
                }
            };
            if text.len() > 1024 {
                return bad_with_id(
                    false,
                    codes::BAD_REQUEST,
                    "text too long (max 1024 bytes)".to_string(),
                );
            }
            let text = Secret::new(text);
            Ok(Request::AnswerPrompt { id, text })
        }
        "CancelAuth" => {
            only_fields(&map, &["proto", "id", "op"], id)?;
            Ok(Request::CancelAuth { id })
        }
        "Launch" => {
            only_fields(&map, &["proto", "id", "op", "session"], id)?;
            let session = get_ident(&map, "session", id)?;
            Ok(Request::Launch { id, session })
        }
        "Power" => {
            only_fields(&map, &["proto", "id", "op", "action"], id)?;
            let action = match map.get("action").and_then(Value::as_str) {
                Some("reboot") => PowerAction::Reboot,
                Some("poweroff") => PowerAction::PowerOff,
                Some("suspend") => PowerAction::Suspend,
                Some(other) => {
                    return bad_with_id(
                        false,
                        codes::BAD_REQUEST,
                        format!("unknown power action {other:?}"),
                    )
                }
                None => {
                    return bad_with_id(
                        false,
                        codes::BAD_REQUEST,
                        "action must be a string".into(),
                    )
                }
            };
            Ok(Request::Power { id, action })
        }
        other => bad_with_id(
            false,
            codes::UNKNOWN_OP,
            format!(
                "unknown op {other:?} (known: ListUsers, ListSessions, StartAuth, AnswerPrompt, CancelAuth, Launch, Power)"
            ),
        ),
    }
}

fn only_fields(
    map: &serde_json::Map<String, Value>,
    allowed: &[&str],
    id: u64,
) -> std::result::Result<(), DecodeError> {
    for k in map.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(DecodeError {
                fatal: false,
                code: codes::BAD_REQUEST,
                message: format!("unknown field {k:?} for this op"),
                id,
            });
        }
    }
    Ok(())
}

fn get_ident(
    map: &serde_json::Map<String, Value>,
    field: &str,
    id: u64,
) -> std::result::Result<String, DecodeError> {
    let err = |m: String| DecodeError {
        fatal: false,
        code: codes::BAD_REQUEST,
        message: m,
        id,
    };
    let s = match map.get(field).and_then(Value::as_str) {
        Some(s) => s,
        None => return Err(err(format!("{field} must be a string"))),
    };
    if s.is_empty() || s.len() > MAX_IDENT_BYTES {
        return Err(err(format!("{field} length must be 1..={MAX_IDENT_BYTES}")));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ' '))
    {
        return Err(err(format!("{field} contains unsupported characters")));
    }
    Ok(s.to_string())
}

/// Outgoing text is sanitised: control characters (except `\n`, folded to a
/// space) are dropped and the string is length-bounded. Prevents terminal
/// escapes / journald control bytes from ever reaching the UI.
pub fn sanitize_text(s: &str, cap: usize) -> String {
    let mut out = String::with_capacity(s.len().min(cap));
    for c in s.chars().take(cap) {
        match c {
            '\n' | '\t' => out.push(' '),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> std::result::Result<Request, DecodeError> {
        decode_request(s)
    }

    #[test]
    fn all_seven_ops_decode() {
        assert!(matches!(
            dec(r#"{"proto":1,"id":1,"op":"ListUsers"}"#),
            Ok(Request::ListUsers { id: 1 })
        ));
        assert!(matches!(
            dec(r#"{"proto":1,"id":2,"op":"ListSessions"}"#),
            Ok(Request::ListSessions { id: 2 })
        ));
        let r = dec(r#"{"proto":1,"id":3,"op":"StartAuth","user":"alice"}"#).unwrap();
        match r {
            Request::StartAuth { id, user } => {
                assert_eq!((id, user.as_str()), (3, "alice"));
            }
            _ => panic!("wrong variant"),
        }
        let r = dec(r#"{"proto":1,"id":4,"op":"AnswerPrompt","text":"pw"}"#).unwrap();
        let debug = format!("{r:?}");
        match r {
            Request::AnswerPrompt { id, text } => {
                assert_eq!(id, 4);
                assert_eq!(text.as_str(), "pw");
            }
            _ => panic!("wrong variant"),
        }
        assert!(!debug.contains("pw"));
        assert!(matches!(
            dec(r#"{"proto":1,"id":5,"op":"CancelAuth"}"#),
            Ok(Request::CancelAuth { id: 5 })
        ));
        let r = dec(r#"{"proto":1,"id":6,"op":"Launch","session":"lion"}"#).unwrap();
        assert!(matches!(r, Request::Launch { id: 6, ref session } if session == "lion"));
        let r = dec(r#"{"proto":1,"id":7,"op":"Power","action":"suspend"}"#).unwrap();
        assert!(matches!(
            r,
            Request::Power {
                id: 7,
                action: PowerAction::Suspend
            }
        ));
    }

    #[test]
    fn rejects_bad_proto() {
        let e = dec(r#"{"proto":2,"id":1,"op":"ListUsers"}"#).unwrap_err();
        assert!(e.fatal);
        assert_eq!(e.code, codes::BAD_PROTO);
        let e = dec(r#"{"id":1,"op":"ListUsers"}"#).unwrap_err();
        assert!(e.fatal);
        assert_eq!(e.code, codes::BAD_PROTO);
    }

    #[test]
    fn rejects_unknown_op_and_fields() {
        let e = dec(r#"{"proto":1,"id":1,"op":"Explode"}"#).unwrap_err();
        assert!(!e.fatal);
        assert_eq!(e.code, codes::UNKNOWN_OP);
        assert_eq!(e.id, 1);
        let e = dec(r#"{"proto":1,"id":1,"op":"ListUsers","extra":1}"#).unwrap_err();
        assert_eq!(e.code, codes::BAD_REQUEST);
        // the id is echoed back on field-level errors
        assert_eq!(e.id, 1);
    }

    #[test]
    fn bounds_idents_and_text() {
        let long_user = "u".repeat(65);
        let s = format!(r#"{{"proto":1,"id":1,"op":"StartAuth","user":"{long_user}"}}"#);
        assert!(dec(&s).is_err());
        assert!(dec(r#"{"proto":1,"id":1,"op":"StartAuth","user":"a;b"}"#).is_err());
        let long_text = "x".repeat(1025);
        let s = format!(r#"{{"proto":1,"id":1,"op":"AnswerPrompt","text":"{long_text}"}}"#);
        assert!(dec(&s).is_err());
    }

    #[test]
    fn malformed_json_is_not_fatal_for_connection() {
        let e = dec("not json").unwrap_err();
        assert!(!e.fatal);
        assert_eq!(e.code, codes::BAD_REQUEST);
        assert_eq!(e.id, 0);
    }

    #[test]
    fn events_and_responses_serialize() {
        let e = Event::Prompt {
            kind: PromptKind::Secret,
            text: "Password:".into(),
        };
        let w = e.to_wire(9);
        assert!(w.contains(r#""proto":1"#));
        assert!(w.contains(r#""event":"Prompt""#));
        assert!(w.contains(r#""kind":"secret""#));

        let r = Response::err(3, codes::THROTTLED, "try again in 30 s");
        let w = r.to_wire();
        assert!(w.contains(r#""ok":false"#));
        assert!(w.contains(r#""code":"throttled""#));

        let r = Response::ok(3, serde_json::json!({"a": 1}));
        assert!(r.to_wire().contains(r#""ok":true"#));
    }

    #[test]
    fn sanitize_strips_control_chars() {
        assert_eq!(sanitize_text("a\u{1b}[0mb\nc", 100), "a[0mb c");
        assert_eq!(sanitize_text(&"x".repeat(300), 10), "xxxxxxxxxx");
    }
}
