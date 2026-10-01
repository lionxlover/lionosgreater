//! logind seat/session bridge: fast user switching for the UI.
//!
//! GDM, SDDM and LightDM all offer "switch user" — the ability to park
//! your session on one VT and go back to the greeter for someone else.
//! The mechanism underneath is always the same: logind seats and VT
//! activation. 0.5.0 exposed none of it; 0.6.0 exposes exactly the two
//! primitives a switcher needs:
//!
//! * [`list_sessions`] — who is logged in, on which seat, which session
//!   is active (the data behind the "2 users signed in" UI).
//! * [`switch_to_vt`] / [`activate_session`] — go there.
//!
//! # Design
//! All calls go through the *documented* `org.freedesktop.login1.Manager`
//! interface with dynamic `call_method` invocations — no proxy codegen,
//! no new dependencies, and no build-time coupling to any systemd
//! version. `ListSessions`' reply signature changed across systemd
//! releases (the trailing field moved from tty to state and grew an
//! object path), so the parser reads the first five fields positionally
//! and ignores the rest: it works on every logind since 2014.
//!
//! # Failure policy
//! logind absent (non-systemd machine, minimal container), bus hiccup,
//! permission refusal — every path returns `Err(String)` with a
//! journal-able reason. The greeter keeps serving logins: seat
//! switching is a feature, never a dependency.

use serde::Serialize;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zbus::zvariant::Value;

pub const LOGIND_NAME: &str = "org.freedesktop.login1";
pub const MANAGER_PATH: &str = "/org/freedesktop/login1";
pub const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";

// ── reachability cache ─────────────────────────────────────────────────

/// Last logind reachability observation with its timestamp, written by
/// every caller that actually talked (or failed to talk) to logind.
/// Read with an age bound by [`last_logind_state`].
static LOGIND_STATE: Mutex<Option<(Instant, bool)>> = Mutex::new(None);

/// Record a logind reachability observation (called by `serve()`, the
/// seat watcher, and the seat D-Bus methods).
pub fn note_logind(reachable: bool) {
    let mut g = LOGIND_STATE.lock().unwrap_or_else(|e| e.into_inner());
    *g = Some((Instant::now(), reachable));
}

/// The cached reachability if fresher than `max_age`, else `None`
/// (unknown — callers treat unknown as absent and probe again).
pub fn last_logind_state(max_age: Duration) -> Option<bool> {
    let g = LOGIND_STATE.lock().unwrap_or_else(|e| e.into_inner());
    g.filter(|(at, _)| at.elapsed() < max_age).map(|(_, ok)| ok)
}

/// One entry of the UI's "who is signed in" list.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SeatSession {
    /// logind session id ("2", "c3", ...).
    pub id: String,
    pub uid: u32,
    pub username: String,
    /// Seat name, "" for sessionless/background sessions.
    pub seat: String,
    /// "user", "greeter", "background", "lock-screen".
    pub class: String,
    /// True when this is the session the user is looking at right now.
    pub active: bool,
}

// ── logind calls ───────────────────────────────────────────────────────

/// True when a functioning logind is reachable on the system bus.
/// Used to decide whether to advertise the seat-switching capability
/// and whether to poll for `SessionsChanged` relays.
pub async fn logind_present(conn: &zbus::Connection) -> bool {
    list_sessions(conn).await.is_ok()
}

/// `Manager.ListSessions` + active-session resolution. Errors carry a
/// short human reason (bus refused / logind missing); both are normal
/// on non-systemd hosts.
pub async fn list_sessions(conn: &zbus::Connection) -> Result<Vec<SeatSession>, String> {
    let msg = conn
        .call_method(
            Some(LOGIND_NAME),
            MANAGER_PATH,
            Some(MANAGER_IFACE),
            "ListSessions",
            &(),
        )
        .await
        .map_err(|e| format!("logind ListSessions failed: {e}"))?;
    // The deserialized Value borrows from the Message's Body, so both
    // must outlive the parse — bind them, don't chain temporaries.
    let body = msg.body();
    let value: Value = body
        .deserialize()
        .map_err(|e| format!("ListSessions reply undecodable: {e}"))?;
    let mut sessions = parse_sessions(&value).ok_or("ListSessions reply shape unexpected")?;
    resolve_active(conn, &mut sessions).await;
    Ok(sessions)
}

/// `Manager.SwitchVT` — jump the seat's console to `vt`. The greeter is
/// root, so logind permits it; failure means "VT not switchable now".
pub async fn switch_to_vt(conn: &zbus::Connection, vt: u32) -> Result<(), String> {
    conn.call_method(
        Some(LOGIND_NAME),
        MANAGER_PATH,
        Some(MANAGER_IFACE),
        "SwitchVT",
        &vt,
    )
    .await
    .map_err(|e| format!("SwitchVT({vt}) refused: {e}"))?;
    Ok(())
}

/// `Manager.ActivateSession` — switch to a specific session (its seat
/// and VT follow).
pub async fn activate_session(conn: &zbus::Connection, id: &str) -> Result<(), String> {
    conn.call_method(
        Some(LOGIND_NAME),
        MANAGER_PATH,
        Some(MANAGER_IFACE),
        "ActivateSession",
        &id,
    )
    .await
    .map_err(|e| format!("ActivateSession({id}) refused: {e}"))?;
    Ok(())
}

/// `Manager.LockSession` — ask another user's session to lock itself
/// (best-effort; sessions without a locker just ignore it).
pub async fn lock_session(conn: &zbus::Connection, id: &str) -> Result<(), String> {
    conn.call_method(
        Some(LOGIND_NAME),
        MANAGER_PATH,
        Some(MANAGER_IFACE),
        "LockSession",
        &id,
    )
    .await
    .map_err(|e| format!("LockSession({id}) refused: {e}"))?;
    Ok(())
}

// ── parsing ────────────────────────────────────────────────────────────

/// Parse `a(sussss[s|o]…)` logind session records, positionally:
/// (id, uid, username, seat, class, …ignored). Returns None for
/// anything that is not an array of structures with five leading
/// compatible fields — the caller treats that as "no sessions" rather
/// than guessing.
fn parse_sessions(v: &Value<'_>) -> Option<Vec<SeatSession>> {
    let Value::Array(arr) = v else {
        return None;
    };
    let mut out = Vec::with_capacity(arr.len());
    for item in arr.iter() {
        let Value::Structure(st) = item else {
            return None;
        };
        let fields = st.fields();
        if fields.len() < 5 {
            return None;
        }
        out.push(SeatSession {
            id: field_str(&fields[0])?,
            uid: field_u32(&fields[1])?,
            username: field_str(&fields[2])?,
            seat: field_str(&fields[3])?,
            class: field_str(&fields[4])?,
            active: false,
        });
    }
    Some(out)
}

fn field_str(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.to_string()),
        _ => None,
    }
}

fn field_u32(v: &Value<'_>) -> Option<u32> {
    match v {
        Value::U32(u) => Some(*u),
        _ => None,
    }
}

/// For every seat named in `sessions`, read `Seat.ActiveSession` and
/// mark the matching session `active`. One call per *distinct* seat
/// (usually exactly one). Any failure leaves everything `false` —
/// fail-open, never fatal.
async fn resolve_active(conn: &zbus::Connection, sessions: &mut [SeatSession]) {
    let seats: Vec<String> = {
        let mut s: Vec<String> = sessions
            .iter()
            .filter(|x| !x.seat.is_empty())
            .map(|x| x.seat.clone())
            .collect();
        s.sort();
        s.dedup();
        s
    };
    for seat in seats {
        // Object path is /org/freedesktop/login1/seat/<name>; seat
        // names are [a-z0-9]+ by logind construction, and we still
        // validate to keep the path un-injectable.
        if !seat
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            continue;
        }
        let Ok(path) =
            zbus::zvariant::ObjectPath::try_from(format!("/org/freedesktop/login1/seat/{seat}"))
        else {
            continue;
        };
        let Ok(reply) = conn
            .call_method(
                Some(LOGIND_NAME),
                path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.login1.Seat", "ActiveSession"),
            )
            .await
        else {
            continue;
        };
        let reply_body = reply.body();
        let Ok(active) = reply_body.deserialize::<Value>() else {
            continue;
        };
        // Get() replies wrap the value in a variant; unwrap any depth.
        let Some(active_path) = unwrap_object_path(&active) else {
            continue;
        };
        let active_id = active_path.rsplit('/').next().unwrap_or_default();
        for s in sessions.iter_mut() {
            if s.seat == seat && s.id == active_id {
                s.active = true;
            }
        }
    }
}

/// Extract an object path from a Value, unwrapping nested variants
/// (the `org.freedesktop.DBus.Properties.Get` wrapper shape) without
/// cloning: `Value::try_clone` exists but a two-arm recursion reads
/// better and borrows nothing.
fn unwrap_object_path(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Value(b) => unwrap_object_path(b),
        Value::ObjectPath(p) => Some(p.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zbus::zvariant::{Array, Signature, StructureBuilder};

    #[test]
    fn logind_state_cache_round_trip() {
        // Unknown before any observation (within this test process the
        // cache may have been touched by other tests, so set both
        // states and read back with a generous age).
        note_logind(true);
        assert_eq!(last_logind_state(Duration::from_secs(3600)), Some(true));
        note_logind(false);
        assert_eq!(last_logind_state(Duration::from_secs(3600)), Some(false));
        // A zero age bound means "never fresh enough".
        assert_eq!(last_logind_state(Duration::ZERO), None);
    }

    fn session_record(fields: Vec<Value<'static>>) -> Value<'static> {
        let mut b = StructureBuilder::new();
        for f in fields {
            b = b.append_field(f);
        }
        Value::Structure(b.build())
    }

    fn sessions_value(items: Vec<Value<'static>>) -> Value<'static> {
        let mut arr = Array::new(Signature::from_str_unchecked("(susssso)"));
        for item in items {
            arr.append(item).expect("append");
        }
        Value::Array(arr)
    }

    #[test]
    fn parses_current_systemd_signature() {
        // systemd >= 252: a(susssso) — trailing field is the object path.
        let v = sessions_value(vec![session_record(vec![
            Value::from("7"),
            Value::from(1000u32),
            Value::from("alice"),
            Value::from("seat0"),
            Value::from("user"),
            Value::from("active"), // trailing state string (systemd >= 252)
            Value::ObjectPath(
                zbus::zvariant::ObjectPath::try_from("/org/freedesktop/login1/session/7")
                    .expect("valid path"),
            ),
        ])]);
        let parsed = parse_sessions(&v).expect("parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "7");
        assert_eq!(parsed[0].uid, 1000);
        assert_eq!(parsed[0].username, "alice");
        assert_eq!(parsed[0].seat, "seat0");
        assert_eq!(parsed[0].class, "user");
        assert!(!parsed[0].active);
    }

    #[test]
    fn parses_legacy_systemd_signature() {
        // Old systemd: a(sussss) — trailing field was the tty.
        let mut arr = Array::new(Signature::from_str_unchecked("(sussss)"));
        let rec = StructureBuilder::new()
            .append_field(Value::from("c2"))
            .append_field(Value::from(42u32))
            .append_field(Value::from("greeter"))
            .append_field(Value::from("seat1"))
            .append_field(Value::from("greeter"))
            .append_field(Value::from("tty1"))
            .build();
        arr.append(Value::Structure(rec)).unwrap();
        let parsed = parse_sessions(&Value::Array(arr)).expect("parses");
        assert_eq!(parsed[0].id, "c2");
        assert_eq!(parsed[0].class, "greeter");
        // Sixth field (tty) silently ignored.
    }

    #[test]
    fn non_array_reply_is_rejected_not_panicked() {
        assert!(parse_sessions(&Value::from("nope")).is_none());
        assert!(parse_sessions(&Value::from(3u32)).is_none());
        // Array of non-structures is also a shape violation.
        let mut arr = Array::new(Signature::from_str_unchecked("s"));
        arr.append(Value::from("x")).unwrap();
        assert!(parse_sessions(&Value::Array(arr)).is_none());
    }

    #[test]
    fn wrong_field_types_are_rejected() {
        // uid in the wrong type position → None (defensive, no panic).
        let rec = StructureBuilder::new()
            .append_field(Value::from("1"))
            .append_field(Value::from("1000")) // str where u32 belongs
            .append_field(Value::from("u"))
            .append_field(Value::from("seat0"))
            .append_field(Value::from("user"))
            .build();
        // The array's element signature matches the (malformed) record
        // so the fixture constructs; parse_sessions must still refuse
        // it positionally.
        let mut arr = Array::new(Signature::from_str_unchecked("(sssss)"));
        arr.append(Value::Structure(rec)).unwrap();
        assert!(parse_sessions(&Value::Array(arr)).is_none());
    }

    #[test]
    fn too_few_fields_rejected() {
        let rec = StructureBuilder::new()
            .append_field(Value::from("1"))
            .append_field(Value::from(1000u32))
            .build();
        let mut arr = Array::new(Signature::from_str_unchecked("(su)"));
        arr.append(Value::Structure(rec)).unwrap();
        assert!(parse_sessions(&Value::Array(arr)).is_none());
    }

    #[test]
    fn empty_list_is_valid() {
        let v = sessions_value(vec![]);
        assert_eq!(parse_sessions(&v), Some(vec![]));
    }

    #[test]
    fn multiple_sessions_all_parsed() {
        let path = |s: &str| {
            Value::ObjectPath(
                zbus::zvariant::ObjectPath::try_from(format!(
                    "/org/freedesktop/login1/session/{s}"
                ))
                .expect("valid path"),
            )
        };
        let v = sessions_value(vec![
            session_record(vec![
                Value::from("2"),
                Value::from(1000u32),
                Value::from("alice"),
                Value::from("seat0"),
                Value::from("user"),
                Value::from("active"),
                path("2"),
            ]),
            session_record(vec![
                Value::from("c1"),
                Value::from(998u32),
                Value::from("lion-login"),
                Value::from("seat0"),
                Value::from("greeter"),
                Value::from("online"),
                path("c1"),
            ]),
            session_record(vec![
                Value::from("3"),
                Value::from(1001u32),
                Value::from("bob"),
                Value::from(""), // no seat: background session
                Value::from("background"),
                Value::from("closing"),
                path("3"),
            ]),
        ]);
        let parsed = parse_sessions(&v).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2].seat, "");
        assert_eq!(parsed[2].class, "background");
    }

    #[test]
    fn object_path_variant_unwrap() {
        let path_of = || {
            zbus::zvariant::ObjectPath::try_from("/org/freedesktop/login1/session/9")
                .expect("valid path")
        };
        assert_eq!(
            unwrap_object_path(&Value::ObjectPath(path_of())).as_deref(),
            Some("/org/freedesktop/login1/session/9")
        );
        assert!(unwrap_object_path(&Value::from("not a path")).is_none());
        // The Get() wrapper shape: Value::Value(Box<ObjectPath>),
        // including nesting.
        let wrapped = Value::Value(Box::new(Value::ObjectPath(path_of())));
        assert!(unwrap_object_path(&wrapped).is_some());
        let double = Value::Value(Box::new(wrapped));
        assert!(unwrap_object_path(&double).is_some());
    }
}
