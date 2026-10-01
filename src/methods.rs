//! Authentication-method availability probing.
//!
//! GDM's fprintd integration is, at the daemon level, exactly one
//! thing: *detect the second factor's presence and tell the UI*. SDDM
//! does it by shelling out; LightDM leaves it to the greeter UI. lion
//! 0.6.0 does it with two read-only probes — a PAM-module file lookup
//! (is the *stack* able to speak this method?) and a bus name-owner
//! check (is the *service* up?) — and exposes the result as one JSON
//! property the UI renders as the fingerprint/smartcard/key logos.
//!
//! # What the probes mean
//! * `pam_module_present` — the module file exists in the PAM module
//!   directory. It does NOT mean the site's `/etc/pam.d/lion-greeter`
//!   references it; only the admin knows that. We report capability,
//!   not policy, and the UI copy says "available", never "enabled".
//! * `service_running` — the D-Bus name the method's userspace daemon
//!   owns (fprintd) is owned right now. Live state, re-probed on every
//!   `AuthMethods` property read, so a USB reader unplugged between
//!   two UI frames is reflected without restarting anything.
//!
//! # Failure policy
//! Every probe is a `Path::exists` / one bus call. Any failure is
//! "method unavailable" — never an error, never a login blocker.

use serde::Serialize;

/// PAM module directory candidates, in probe order. Covers glibc
/// multiarch layouts (Debian/Ubuntu, Fedora/RHEL, Arch, Alpine).
const PAM_MODULE_DIRS: &[&str] = &[
    "/usr/lib/security",
    "/usr/lib64/security",
    "/usr/lib/x86_64-linux-gnu/security",
    "/usr/lib/aarch64-linux-gnu/security",
];

/// Override for tests, alt-roots and recovery shells: a single
/// directory to probe instead of the standard four.
const PAM_MODULES_DIR_ENV: &str = "LION_GREETER_PAM_MODULES_DIR";

/// fprintd's bus name — the daemon behind Linux fingerprint auth.
const FPRINTD_NAME: &str = "org.freedesktop.fprintd";

/// Modules that speak each method. Two entries for a method mean
/// "either distro package satisfies it".
struct MethodSpec {
    id: &'static str,
    /// Human-facing method id used in the JSON contract.
    label: &'static str,
    modules: &'static [&'static str],
}

const METHODS: &[MethodSpec] = &[
    MethodSpec {
        id: "fingerprint",
        label: "fingerprint",
        modules: &["pam_fprintd.so", "pam_thinkfinger.so"],
    },
    MethodSpec {
        id: "smartcard",
        label: "smartcard",
        modules: &["pam_pkcs11.so", "pam_p11.so", "pam_sss.so"],
    },
    MethodSpec {
        id: "security-key",
        label: "security-key",
        modules: &["pam_u2f.so", "pam_fido2.so"],
    },
    MethodSpec {
        id: "face",
        label: "face",
        modules: &["pam_face_authentication.so", "pam_howl.so"],
    },
];

/// The JSON contract of the `AuthMethods` property:
/// `[{"method":"password","available":true}, ...]` plus, for probed
/// methods, the reason fields so the UI can render accurate states.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthMethod {
    pub method: &'static str,
    pub available: bool,
    /// True when a PAM module for the method is installed.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub pam_module_present: bool,
    /// True when the method's userspace daemon owns its bus name.
    /// Only fingerprint has one to ask about today.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub service_running: bool,
}

/// Probe every method. `fprintd_running` is supplied by the caller
/// (the IPC layer owns the bus connection); `None` = "no bus answer,
/// assume not running" — availability still counts if the module is
/// installed (a reader can be plugged in later).
pub fn auth_methods(fprintd_running: bool) -> Vec<AuthMethod> {
    let mut out = Vec::with_capacity(METHODS.len() + 1);

    // Password is the floor: PAM always speaks it, and the
    // conversation-forwarding surface (0.5.0) means multi-round
    // password flows work too.
    out.push(AuthMethod {
        method: "password",
        available: true,
        pam_module_present: true,
        service_running: false,
    });

    for spec in METHODS {
        let module_present = spec
            .modules
            .iter()
            .any(|m| module_dirs().iter().any(|d| d.join(m).is_file()));
        // p11-kit/pcsc smartcard daemons own no stable bus name, so
        // only fingerprint gets a live service check.
        let service_running = spec.id == "fingerprint" && fprintd_running;
        // "available" = the stack *could* ask for this method: module
        // installed, and (for fingerprint) the daemon alive. The UI
        // decides whether to draw the logo based on `available`.
        let available = if spec.id == "fingerprint" {
            module_present && service_running
        } else {
            module_present
        };
        out.push(AuthMethod {
            method: spec.label,
            available,
            pam_module_present: module_present,
            service_running,
        });
    }
    out
}

/// The one live bus probe: does fprintd own its name right now?
/// Uses the standard `org.freedesktop.DBus.NameHasOwner` request so
/// it works on any D-Bus daemon, not justdbus-broker/systemd.
pub async fn fprintd_running(conn: &zbus::Connection) -> bool {
    let Ok(reply) = conn
        .call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "NameHasOwner",
            &FPRINTD_NAME,
        )
        .await
    else {
        return false;
    };
    reply.body().deserialize::<bool>().unwrap_or(false)
}

fn module_dirs() -> Vec<std::path::PathBuf> {
    if let Some(d) = std::env::var_os(PAM_MODULES_DIR_ENV) {
        return vec![std::path::PathBuf::from(d)];
    }
    PAM_MODULE_DIRS
        .iter()
        .map(std::path::PathBuf::from)
        .collect()
}

/// Convenience: the JSON form used by the D-Bus property.
pub fn auth_methods_json(fprintd_running: bool) -> String {
    serde_json::to_string(&auth_methods(fprintd_running)).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sets the fixture module dir AND takes the global env lock (held
    /// for the whole test via the returned guard): `PAM_MODULES_DIR`
    /// is process-global and the harness runs tests in parallel.
    fn set_mod_dir(tag: &str) -> (std::path::PathBuf, std::sync::MutexGuard<'static, ()>) {
        let _g = crate::test_env_lock();
        let d = std::env::temp_dir().join(format!(
            "lion-methods-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var(PAM_MODULES_DIR_ENV, &d);
        (d, _g)
    }

    fn clear_mod_dir(d: &std::path::Path) {
        std::env::remove_var(PAM_MODULES_DIR_ENV);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn password_is_always_available() {
        let (d, _lock) = set_mod_dir("pw");
        let m = auth_methods(false);
        let pw = m.iter().find(|x| x.method == "password").unwrap();
        assert!(pw.available);
        assert!(pw.pam_module_present);
        clear_mod_dir(&d);
    }

    #[test]
    fn empty_module_dir_means_only_password() {
        let (d, _lock) = set_mod_dir("empty");
        let m = auth_methods(true);
        assert!(m.iter().all(|x| x.method == "password" || !x.available));
        clear_mod_dir(&d);
    }

    #[test]
    fn fprintd_module_without_daemon_is_unavailable_but_flagged() {
        let (d, _lock) = set_mod_dir("fprint-nod");
        std::fs::write(d.join("pam_fprintd.so"), b"").unwrap();
        let m = auth_methods(false);
        let fp = m.iter().find(|x| x.method == "fingerprint").unwrap();
        assert!(fp.pam_module_present);
        assert!(!fp.available, "daemon down = not offered");
        assert!(!fp.service_running);
        clear_mod_dir(&d);
    }

    #[test]
    fn fprintd_module_with_daemon_is_available() {
        let (d, _lock) = set_mod_dir("fprint-yes");
        std::fs::write(d.join("pam_fprintd.so"), b"").unwrap();
        let m = auth_methods(true);
        let fp = m.iter().find(|x| x.method == "fingerprint").unwrap();
        assert!(fp.available);
        assert!(fp.service_running);
        clear_mod_dir(&d);
    }

    #[test]
    fn smartcard_variants_each_satisfy() {
        for (tag, module) in [
            ("pkcs11", "pam_pkcs11.so"),
            ("p11", "pam_p11.so"),
            ("sss", "pam_sss.so"),
        ] {
            let (d, _lock) = set_mod_dir(tag);
            std::fs::write(d.join(module), b"").unwrap();
            let m = auth_methods(false);
            let sc = m.iter().find(|x| x.method == "smartcard").unwrap();
            assert!(sc.pam_module_present, "{module}");
            assert!(sc.available, "no service check for smartcard");
            clear_mod_dir(&d);
        }
    }

    #[test]
    fn security_key_modules() {
        let (d, _lock) = set_mod_dir("u2f");
        std::fs::write(d.join("pam_u2f.so"), b"").unwrap();
        let m = auth_methods(false);
        let sk = m.iter().find(|x| x.method == "security-key").unwrap();
        assert!(sk.available);
        // fprintd's daemon state must not leak into other methods.
        assert!(!sk.service_running);
        clear_mod_dir(&d);
    }

    #[test]
    fn face_modules_optional() {
        let (d, _lock) = set_mod_dir("face");
        std::fs::write(d.join("pam_face_authentication.so"), b"").unwrap();
        let m = auth_methods(false);
        let f = m.iter().find(|x| x.method == "face").unwrap();
        assert!(f.available);
        clear_mod_dir(&d);
    }

    #[test]
    fn json_contract_is_stable() {
        let (d, _lock) = set_mod_dir("json");
        let json = auth_methods_json(false);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert!(!arr.is_empty());
        assert_eq!(arr[0]["method"], "password");
        assert_eq!(arr[0]["available"], true);
        // Skipped false fields keep the payload small: any method with
        // an unavailable module serializes without the flag fields.
        let compact = arr
            .iter()
            .map(|m| m.to_string())
            .find(|s| !s.contains("\"available\":true,\"pam_module_present\""))
            .expect("at least one unavailable method in an empty module dir");
        assert!(!compact.contains("\"service_running\""));
        clear_mod_dir(&d);
    }

    #[test]
    fn all_method_ids_are_ascii_snake_case() {
        // The ids go into JSON contracts; keep them machine-checkable.
        for spec in METHODS {
            assert!(
                spec.id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{}",
                spec.id
            );
        }
    }
}
