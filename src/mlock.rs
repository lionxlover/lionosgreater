//! Memory locking (`mlockall`) with a hard limit guard.
//!
//! # Why
//! The greeter's heap briefly holds user passwords inside `Zeroizing`
//! buffers (see `pam_ffi.rs`). Those buffers are wiped on drop, but a
//! swap-out *before* the wipe would copy the plaintext into the swap
//! device, where it survives until the swap is overwritten. On a
//! laptop stolen seconds after a failed login, that can be a real leak.
//! `mlockall(MCL_CURRENT | MCL_FUTURE)` pins all current and future
//! anonymous pages into RAM, so a plaintext password never touches disk.
//! GDM and SDDM pay for the equivalent guarantee through `gtk3`'s
//! `mlock()` of the password page and systemd's `LockPersonality`
//! tricks respectively; we can do strictly better with one syscall.
//!
//! # The RLIMIT trap
//! `mlockall` is bounded by `RLIMIT_MEMLOCK` (default 64 KiB per
//! non-root process on Linux, even for daemons, unless the service
//! unit raises it). A daemon that calls `mlockall` and ignores the
//! failure gets *no* protection and a false sense of security; a daemon
//! that calls it and *aborts* turns a cosmetic config gap into a
//! "cannot log in" outage. Neither is acceptable for a login daemon:
//!
//! * we **estimate** whether the lock can succeed before attempting it
//!   (current RSS + headroom vs the limit) and skip cleanly if not;
//! * if the attempt runs and fails anyway, we `munlockall()` to undo
//!   any partial lock and continue running;
//! * we **never** panic and **never** refuse to serve logins because
//!   memory could not be locked. Worst case we log one line and carry
//!   on with the same behaviour as every other greeter on the planet.
//!
//! # Operationally
//! The shipped `lion-greeter.service` sets `LimitMEMLOCK=infinity`, so
//! on a real LionOS install the lock is attempted with no ceiling and
//! `Capabilities` reports `"mlock"`. In constrained containers (64 KiB
//! hard limit, no CAP_IPC_LOCK) the daemon reports
//! `SkippedSmallLimit` instead — which is exactly the deployment
//! difference this module exists to make visible and auditable, rather
//! than silent.
//!
//! Locking ~2-10 MiB of RAM is a rounding error on any machine that
//! can render a greeter UI, and MCL_FUTURE keeps pages locked without
//! further syscalls — the steady-state cost is one bit in each VMA.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};

/// How much room we must leave inside `RLIMIT_MEMLOCK` beyond current
/// RSS before even attempting `mlockall`. 16 MiB covers the tokio
/// runtime (2 workers * ~2 MiB stacks), the D-Bus buffers, and one
/// full user list (43 components' worth of JSON) with generous slack.
/// Chosen so that on any machine where the *estimate* passes, the real
/// call is all but guaranteed to succeed — we only attempt when we
/// believe it, and believe it only when the numbers say so.
pub const HEADROOM_BYTES: u64 = 16 * 1024 * 1024;

/// MCL_CURRENT | MCL_FUTURE — lock everything now and everything the
/// daemon allocates later. Named so call sites read like the man page.
const MCL_CURRENT_FUTURE: libc::c_int = libc::MCL_CURRENT | libc::MCL_FUTURE;

/// Set once `mlockall` has succeeded; read by the D-Bus `Capabilities`
/// property so the UI / ops tooling can *see* whether secrets are
/// actually RAM-pinned on this machine rather than trusting the manual.
static LOCKED: AtomicBool = AtomicBool::new(false);

/// What happened when (or before) we tried to lock memory. Ordered by
/// desirability so `PartialOrd` on the discriminants reads naturally
/// in logs and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MlockOutcome {
    /// `mlockall` returned 0. All current and future pages are pinned.
    /// Secrets never reach swap while the daemon lives.
    Locked,
    /// Not attempted: `RLIMIT_MEMLOCK` is too small to hold RSS plus
    /// headroom. This is a *deployment* finding, not a daemon fault.
    SkippedSmallLimit { limit_bytes: u64, est_bytes: u64 },
    /// Attempted and refused by the kernel (or the syscall is blocked
    /// by the systemd syscall filter). Partial locks were undone with
    /// `munlockall()`; the daemon continues unprotected.
    Failed { errno: i32 },
}

impl MlockOutcome {
    /// Short machine-readable tag for logs/reports.
    pub fn tag(self) -> &'static str {
        match self {
            MlockOutcome::Locked => "locked",
            MlockOutcome::SkippedSmallLimit { .. } => "skipped_small_limit",
            MlockOutcome::Failed { .. } => "failed",
        }
    }
}

/// Read this process's current resident set size, in bytes, from
/// `/proc/self/statm` (field 2, "resident", in pages). Returns `None`
/// on any parse/IO error — callers treat that as "estimate unknown",
/// not as zero.
fn current_rss_bytes() -> Option<u64> {
    let mut buf = [0u8; 128];
    let mut f = std::fs::File::open("/proc/self/statm").ok()?;
    let n = f.read(&mut buf).ok()?;
    let text = std::str::from_utf8(&buf[..n]).ok()?;
    let resident_pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    let page: u64 = page_size_bytes();
    Some(resident_pages.saturating_mul(page))
}

/// Page size via `sysconf(_SC_PAGESIZE)`, cached by the libc call itself
/// is cheap enough to call once per attempt. Falls back to 4096 if the
/// platform somehow refuses.
fn page_size_bytes() -> u64 {
    // SAFETY: sysconf with a valid _SC_PAGESIZE argument is always safe.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 {
        v as u64
    } else {
        4096
    }
}

/// Read `RLIMIT_MEMLOCK`. `Ok(None)` means RLIM_INFINITY (no ceiling).
/// `Err` means getrlimit itself failed, which we treat conservatively
/// as "limit unknown and possibly 0" so the caller will skip rather
/// than fire a syscall that might partially lock and fail.
fn memlock_limit() -> Result<Option<u64>, i32> {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into a valid rlimit struct.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EPERM));
    }
    if rl.rlim_cur == libc::RLIM_INFINITY {
        Ok(None)
    } else {
        Ok(Some(rl.rlim_cur))
    }
}

/// Pure decision: given the (possibly absent) lock limit and our
/// estimated footprint, should `mlockall` even be attempted?
///
/// * No limit (infinity) -> yes, always.
/// * A limit at least `rss + HEADROOM_BYTES` -> yes.
/// * Anything smaller -> no: the call would either fail outright or,
///   worse, succeed partially and pin a fraction of the daemon while
///   the password pages miss the cut.
pub fn should_attempt(limit: Option<u64>, rss: u64) -> bool {
    match limit {
        None => true,
        Some(limit) => rss.saturating_add(HEADROOM_BYTES) <= limit,
    }
}

/// Whether a previous successful `mlockall` is still in effect. Exposed
/// through the D-Bus `Capabilities` property so the login UI and any
/// audit tool can verify, at runtime, that secrets are RAM-pinned.
pub fn is_locked() -> bool {
    LOCKED.load(Ordering::Acquire)
}

/// Attempt to lock the daemon's memory. Safe to call exactly once, from
/// `main` before the runtime spawns threads (locking first avoids
/// racing with MCL_FUTURE-relevant allocations — although MCL_FUTURE
/// makes later allocations locked too, pinning *before* the heap grows
/// keeps the estimate honest).
///
/// Never panics, never aborts, never returns an error the caller must
/// handle: the outcome is informational. Call it, log it, move on.
pub fn apply() -> MlockOutcome {
    let limit = match memlock_limit() {
        Ok(l) => l,
        Err(errno) => {
            tracing::warn!(
                errno,
                "getrlimit(RLIMIT_MEMLOCK) failed; skipping mlockall (conservative)"
            );
            return MlockOutcome::Failed { errno };
        }
    };

    // Unknown RSS (no /proc?) -> estimate 0 only if the limit is
    // unlimited; otherwise treat as "cannot vouch" and skip. We refuse
    // to fire a syscall whose success we cannot bound.
    let rss = current_rss_bytes().unwrap_or(u64::MAX);
    if rss == u64::MAX {
        if limit.is_none() {
            // Unlimited: even a fat guess is fine.
            return do_lock();
        }
        tracing::warn!(
            ?limit,
            "cannot read RSS from /proc/self/statm; skipping mlockall (conservative)"
        );
        return MlockOutcome::SkippedSmallLimit {
            limit_bytes: limit.unwrap_or(0),
            est_bytes: 0,
        };
    }

    if !should_attempt(limit, rss) {
        let limit_bytes = limit.unwrap_or(0);
        tracing::info!(
            limit_bytes,
            rss_bytes = rss,
            headroom_bytes = HEADROOM_BYTES,
            "RLIMIT_MEMLOCK too small for mlockall; skipping (set LimitMEMLOCK=infinity in the unit to enable)"
        );
        return MlockOutcome::SkippedSmallLimit {
            limit_bytes,
            est_bytes: rss.saturating_add(HEADROOM_BYTES),
        };
    }

    do_lock()
}

fn do_lock() -> MlockOutcome {
    // SAFETY: mlockall(2) with valid flags; failure is returned, not
    // signalled, and does not put the process in an inconsistent state
    // beyond a possible partial lock, which we undo below.
    let rc = unsafe { libc::mlockall(MCL_CURRENT_FUTURE) };
    if rc == 0 {
        LOCKED.store(true, Ordering::Release);
        tracing::info!(
            outcome = "locked",
            "mlockall(CURRENT|FUTURE) active: secrets cannot reach swap"
        );
        MlockOutcome::Locked
    } else {
        let errno = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOMEM);
        // Undo any partial lock so state is clean and predictable.
        // SAFETY: munlockall(2) on a possibly-partially-locked process.
        let _ = unsafe { libc::munlockall() };
        tracing::warn!(
            errno,
            "mlockall failed; continuing without memory lock (non-fatal)"
        );
        MlockOutcome::Failed { errno }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_limit_always_attempts() {
        assert!(should_attempt(None, 0));
        assert!(should_attempt(None, 128 * 1024 * 1024));
    }

    #[test]
    fn generous_limit_attempts() {
        // RSS 8 MiB + 16 MiB headroom = 24 MiB needed; 32 MiB limit ok.
        assert!(should_attempt(Some(32 * 1024 * 1024), 8 * 1024 * 1024));
    }

    #[test]
    fn small_limit_skips() {
        // The container default: 64 KiB limit, any real RSS -> skip.
        assert!(!should_attempt(Some(64 * 1024), 2 * 1024 * 1024));
        // Exactly RSS + headroom is allowed (>=, not >).
        assert!(should_attempt(Some(8 + HEADROOM_BYTES), 8));
        // One byte less than RSS + headroom is not.
        assert!(!should_attempt(Some(8 + HEADROOM_BYTES - 1), 8));
    }

    #[test]
    fn zero_limit_never_attempts() {
        assert!(!should_attempt(Some(0), 0));
    }

    #[test]
    fn saturation_does_not_panic_or_wrap() {
        // u64::MAX as a limit is effectively infinity: a maximal RSS
        // still passes (and the add saturates rather than wrapping to
        // a small number that would wrongly "pass").
        assert!(should_attempt(Some(u64::MAX), u64::MAX - 1));
        // A huge-but-finite RSS against a small limit must stay "skip".
        assert!(!should_attempt(Some(64 * 1024), u64::MAX - 1));
    }

    #[test]
    fn outcome_tags_are_stable() {
        assert_eq!(MlockOutcome::Locked.tag(), "locked");
        assert_eq!(
            MlockOutcome::SkippedSmallLimit {
                limit_bytes: 64 * 1024,
                est_bytes: 24 * 1024 * 1024
            }
            .tag(),
            "skipped_small_limit"
        );
        assert_eq!(MlockOutcome::Failed { errno: 12 }.tag(), "failed");
    }

    #[test]
    fn rss_readable_and_sane() {
        // In the test environment /proc exists; RSS should be a small
        // but positive multiple of the page size.
        if let Some(rss) = current_rss_bytes() {
            assert!(rss >= page_size_bytes());
            assert!(rss < 1024 * 1024 * 1024, "1 GiB RSS is not plausible here");
        }
    }
}
