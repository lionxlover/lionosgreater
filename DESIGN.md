# lion-greeter — DESIGN

Decisions, trade-offs and deferred items for spec 01, MVP + v1-partial
milestone. Companion documents: `README.md` (status matrix),
`docs/PROTOCOL.md` (wire format), `MIGRATION.md` (upgrade path).

## 1. Process & privilege model

```
root:  lion-greeter.service ── owns PAM, logind calls, setuid-exec
uid:   lion-greeter (user) ── lion-login-ui, connects to ui.sock
```

The spec asks for "an unprivileged greeter with only the PAM/exec step
privileged". Interpreting it literally would split the daemon into a
privileged helper plus an unprivileged frontend — two processes, one
extra IPC hop, and a second protocol to fuzz. Since the *only* consumer
of the socket is the UI (already unprivileged, already authenticated by
the kernel via SO_PEERCRED), the single privileged daemon is the
simpler, smaller attack surface: one process, one protocol, PAM never
crosses a trust boundary. The "unprivileged greeter" role is filled by
`lion-login-ui` running as the `lion-greeter` user.

Consequence: the unit's `CapabilityBoundingSet` is non-empty (SETUID,
SETGID, CHOWN, DAC_OVERRIDE, SYS_ADMIN for guest tmpfs, KILL) — each
justified in a comment in `packaging/lion-greeter.service`.

## 2. Unix socket instead of D-Bus

Spec §4 defines the UI interface as a local unix socket with a
JSON-lines protocol; the D-Bus boilerplate in §8/§9 ("treat every D-Bus
caller as untrusted", "ship D-Bus interface XML") is the generic
engineering template. Where both apply, §0 says the more specific file
wins. So: no D-Bus name is claimed, no D-Bus activation file is shipped;
socket activation is systemd-native (`lion-greeter.socket`), ownership
pinned by the manager (SocketUser/SocketGroup/SocketMode). zbus *is*
used — but as a client of logind (CreateSession, Reboot/PowerOff/Suspend),
which is the canonical D-Bus surface for those operations. If remote/
enterprise management (v2) needs a D-Bus API, it can be added additively
without touching proto 1.

## 3. PAM via dlopen, not a build-time binding

`pam::sys` resolves `libpam.so.0` at runtime with `RTLD_NOW|RTLD_LOCAL`.
Trade-offs:

- **Pro**: no `libpam-dev` build dependency (the crate builds anywhere,
  including cross and reproducible builders); a missing libpam is a
  clean, early, fail-closed startup error instead of a link failure;
  no vendor-locked `pam`/`pam-sys` crate version (both are stale in the
  ecosystem).
- **Con**: symbol/ABI drift is only caught at runtime. Mitigation:
  numeric constants are pinned to Linux-PAM 1.5.x headers in the audit
  box, and the nspawn CI job exercises the full stack.

The conversation callback runs on the auth worker thread and bridges to
the async server through two channels (`tokio` unbounded for events,
`std::sync::mpsc` behind a `Mutex` for answers). The mutex is
uncontended by construction: the callback and the worker's post-verdict
park loop are the same thread, and the two never hold the receiver at
the same time.

## 4. One worker thread per PAM transaction

PAM handles are not thread-safe, so each `StartAuth` spawns one worker
thread that owns `pam_start → authenticate → acct_mgmt → chauthtok →
setcred → pam_end` end-to-end. The thread parks after the verdict until
`Launch` (setcred) or teardown. This makes every lifetime question
trivially sound, at the cost of one thread per concurrent login attempt
(a greeter has exactly one).

**Known trade-off (spec §6 "PAM module hangs")**: a module that blocks
forever *without prompting* cannot be interrupted from outside. The
pump's watchdog declares the session timed out and the UI shows a
generic failure; the worker thread self-reaps if PAM ever returns; a
pathologically wedged module leaks exactly one parked thread. The
alternatives (SIGALRM into PAM, or cancelling the thread) are unsound
or impossible in portable Rust; this is the standard trade-off made by
GDM/SDDM-adjacent code too. Timed-out sessions do **not** count as
throttle failures (the PAM stack never completed, so `pam_faillock`
sees nothing either).

## 5. Throttle: soft, user-visible; hard enforcement stays with pam_faillock

Spec §3 delegates brute-force enforcement to `pam_faillock` and asks the
greeter to *surface* the lock-out. So the greeter keeps an in-memory,
per-user + per-connection-key exponential lock (1 s, 2 s, 4 s… capped),
emits `Throttle{seconds}` after failures and before a locked retry, and
denies `StartAuth` with `throttled` while locked. It never assumes it is
the only defence and never persists counters (fresh start = fresh grace,
same as faillock's unlock_time semantics).

## 6. Autologin / timed login go *through* PAM

Autologin uses a dedicated service (`lion-greeter-autologin`, shipped in
`packaging/pam/`) that permits only members of the `lion-autologin`
group. Missing stack or non-member → `ServiceError` → the daemon logs
it and falls back to the normal greeter. Autologin therefore cannot
bypass PAM policy, and the daemon's autologin is disabled-by-default
(`autologin.user = null`) exactly as the spec's config defaults say.
Timed login re-uses the same service: countdown prompts are plain
`Prompt{kind:info}` events, so the protocol stays spec-shaped; any
client request cancels the countdown.

## 7. Guest sessions

Guest = a pre-provisioned `lion-guest` system account + a tmpfs mounted
at `greeter.guest.home` (NOSUID|NODEV, size-capped, mode 0700) before
the session exec, with HOME pointed at the tmpfs. `umount2(MNT_DETACH)`
detaches lazily at the next guest launch/teardown. If the account or
the mount is missing, launch fails closed. The tmpfs mount is the
single reason the unit needs `CAP_SYS_ADMIN`; drop guest support and
the capability goes too.

## 8. Sessions & last choice

`/usr/share/wayland-sessions/*.desktop` (bounded INI parse, `TryExec`
checked, `Hidden`/`NoDisplay` honoured) plus the always-present builtin
`lion` session. A `.desktop` file whose stem is `lion` overrides the
builtin (richer metadata for the same session). The last choice is
persisted in the daemon's own `state_dir` (0700, root) instead of
writing into AccountsService's state: AccountsService is a foreign
daemon's database and writing it from outside races its own updates;
the greeter's store is read as a *fallback* only — AccountsService's
`Session=` (if present) still wins, so accountsservice-enabled tools
keep working. Exec lines support quoted arguments; `%`-placeholders are
rejected (fail closed) until a v2 need appears.

## 9. User enumeration

`/etc/passwd` is text-parsed (no NSS). This bounds the scan (a hung
SSSD socket can't wedge the greeter) and hides nothing from the UI that
remote users would show anyway — remote/SSSD logins are spec §11 v2;
when they land, enumeration moves behind a `UserDb` trait just like PAM
and logind already are. AccountsService data (icon, session, real name)
is merged opportunistically; the avatar path is passed as data and
never read by the daemon.

## 10. Secrets

- Answers decode straight into `Secret` (`Zeroizing<String>` wrapper,
  redacted `Debug`/`Display`, no `Serialize`).
- The raw JSON line is a `Zeroizing<String>`; the codec wipes error-path
  buffers.
- Inside the C callback the answer is copied into a `malloc`'d
  NUL-terminated buffer that PAM owns and frees (Linux-PAM overwrites
  its authtok copies); interior NUL answers are rejected rather than
  truncated.
- Nothing secret ever reaches `tracing`: log fields are user names,
  PAM codes, and timing.

## 11. Idle discipline (spec §7)

No periodic timers unless systemd armed `WATCHDOG_USEC` (the heartbeat
is the manager's liveness contract, not idle work — one timer at
`usec/2`). The timed-login countdown only exists while configured.
Workers block on channels; the accept loop blocks on epoll. Bench
numbers on the dev reference: startup ≈ 0.15 ms (budget 50 ms), idle
RSS ≈ 1.6 MB (budget 8 MB), mock auth round-trip ≈ 42 µs (budget:
< 20 ms *over PAM's own time*).

## 12. Protocol details worth writing down

- Every message carries `proto` and `id`; responses echo the request id
  even for decode errors (when the id parsed), so clients can correlate
  strictly.
- `proto` mismatch is the only *fatal* wire error (connection closed);
  everything else is a per-request error object.
- Events (`Prompt`, `AuthResult`, `Throttle`) carry the id of the
  `StartAuth` that opened the conversation; countdown infos use id 0.
- Boundaries: 8 KiB lines, 64-byte identifiers, 1024-byte answer text,
  64 msgs/s sustained per connection, per-op gaps (ListUsers 250 ms,
  StartAuth 200 ms, Power 1 s), floods drop the connection.
- Outgoing text is control-character-sanitised (no terminal escapes into
  whatever the UI renders).

## 13. Deferred (with reasons)

| Item | Milestone | Why deferred |
|---|---|---|
| Fingerprint/smartcard UI hints + automatic fallback logic | v1-full | plumbing exists (PAM stack ships `pam_fprintd.so`); needs UI-side affordance work |
| Throttle event for *pam_faillock* preauth denials specifically | v1-full | soft layer already surfaces lock-outs generically |
| logind session reuse ("switch to running session") | v2 | needs `ListSessions`-by-logind semantics + `ActivateSession` handoff protocol additions |
| SSSD/LDAP users | v2 | NSS-free enumeration is a deliberate MVP posture (§9) |
| Accessibility hooks | v2 | protocol needs an a11y event channel design |
| D-Bus management API | v2 if ever | §4 socket wins (§2 above) |

## 14. Testing strategy

- **Unit** (66): every parser/state machine — PAM mock scenarios
  (success, fail, expired, multi-prompt, timeout, service-error), codec
  bounds/zeroization, throttle math incl. injectable clock, user/session
  parsing incl. path-traversal guards, config validation, sysffi
  fork/exec/peercred against real syscalls, real-libpam dlopen smoke.
- **Integration** (19): the full server over a real unix socket with
  mock backends — all seven ops, every event, trust gate, throttle,
  autologin, timed login, guest, crash-recovery, flood/oversize/UTF-8
  handling.
- **Fuzz**: the decode boundary + event serialisation (`fuzz/`, corpus
  in-tree, CI short pass).
- **nspawn**: real PAM + real logind + real launcher in a container
  (CI job; script in `packaging/ci/integration/`).
- **Bench**: `lion_bench` emits JSON; CI fails at >10% over budget.
