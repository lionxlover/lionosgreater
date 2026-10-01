# lion-greeter

LionOS login authentication daemon. Authenticates local users via PAM
and hands off to `lion-session`. Exposes a small D-Bus surface so that
the unprivileged `lion-login-ui` process can drive the UI without ever
touching PAM, root, or the password directly.

- **Bus name**: `org.lionos.Greeter`
- **Object path**: `/org/lionos/Greeter`
- **Interface**: `org.lionos.Greeter1`
- **Version**: `0.6.0`

## What it does

1. **Enumerate local users** (`ListUsers`) so the login UI can show
   avatars and full names without itself reading `/etc/passwd`.
   Results are cached for 5s to avoid hitting NSS on every UI redraw.
2. **Authenticate** a username/password pair via PAM. The PAM stack
   runs on a dedicated OS thread so blocking modules (LDAP, Kerberos)
   cannot stall the async runtime. **Since 0.5.0, any second-factor
   prompt (TOTP, security-key touch, smartcard PIN, password-change
   rounds) is forwarded live to the UI over D-Bus** — see
   `ConversationPrompt` / `ReplyConversation` below.
3. **Optionally auto-login** a configured user (0.5.0): a countdown the
   UI can render and the user can cancel, backed by a dedicated
   `lion-greeter-autologin` PAM stack so site policy stays in PAM.
4. **List installed desktop sessions** (0.6.0) — the XDG
   `wayland-sessions`/`x11-sessions` directories behind the UI's gear
   menu — and hand the chosen session to `lion-session` via `--session`
   plus `XDG_SESSION_DESKTOP`/`XDG_CURRENT_DESKTOP`. The last choice is
   remembered.
5. **Bridge logind seats for fast user switching** (0.6.0): who is
   signed in and where, jump to a VT, activate another user's session,
   ask a session to lock — all validated, capability-flagged, and
   quietly absent on non-systemd hosts.
6. **Hand off** to `/usr/bin/lion-session` as the target user, with a
   clean environment, a fresh session leader, supplementary groups
   initialised via `initgroups`, supplementary FDs closed, and core
   dumps disabled for the session.
7. **Report progress** over D-Bus so the UI can animate each phase
   (`verifying` → `authorized` → `starting_session`), advertise which
   auth methods this machine can speak (fingerprint / smartcard /
   security-key, 0.6.0), and pin secrets in RAM with `mlockall`
   (RLIMIT-guarded, never fatal) so passwords cannot reach swap.

Rendering, post-login behaviour and account management are out of
scope.

## CLI

The binary is a single-mode tool; its mode is selected by the first
argument:

```
lion-greeter [--daemon]       Run the long-lived D-Bus service (default)
lion-greeter --version        Print version info and exit
lion-greeter --list-users     Print local-user JSON and exit
lion-greeter --list-sessions  Print installed XDG sessions JSON and exit (0.6.0)
lion-greeter --list-methods   Print auth-method availability JSON and exit (0.6.0)
lion-greeter --check-pam      Probe the PAM stack and exit
lion-greeter --check-config   Parse greeter.toml and print it
```

`--version`, `--list-*`, `--check-pam` and `--check-config` are
sysadmin inspection tools — they run without root or D-Bus and are
useful for install scripts, post-install smoke tests, and bare-metal
recovery shells.

## D-Bus API

| | |
|---|---|
| `ListUsers() -> s` | JSON array of `{username, full_name, avatar_path, session_type, last_used}`. Last user first. Cached for 5s. |
| `GetLastUser() -> s` | Username or `""`. |
| `Authenticate(s user, s password) -> (b ok, s message, u retry_after_ms)` | Drives the full PAM flow. Emits the signals below. |
| `CancelAuth() -> b` | Cooperatively cancel an in-flight `Authenticate` (also aborts any pending forwarded conversation). Returns `true` iff there was something to cancel. |
| `ReplyConversation(t request_id, as answers) -> b` | **0.5.0** Answer a forwarded PAM prompt (aligned with the `ConversationPrompt` payload). Single-use ids; over-long answers refused. |
| `AuthenticateSession(s user, s password, s session_id) -> (b ok, s message, u retry_after_ms)` | **0.6.0** Authenticate *and* choose the desktop session. The id is validated against the installed list before anything else — a bad id costs no throttle budget and no PAM call. |
| `ListSessions() -> s` | **0.6.0** JSON array of installed sessions `{id, name, comment, exec, session_type, desktop_names}` — the gear-menu data. Empty array when none are installed. |
| `GetLastSession() -> s` | **0.6.0** Last-chosen session id or `""`. |
| `ListSeatSessions() -> s` | **0.6.0** Live logind snapshot `[{id, uid, username, seat, class, active}]` — the fast-user-switching data. `[]` when logind is absent (never an error). |
| `SwitchToVT(u vt) -> (b ok, s message)` | **0.6.0** Jump the seat to a virtual terminal. VT validated 1..=63; refuses politely without logind. |
| `ActivateSession(s session_id) -> (b ok, s message)` | **0.6.0** Switch directly to another user's logind session (id validated `\d+`/`c\d+`). |
| `LockSession(s session_id) -> (b ok, s message)` | **0.6.0** Ask another user's session to lock itself. |
| `CancelAutologin() -> b` | **0.5.0** Disarm the pending automatic sign-in; `true` iff a countdown/attempt was running. |
| `GetMetrics() -> s` | JSON object with auth counters + uptime. |
| `ResetMetrics()` | Zero the counters (not uptime). |
| `Version` (property, `s`) | `0.6.0`. |
| `Capabilities` (property, `s`) | JSON array of optional feature strings: `["cancel", "metrics", "conversation", "autologin", "sessions", "auth-methods"]` plus `"mlock"` only when memory is actually pinned and `"seat-switch"` only while logind is reachable. |
| `AutologinUser` (property, `s`) | **0.5.0** Configured autologin user or `""`. |
| `AutologinDelayMs` (property, `t`) | **0.5.0** Countdown length in milliseconds. |
| `AutologinRelogin` (property, `b`) | **0.5.0** Whether autologin re-arms after logout. |
| `LastSession` (property, `s`) | **0.6.0** Last-chosen session id or `""`. |
| `DefaultSession` (property, `s`) | **0.6.0** `[session] default` from greeter.toml or `""`. |
| `AuthMethods` (property, `s`) | **0.6.0** JSON array of available auth methods — password always, fingerprint/smartcard/security-key/face when their PAM module is installed (and, for fingerprint, fprintd is alive): the data behind the UI's method logos. |

Signals (emitted during `Authenticate`):

| | |
|---|---|
| `AuthProgress(s stage)` | `"verifying"` \| `"authorized"` \| `"starting_session"`. |
| `AuthFailed(s message, u retry_after_ms)` | Always takes ≥ 600ms wall-clock after the call started. |
| `AuthSucceeded()` | UI should play its unlock/fade-out transition. |
| `AuthCanceled()` | UI should reset to idle (Esc / cancel pressed). |
| `ConversationPrompt(t request_id, s prompts_json)` | **0.5.0** A live PAM question: `[{"style":"echo_off","text":"Verification code:"}]` (styles: `echo_off`, `echo_on`, `error`, `info`). The UI must answer via `ReplyConversation`, or the round times out after 30s. |
| `AutologinCountdown(u ms_left)` | **0.5.0** ~5x/s while the countdown runs; the UI shows "signing in as X in N s". |
| `AutologinAborted(s reason)` | **0.5.0** Autologin ended without a session (`canceled`, `pam-requires-authentication`, `user-unavailable`, `session-start-failed`); the UI falls back to the manual form, pre-selecting the same user. |
| `SessionsChanged()` | **0.6.0** The logind session/seat snapshot moved (someone logged in/out, VT switched). Re-fetch via `ListSeatSessions`. |

## Configuration

`/etc/lionos/greeter.toml` (override: `$LION_GREETER_CONFIG`; example
in `etc/lionos/greeter.toml.example`):

```toml
[autologin]
user = "kiosk"      # account to sign in without a password ("" or "none" = off)
delay_ms = 2000     # cancellable countdown before it fires
relogin = true      # false = auto-login once per daemon start, not after logout

[session]
default = "lion"    # preferred session id; omit = last-chosen, then compositor default

[security]
mlock = true         # pin secrets in RAM (mlockall); never fatal, see Capabilities
```

A broken file is logged and ignored — configuration can never lock a
user out of their own machine. Site policy for autologin itself lives
in `pam.d/lion-greeter-autologin` (pam_nologin is always enforced; add
`pam_succeed_if`/`pam_u2f` lines there to restrict it further).

### GetMetrics output schema

```json
{
  "auth_attempts": 42,
  "auth_successes": 38,
  "auth_failures": 4,
  "auth_cancels": 0,
  "sessions_started": 38,
  "throttled_users": 1,
  "autologin_fires": 3,
  "autologin_aborts": 1,
  "seat_switches": 2,
  "uptime_seconds": 3600,
  "started_unix": 1730000000
}
```

Useful for ops dashboards, the LionOS install wizard, and post-mortem
scripts that don't want to scrape the journal.

## Build

```
cargo build --release
```

The build is self-contained:

- No `libclang`/`bindgen` needed. The PAM FFI in `src/pam_ffi.rs` is
  hand-rolled, not generated.
- No `libpam-dev` needed. `build.rs` emits `-l:libpam.so.0` so the
  linker resolves against the runtime libpam that every Linux box has.
- The default target CPU is `x86-64-v3` (Haswell 2013+). See
  `.cargo/config.toml` and `OPTIMIZATIONS.md` §1.3 for how to
  override.

Only build-time deps are: a Rust toolchain (≥ 1.74), and `libpam0g`
(which is installed on every Linux system that uses PAM — all of them).

## Test

```
cargo test                      # 93 unit + 14 integration tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
bash scripts/live_dbus_test.sh  # 62 live checks against a private bus
```

The unit suite covers:

- throttle escalation curve (5 tests)
- GECOS parser (5 tests)
- `getpwnam_r` plumbing (live `gecos_for("root")`)
- PAM envlist parser + conversation bridge
- state round-trips (last-user, last-session, last-session-id)
- user-enumeration cache (TTL + invalidation)
- metrics counters + JSON serialization
- **0.6.0**: XDG session parsing (13 tests), logind reply parsing
  across both signature generations (8 tests), auth-method probing
  (10 tests), session-id resolution policy, VT/session-id validation

The integration layer (`tests/`) adds:

- `fuzz_harness.rs` — deterministic fuzzing of both untrusted-input
  parsers (~5,000 mutants per run, no dependencies)
- `cli_smoke.rs` — the real binary: `--version`, `--check-config`
  (valid, missing and broken files), `--list-sessions` (fixtures),
  `--list-methods`, unknown-mode behaviour

End-to-end PAM auth is exercised live by `scripts/live_dbus_test.sh`
against the host's real PAM stack on a private bus.

## Install

`make install` (or the equivalent commands below):

```
install -Dm755 target/release/lion-greeter       /usr/bin/lion-greeter
install -Dm644 lion-greeter.service              /usr/lib/systemd/system/lion-greeter.service
install -Dm644 dbus-1/org.lionos.Greeter.conf    /usr/share/dbus-1/system.d/org.lionos.Greeter.conf
install -Dm644 pam.d/lion-greeter                /etc/pam.d/lion-greeter
install -Dm644 pam.d/lion-greeter-autologin      /etc/pam.d/lion-greeter-autologin
install -d -m755 /var/lib/lion-greeter
systemctl daemon-reload
systemctl enable --now lion-greeter
```

Distro packages: `packaging/PKGBUILD` (Arch), `packaging/debian/`
(Debian/Ubuntu), `packaging/rpm/lion-greeter.spec` (Fedora/RHEL/SUSE)
— all build from the same `--locked` graph and run the test suite at
package-build time.

## Source layout

```
src/
  main.rs        — thin binary: CLI modes, runtime, panic hook
  lib.rs         — library target (integration-testable since 0.6.0)
  ipc.rs         — D-Bus interface (Greeter1), session resolution, seat relay
  auth.rs        — login worker (OS thread), session handoff hardening
  pam_ffi.rs     — vendored libpam FFI (no bindgen / no libclang)
  sessions.rs    — XDG session directory listing (0.6.0)
  seat.rs        — logind user-switching bridge (0.6.0)
  methods.rs     — auth-method availability probing (0.6.0)
  state.rs       — last-user / last-session persistence
  throttle.rs    — per-user brute-force backoff
  users_enum.rs  — local user enumeration (thread-safe, 5s cache)
  metrics.rs     — atomic counters exposed via GetMetrics()
  config.rs      — greeter.toml (hand-parsed TOML subset, 0.5.0)
  mlock.rs       — mlockall secret pinning (0.5.0)
build.rs         — link to libpam.so or libpam.so.0
tests/
  fuzz_harness.rs — deterministic parser fuzzing
  cli_smoke.rs    — real-binary CLI tests
fuzz/            — libFuzzer target + seed corpus
.cargo/config.toml — x86-64-v3 baseline, default RUST_LOG
.github/workflows/ci.yml — CI: fmt/clippy/tests/MSRV/audit/release
pam.d/           — lion-greeter, lion-greeter-autologin
dbus-1/          — system-bus policy
etc/lionos/      — greeter.toml.example
packaging/       — PKGBUILD, debian/, rpm/
Makefile         — build / test / check / install / dist
CHANGELOG.md     — release history
STABILITY.md     — API stability tiers (D-Bus / CLI / config)
SECURITY.md      — threat model, reporting, hardening inventory
lion-greeter.service — systemd unit (Type=dbus, crash-restart,
                     capability-dropped, syscall-filtered)
README.md        — this file
OPTIMIZATIONS.md — production optimization catalogue
ENHANCEMENTS.md  — enhancement log vs. the original 0.2.0
TEST_REPORT.md   — verification matrix
```

## Threat model

- **Surface**: the system D-Bus interface `org.lionos.Greeter1`. Reachable
  only by the dedicated `lion-login` account (see
  `dbus-1/org.lionos.Greeter.conf`). The default policy denies `own`,
  `send_destination`, and `receive_sender` to everyone else.
- **Username probing**: unknown usernames take the same path and the
  same wall-clock latency as wrong-password attempts. The throttle
  collapses every unknown name onto the same key (`"\0unknown"`), so
  probing arbitrary names does not grow the throttle map and reveals
  nothing about which accounts exist.
- **Brute force**: per-user doubling backoff (2s, 4s, ... capped at
  60s) after two free failures. `MAX_TRACKED=256` bounds memory in the
  face of a distributed brute-force attempt.
- **Password handling**: the plaintext password lives only inside a
  `Zeroizing<Vec<u8>>` for as long as the PAM context is alive, and is
  wiped on drop. `strdup` copies are owned by libpam and freed by it;
  the standard PAM limitation (those bytes may technically outlive
  free) is unavoidable without rewriting libpam itself.
- **FD leak**: every FD the daemon happens to hold (D-Bus socket,
  journal, secrets) is closed before `execve`, so the user session
  cannot read them.
- **Core dumps**: `RLIMIT_CORE=0` is set on the session child so a
  session crash cannot write a core that another user later reads.
- **Privilege drop**: `setgroups(0, NULL)` → `initgroups(name, gid)` →
  `setgid(gid)` → `setuid(uid)`, in that order; then a paranoid
  `setuid(0)` probe to verify privileges are unrecoverable.
- **logind proxy abuse** (0.6.0): session ids and VT numbers are
  charset/range-validated before any forwarding to logind, so a
  compromised UI cannot use the root greeter as a generic bus proxy.
- **Untrusted files** (0.6.0): session `.desktop` files and
  `greeter.toml` are parsed by hand-written subset parsers whose
  invariants (whole-file reject, plausibility validation, no
  panics) are enforced by a deterministic fuzz harness on every CI
  run. See `SECURITY.md` for the full hardening inventory.

## Documentation index

- `CHANGELOG.md` — release history (semver).
- `STABILITY.md` — API stability tiers for D-Bus, CLI, config, state.
- `SECURITY.md` — threat model, reporting policy, hardening inventory.
- `OPTIMIZATIONS.md` — production optimization catalogue (LTO, target
  CPU, runtime bounds, cache, mutex choice, what we did NOT optimize).
- `ENHANCEMENTS.md` — enhancement log vs. the original 0.2.0 zip.
- `TEST_REPORT.md` — verification matrix.
- `packaging/README.md` — distro packaging (Arch/Debian/RPM).

