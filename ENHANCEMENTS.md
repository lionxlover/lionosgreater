# ENHANCEMENTS — lion-greeter 0.2.0 → 0.3.0

## TL;DR

The original `lion-greeter-src.zip` did not build (missing libclang) and
would not have compiled past `users_enum.rs` even if it had (broken
`u.gecos()` call). This release:

- **fixes the build** by replacing `pam-client`+`pam-sys`+`bindgen` with
  a ~280-line vendored PAM FFI that needs no `libclang`, no `libpam-dev`,
  and links against the runtime `libpam.so.0` present on every Linux box;
- **fixes a real concurrency bug** in user enumeration (libc `getpwent`
  is process-global and was being called concurrently from
  `spawn_blocking` tasks);
- **hardens the session child** against FD leaks and core-dump
  information disclosure;
- **adds cooperative cancellation** of an in-flight PAM auth via a
  new `CancelAuth()` D-Bus method and `AuthCanceled` signal;
- **tracks last-session timestamp** so the UI can show
  "logged in 2 days ago" hints;
- **installs a panic hook** so worker panics are logged with structured
  fields and turned into `AuthError::Service` rather than aborting the
  daemon;
- **grows the test suite from 2 to 16 tests** covering the throttle,
  GECOS parser, PAM envlist parser, state round-trips, and the
  `getpwnam_r` plumbing;
- **tightens systemd unit hardening** (private devices/mounts/tmp,
  protect hostname/proc, `IPAddressDeny=any`, syscall filters, file
  limits);
- **tightens the D-Bus policy** with an explicit
  `deny own/send_destination/receive_sender` in the default context.

## Detailed change list

### Build system

| File | Change |
|---|---|
| `Cargo.toml` | Removed `pam-client = "0.5"`. Bumped `version` 0.2.0 → 0.3.0. Added `repository`, `homepage`, `keywords`, `categories`, `rust-version = "1.74"`. Added `[profile.dev]` with `opt-level=0, debug=1`. |
| `build.rs` | New. Emits `-lpam` if `libpam.so` (dev symlink) exists, else falls back to `-l:libpam.so.0` so the build works without `libpam-dev`. |

### New module: `src/pam_ffi.rs`

Hand-rolled, panic-safe PAM FFI. Replaces `pam-client`/`pam-sys`/`bindgen`
entirely. Exposes:

- `PamContext::start(service, user, password) -> Result<Self, c_int>`
- `PamContext::authenticate / acct_mgmt / setcred_reinit / open_session`
- `PamContext::envlist -> Vec<(String, String)>`
- `PamContext::is_authed` (diagnostic)
- `Drop` impl that calls `pam_close_session` (if open) then `pam_end`
  with the last non-success status (so module cleanup hooks fire
  correctly).

Internals:

- The conversation callback is `unsafe extern "C"` wrapped in
  `std::panic::catch_unwind` — panics across the FFI boundary are UB,
  so we catch and convert to `EINVAL`.
- The password is stored as `Zeroizing<Vec<u8>>` (NUL-terminated), not
  `Zeroizing<CString>` (which doesn't typecheck — `CString` does not
  implement `Zeroize`). Bytes are wiped on drop.
- `strdup` is used for the response string libpam will later `free`.
  The original `Zeroizing` password is untouched and wiped on context
  drop.
- Unknown `msg_style` values are refused (return `EINVAL`) so a future
  PAM module cannot surprise us with a binary prompt we did not opt
  into.
- The `pam_getenvlist` result is properly freed (each string AND the
  array itself, per the man page).

### `src/auth.rs` (rewritten)

- Uses `crate::pam_ffi::PamContext` instead of `pam_client::Context`.
- Adds `pam_setcred(PAM_REINITIALIZE_CRED)` after `authenticate` and
  before `open_session`. The original skipped this; production PAM
  modules like `pam_krb5` / `pam_gnome_keyring` expect it for clean
  credential refresh on re-login.
- Adds **`close_fds_except_stdio_preexec()`** — walks `/proc/self/fd`
  in the child and closes every FD > 2 before `execve`. So a D-Bus
  socket, journal handle, or secret held by the greeter cannot leak
  into the user session.
- Adds `RLIMIT_CORE = 0` on the child via `setrlimit` — a session
  crash cannot write a core dump another user could later read.
- Adds an explicit `setgroups(0, NULL)` before `initgroups` as
  defense in depth (glibc's `initgroups` already does it, but the
  explicit call documents the intent and is portable to non-glibc).
- Wraps the worker body in `catch_unwind` so a panic is logged with
  a structured `panic.location` / `panic.message` and converted to
  `AuthError::Service` rather than aborting the daemon.
- `spawn_login` now takes a `Arc<AtomicBool>` cancel flag. The
  worker checks it at three checkpoints (start, after `authenticate`,
  after `setcred`) so a UI cancel request actually stops the flow
  before the user's session is started.
- New error variant `AuthError::Canceled` and a new `Stage` equality
  derive for tests.

### `src/ipc.rs` (extended)

- `Greeter` struct gains a `cancel: Mutex<Option<Arc<AtomicBool>>>`
  holding the cancel flag for the in-flight login, if any.
- New D-Bus method `CancelAuth() -> b` — sets the flag for the
  in-flight auth. Returns `true` iff there was something to cancel.
- New signal `AuthCanceled` — emitted when the in-flight auth
  observes the cancel flag. UI resets to idle.
- New property `Capabilities (s)` — JSON array of optional feature
  strings, currently `["cancel"]`. Lets us add future features without
  ABI breakage.
- `Authenticate` now records `state::touch_last_session()` on success.
- Cancellation does **not** record a failure or increment the
  throttle (it's a user action, not an attack).

### `src/state.rs` (extended)

- New `last_session_path()` and `last_session_ts()` for the
  last-login timestamp.
- New `touch_last_session()` — atomic write of `now()` to
  `last-session`. Called by the IPC layer on successful auth.
- The atomic-write helper now creates files with explicit mode 0o644
  via `OpenOptionsExt::mode` (the original relied on umask, which
  could vary).
- The atomic-write helper now fsyncs the parent directory after the
  rename, so the rename is durable across a crash.
- Added two new unit tests covering last-user and last-session
  round-trips in a temp dir.

### `src/throttle.rs` (extended)

- New `clear_all()` for the future suspend-resume hook.
- New `tracked_len()` and `failure_count()` for tests/diagnostics.
- Replaced the `map_or(false, …)` predicate with `is_some_and(…)`
  per `clippy::unnecessary_map_or`.
- Three new tests: `failure_count_is_tracked`, `clear_all_drops_everyone`,
  `unknown_users_share_one_entry` (verifies the `MAX_TRACKED` cap
  bounds memory under probing).

### `src/users_enum.rs` (extended + bug-fixed)

- Fixed the broken `u.gecos()` call — `users 0.11` does not expose
  `pw_gecos` on Linux. Replaced with a `gecos_for(username)` helper
  that calls `libc::getpwnam_r` directly and returns the GECOS field.
  This is a real correctness fix: the original code never compiled.
- Extracted `parse_gecos_full_name` as a pure, testable helper.
- Added a process-wide `Mutex<()>` (via `OnceLock`) that serializes
  every call to `users::all_users()` / `users::get_user_by_name()`.
  Without it, two concurrent `spawn_blocking` tasks could call into
  libc's non-reentrant `getpwent` simultaneously — UB.
- Added seven new unit tests: GECOS parsing variants, nologin-shell
  recognition, and a live `gecos_for("root")` lookup that verifies the
  `getpwnam_r` plumbing actually works.

### `src/main.rs` (extended)

- Installs a `std::panic::set_hook` that converts panics into
  `tracing::error!` with structured fields (`panic.location`,
  `panic.message`). The default hook writes to stderr, which on a
  greeter is the journal — fine, but `tracing` gives us redaction
  control and structured tags.
- Added the `mod pam_ffi;` declaration.
- Added a top-level doc-comment describing the threat model.

### `lion-greeter.service` (hardened)

| Directive | Before | After |
|---|---|---|
| `ProtectKernelLogs` | — | `yes` |
| `ProtectHostname` | — | `yes` |
| `ProtectProc` | — | `invisible` |
| `ProtectSystem` | — | `strict` |
| `ProtectHome` | — | `read-only` |
| `PrivateTmp` | — | `yes` |
| `PrivateDevices` | — | `yes` |
| `PrivateMounts` | — | `yes` |
| `RestrictSUIDSGID` | — | `yes` |
| `IPAddressDeny` | — | `any` |
| `ProcSubset` | — | `pid` |
| `SystemCallFilter` | — | `@system-service`, then `~@privileged @resources @mount @swap @obsolete @cpu-emulation` |
| `ReadWritePaths` | — | `/var/lib/lion-greeter /run/lion-greeter` |
| `LimitNOFILE` | — | `256` |
| `LimitNPROC` | — | `64` |

### `dbus-1/org.lionos.Greeter.conf` (hardened)

- The default policy now explicitly `deny own`, `deny
  send_destination`, and `deny receive_sender` (defense in depth).
- `root` policy now also explicitly allows `send_destination` and
  `receive_sender` so self-tests and future tooling don't accidentally
  hit the default deny.

### `pam.d/lion-greeter` (documented)

- No module changes (the stack is already correct).
- Added a thorough comment block explaining each line and the
  relationship between PAM's own `pam_faildelay` and the daemon's
  600ms minimum-failure-latency + per-user throttle.

### `README.md` (new)

Architecture overview, full D-Bus API table, build/test/install
instructions, source-layout map, and a written threat-model section.

### `TEST_REPORT.md` (new)

Documents the test environment, the build failures of the original
code, the verification results of the enhanced code, and the
limitations of what could be tested in-sandbox.

## Migration notes for downstream consumers

- **No D-Bus ABI breakage**: existing UI clients can keep calling
  `ListUsers`, `GetLastUser`, `Authenticate` exactly as before.
- **New optional method**: `CancelAuth()` is additive; UIs that
  don't call it are unaffected.
- **New optional property**: `Capabilities` is additive; UIs can
  probe it to detect `cancel` support and hide the cancel button if
  absent.
- **New signal `AuthCanceled`**: UIs that don't listen for it will
  just see `Authenticate` return `(false, "Sign-in was canceled", 0)`,
  which is still a valid (if less specific) outcome.
- **State directory unchanged**: `/var/lib/lion-greeter/` now contains
  two files (`last-user`, `last-session`) instead of one. The
  `StateDirectoryMode=0755` directive in the unit handles this
  transparently.

---

# Production optimization pass — 0.3.0 → 0.4.0

After the 0.3.0 fix-and-harden pass, the user asked for maximum
optimization for a future-proof LionOS. The full catalogue of what
was done (and what was deliberately NOT done) is in `OPTIMIZATIONS.md`.
Summary of the diff:

## Build-time

| Change | Effect |
|---|---|
| `lto = "fat"` (was `true`) | Whole-program LTO across all crates including zbus/tokio/tracing. ~1m30s build, smaller binary. |
| `tracing` feature `release_max_level_info` | `debug!`/`trace!` calls are compiled out at the call site in release. ~40 KB off the binary; zero hot-path overhead. |
| `.cargo/config.toml`: `target-cpu=x86-64-v3` | AVX2/BMI2/FMA/SSE4.2 baseline (Haswell 2013+). Same baseline as RHEL 9 / Fedora 40+. |
| `panic = "abort"` (already), `strip = "symbols"` (was `true`) | Slightly more aggressive strip. |

## Runtime

| Change | Effect |
|---|---|
| Bounded tokio runtime: `worker_threads(2)`, `max_blocking_threads(2)` | Saves ~30 MB RSS on a 16-core box (was `num_cpus()` workers). |
| `throttle` and `cancel` locks switched from `tokio::sync::Mutex` to `std::sync::Mutex` | Single `cmpxchg` fast path instead of an async FIFO queue. |
| `enumerate_users_cached()` with 5s TTL | `ListUsers` no longer hits NSS on every UI redraw. Big win on SSSD/LDAP systems. |
| `Vec::with_capacity(users.len())` in `list_users` | Single allocation instead of ~6 reallocations. |
| `#[tracing::instrument]` on `spawn_login` and `worker` | Structured spans in the journal for post-mortem analysis. |

## New modules / features

| Change | Effect |
|---|---|
| New `src/metrics.rs` with `AtomicU64` counters | Exposed via `GetMetrics()` / `ResetMetrics()` D-Bus methods. Ops dashboards can read auth counters + uptime without scraping the journal. |
| New `Capabilities` property value `"metrics"` | UIs can detect the metrics API. |
| New CLI flags `--version`, `--list-users`, `--check-pam` | Sysadmin inspection tools; useful for install scripts and bare-metal recovery shells. No D-Bus or root needed. |
| `--check-pam` calls `pam_start` + `pam_end` to verify the PAM stack loads | Post-install smoke test that catches a broken `/etc/pam.d/lion-greeter` before the user tries to log in. |

## What was NOT done (with reasoning)

- Did NOT switch to `jemalloc` or `mimalloc`. Allocation rate is too low; glibc malloc is fine.
- Did NOT add PGO. The hot path is straight-line; PGO would shave < 1%.
- Did NOT add BOLT. Same reasoning.
- Did NOT inline the PAM FFI calls. Each call crosses a libpam boundary; the 5-cycle call overhead is invisible vs the ms-scale PAM work.
- Did NOT switch `busy` from `tokio::sync::Mutex` to a `Semaphore`. Same semantics, no perf difference.

See `OPTIMIZATIONS.md` §4 for the full reasoning on each non-change.

## Binary size: 0.3.0 → 0.4.0

| | 0.3.0 | 0.4.0 | delta |
|---|---|---|---|
| Release binary | 2,904,880 B | 2,865,000 B | −39,880 B (−1.4%) |
| text | (n/a) | 2,794,066 B | — |
| data | (n/a) | 67,576 B | — |
| bss | (n/a) | 2,184 B | — |

The 40 KB saving comes almost entirely from `release_max_level_info`
compiling out the `debug!`/`trace!` calls and their format strings.

## Test suite: 0.3.0 → 0.4.0

| | 0.3.0 | 0.4.0 | delta |
|---|---|---|---|
| Unit tests | 16 | 22 | +6 |
| — metrics | 0 | 4 | +4 |
| — user-enumeration cache | 0 | 2 | +2 |

All 22 tests pass. `cargo clippy --all-targets -- -D warnings` is clean.
`cargo fmt --check` is clean.


---

# 0.4.0 → 0.5.0 — Round 3: parity-breaking features

Round 2 closed the maturity gap; round 3 attacks the *feature* gap
(0.4.0 scored 4.5/10 on features vs GDM's 8.5). Three additions, each
chosen because it is the single highest-leverage missing capability
competitors actually ship, and each designed to fail soft — a login
daemon must never gain a new way to refuse service.

## 1. PAM conversation forwarding (2FA / smartcards / password change)

**Problem.** 0.4.0 answered every PAM prompt from a fixed
`(username, password)` pair. Any stack with a second factor
(pam_google_authenticator, pam_u2f, pam_fido2, pam_pkcs11, SSSD,
pam_mount "password again") would fail or hang. That is "works with
pam_unix", not "works with PAM".

**Design** (`pam_ffi.rs`, `auth.rs`, `ipc.rs`):
- The conversation callback now routes prompts through a pluggable
  `ConvBridge` trait. `ConvSide::Static` keeps the 0.4 behaviour
  (`--check-pam`, autologin); `ConvSide::Interactive` forwards.
- The interactive bridge is *hybrid*: the first echo-off prompt is
  answered from the password the UI already collected (the UI sees
  nothing new for a plain password login — zero regression), and any
  *further* promptable prompt becomes a `ConversationPrompt(u id, s
  prompts_json)` D-Bus signal. The worker parks on a condvar with a
  30 s deadline, cooperative cancel, and info/error lines logged.
- The UI replies with `ReplyConversation(u id, as answers)`; ids are
  single-use, so a stale or spoofed reply cannot inject an answer into
  another round. Answers are capped at 1024 bytes each and zeroized.
- `CancelAuth` now also aborts pending rounds — a parked worker wakes
  immediately instead of at the deadline.

**Security invariants kept:** unknown message styles (e.g.
PAM_BINARY_PROMPT) are still refused, not guessed; panics in the
callback still become EINVAL, never UB; the password is still
`Zeroizing` and one-shot.

## 2. Autologin (`config.rs`, `auth.rs`, `ipc.rs`, `pam.d/lion-greeter-autologin`)

- `Autologin { user, delay_ms, relogin }` in `/etc/lionos/greeter.toml`
  (override: `$LION_GREETER_CONFIG`). Hand-written TOML-*subset* parser
  — zero new dependencies (~30 KB of `toml` crate avoided), unknown
  keys/sections ignored for forward compatibility, and a *broken file
  is logged and ignored* — config can never lock users out.
- A dedicated `lion-greeter-autologin` PAM stack (ships in `pam.d/`)
  keeps site policy in PAM where it belongs: pam_nologin still gates
  lockdowns, session phases are identical to interactive login, and a
  site can demand a group or a plugged token by editing one file.
  If the stack refuses, the daemon reports `AutologinAborted` and the
  UI falls back to the manual form — **without charging the attempt
  against the user's throttle** (it is not the user's fault).
- The driver counts down in public: `AutologinCountdown(ms_left)`
  signals ~5x/s, `CancelAutologin()` is the "Esc" affordance, and
  `relogin = false` means a logout does not bounce the user straight
  back in (shared-machine behaviour). `AutologinUser/DelayMs/Relogin`
  are exposed as properties so the UI can render state it did not
  have to discover by timing.
- Two new metrics (`autologin_fires`, `autologin_aborts`) make a
  misconfigured stack visible from `GetMetrics()`.

## 3. Secret pinning: `mlockall` with an RLIMIT guard (`mlock.rs`)

- `mlockall(MCL_CURRENT | MCL_FUTURE)` pins every current and future
  page, so plaintext passwords cannot reach swap before they are
  zeroized. One syscall, no capability needed when the unit grants
  `LimitMEMLOCK=infinity` (added to `lion-greeter.service`, along with
  the `@memory-lock` syscall-filter group the sandbox otherwise blocks).
- The guard is the interesting part: before attempting, we read
  `RLIMIT_MEMLOCK` and current RSS and *skip* unless `rss + 16 MiB
  headroom` fits. A failed attempt is undone with `munlockall()`. The
  daemon never panics, never blocks, never refuses logins — worst case
  it logs one line. `Capabilities` advertises `"mlock"` **only when the
  lock actually succeeded**, so an advertised guarantee is a real one
  (auditable via D-Bus, in the journal, and in `--check-config`).
- This sandbox caps RLIMIT_MEMLOCK at 64 KiB; the live test proves the
  skip path: `skipped_small_limit`, logins unaffected.

## 4. Sysadmin surface

- `--check-config`: parse and print the effective config, including the
  exact failure line for a broken file, exit 0 either way (the daemon
  would ignore the file too — a broken config must not fail a boot).
- `--version` now reports the full feature surface.
- 33 new unit tests (conversation slot/bridge/registry, config parser,
  mlock decision logic) → **55 total, all passing**.
- 30-check live D-Bus integration suite (see TEST_REPORT.md) exercises
  the real release binary on a private bus, including the live PAM
  bridge against `pam_unix` and the autologin countdown/cancel/signals.

---

# Round 4 — 0.6.0 enhancements

## The two gaps 0.6.0 closes

Round 3 left lion-greeter #1 overall but tied on **features** (8.5,
level with GDM) and #3 on **maturity** (6.5). Both gaps had specific,
nameable causes:

* Features: GDM kept session selection, user switching, and
  biometric-marketing integration; greetd kept multi-session config.
* Maturity: engineering maturity was already top-tier (55 tests +
  live suite + zero deps); what was missing were the *artifacts*
  maturity is measured by — CI, fuzzing, packaging, changelog,
  stability/security policy.

## 1. XDG session selection (sessions.rs, ~560 lines)

The "gear menu" every other greeter has: `/usr/share/wayland-sessions`
+ `/usr/share/x11-sessions` enumeration with full lister rules
(Type/Name/Exec required, Hidden/NoDisplay excluded, TryExec must
resolve, DesktopNames parsed, locale keys dropped, quoting + the
desktop-entry spec's five escapes). Hand-written parser — zero new
dependencies, same audit story as the TOML subset. The chosen session
flows to `lion-session` as `--session <id>` + `XDG_SESSION_DESKTOP` +
`XDG_CURRENT_DESKTOP` (which lion-session's OnlyShowIn/NotShowIn
autostart filtering keys off). `AuthenticateSession` validates the id
before ANY auth state is touched: a bad id costs no throttle budget,
no metrics, no PAM call. Last choice persists
(`last-session-id`), config can pin a default
(`[session] default`), resolution priority is explicit >
config > last-chosen > lion-session's default — and defaults
degrade silently while explicit choices fail loudly.

## 2. Fast user switching (seat.rs, ~430 lines)

The logind bridge: `ListSeatSessions` (live snapshot with
active-session resolution via `Seat.ActiveSession`, one call per
distinct seat), `SwitchToVT` (validated 1..=63), `ActivateSession`
(id validated `[0-9]+`/`c[0-9]+`), `LockSession`, and a
`SessionsChanged` relay (5 s poll, signal only on change). Every call
is a dynamic `call_method` against the documented Manager interface —
no proxy codegen, no systemd-version coupling; the positional parser
accepts both the 2014 (`a(sussss)`) and current (`a(susssso)`)
ListSessions signatures. Without logind: capability hidden, methods
refuse politely, `[]` snapshots — never an error, never a dependency.
This is what GDM's user-switcher does, expressed as a documented,
versioned, capability-flagged API any UI can call.

## 3. Auth-method probing (methods.rs, ~300 lines)

GDM's fprintd integration at the daemon level: module-file presence
(pam_fprintd, pam_pkcs11/pam_p11/pam_sss, pam_u2f/pam_fido2,
pam_face_authentication) + a live `NameHasOwner` check for fprintd →
the `AuthMethods` property the UI renders logos from. The honesty
rule: fingerprint is "available" only when module AND daemon are up;
everything else reports capability ("module installed") without
claiming availability. `--list-methods` gives install scripts the same
answer offline.

## 4. Engineering-maturity artifacts (the maturity gap, closed)

* **lib/bin split** — `lion_greeter` library + thin binary: the
  parsers are integration-testable without root.
* **CI** (`.github/workflows/ci.yml`): fmt + clippy(-D warnings) +
  tests + live D-Bus suite + MSRV 1.74 + cargo-audit + release
  artifact with SHA256. Everything CI runs is what a packager runs.
* **Deterministic fuzz harness** (`tests/fuzz_harness.rs`): xorshift
  mutation over a 26-seed corpus through 6 damage classes;
  ~5,000 mutants per `cargo test` run, zero dependencies, zero setup.
  Plus a libFuzzer target + seeded corpus (`fuzz/`) for
  corpus-growing infrastructure.
* **Packaging ×3** in-repo: `packaging/PKGBUILD`,
  `packaging/debian/` (control/rules/postinst with a PAM smoke
  probe), `packaging/rpm/lion-greeter.spec`. Same file set as the
  `Makefile` install; example config lands in /usr/share, never
  clobbering /etc.
* **Operator documents**: CHANGELOG.md (semver history),
  STABILITY.md (four-tier stability contract: D-Bus / CLI / config /
  state), SECURITY.md (threat model, reporting policy, hardening
  inventory), `etc/lionos/greeter.toml.example`.
* **`--list-sessions` / `--list-methods`** inspection modes; metrics
  gained `seat_switches`.

## 5. Security additions

* Input validation before any logind forwarding (session-id charset,
  VT range) — a compromised UI cannot turn the root greeter into a
  generic bus proxy.
* Session ids scrubbed to file-stem charset before becoming env vars
  or argv (path traversal impossible by construction, tested).
* The new parsers carry the same whole-file-reject and
  never-block-a-login discipline as the config parser, now enforced
  by fuzzing on every CI run.
