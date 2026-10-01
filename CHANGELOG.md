# Changelog — lion-greeter

All notable changes to this project are documented in this file. The
format follows Keep-a-Changelog; versions follow semver (see
STABILITY.md for what "breaking" means for a D-Bus surface).

## [0.6.1] — 2026-10-01

### Fixed — correctness under cancellation
* **Cancel racing libpam is honored at result time**. `pam_authenticate`
  is an uninterruptible FFI call, and the worker checks the cancel flag
  only at round boundaries — so a UI that pressed Esc *mid-verification*
  was told "wrong password" when libpam finished. 0.6.1 checks the flag
  when the outcome is assembled: the attempt resolves as
  `Sign-in was canceled` + `AuthCanceled` signal, the failure-latency
  pad still applies (canceled and failed are timing-indistinguishable),
  **and the failure still counts toward the throttle** — racing Esc
  cannot launder brute-force attempts. (Found by the 0.5.0-vs-0.6.0
  audit: 0.5.0's forwarded password round was cancelable mid-flight;
  0.6.0's password-first design had silently lost that property.)

### Added — hardening of the conversation surface (live-tested)
* `ReplyConversation` answer guards are now exercised live: an empty
  answer batch and an over-1024-byte answer are both refused before any
  request-id lookup (`MAX_ANSWER_BYTES`).
* Live phase 1.7: CancelAuth mid-flight (fresh daemon, monitored
  `AuthCanceled` on the wire, throttle-integrity assertion).
* `scripts/live_dbus_test.sh` is now self-locating (resolves the repo
  root from its own path; works from any checkout without edits).

### Fixed — test determinism
* **Root-caused and eliminated an intermittent unit-test flake** (observed
  once in ~200 runs of 0.6.0): 12 tests across `state`, `methods` and
  `users_enum` mutate process-global fixtures (`STATE_DIRECTORY`,
  `PAM_MODULES_DIR`, the shared user-list cache) while the harness runs
  tests in parallel threads — a sibling test's `set_var` could land
  mid-test and make assertions read the wrong fixture directory. All
  env/cache-mutating tests now serialize through one global
  `test_env_lock()` (deadlock-free by construction: single acquisition
  per test). 50 consecutive full-suite runs verified clean.

### Docs
* 4 rustdoc link warnings fixed (private-item links, `[session]` TOML
  escapes) — `cargo doc` is now warning-clean.

## [0.6.0] — 2026-09-30

### Added — features that close the last feature gap vs GDM/SDDM
* **XDG session selection**: `/usr/share/wayland-sessions` +
  `/usr/share/x11-sessions` enumeration (Type/Name/Exec/TryExec/
  Hidden/NoDisplay/DesktopNames rules, quoting + escapes, locale keys
  dropped, id dedup with wayland priority). New D-Bus: `ListSessions`,
  `GetLastSession`, `AuthenticateSession(u,p,session)`, properties
  `LastSession`/`DefaultSession`; config `[session] default`; the
  chosen session reaches `lion-session` via `--session` plus
  `XDG_SESSION_DESKTOP`/`XDG_CURRENT_DESKTOP`; last choice persisted.
* **Fast user switching (logind seats)**: `ListSeatSessions` (live
  snapshot incl. active-session resolution via `Seat.ActiveSession`),
  `SwitchToVT` (validated 1..=63), `ActivateSession`, `LockSession`,
  `SessionsChanged` relay signal (5 s poll, change-only), capability
  `seat-switch` (present-probe + 30 s TTL cache), `seat_switches`
  metric. All calls dynamic `call_method` — no proxy codegen, works
  with logind signatures from 2014 and 2026.
* **Auth-method availability probing** (`methods.rs`): fingerprint
  (pam_fprintd module + live bus name-owner), smartcard
  (pam_pkcs11/pam_p11/pam_sss), security-key (pam_u2f/pam_fido2),
  face (pam_face_authentication) → `AuthMethods` property the UI
  renders logos from; `--list-methods` CLI mode.
* `--list-sessions` CLI mode; capability strings `sessions`,
  `auth-methods`.

### Changed — engineering maturity
* **lib/bin split**: `lion_greeter` library target + thin binary.
  Parsers and resolution policy are now integration-testable without
  a root process.
* CI workflow (`.github/workflows/ci.yml`): fmt + clippy(-D warnings)
  + tests + live D-Bus suite + MSRV 1.74 + cargo-audit + release
  artifact with SHA256.
* Deterministic fuzz harness (`tests/fuzz_harness.rs`): xorshift
  mutation over a 26-seed corpus, ~5,000 mutants per run, invariant
  set shared with the libFuzzer target (`fuzz/`, corpus seeded).
* Distro packaging in-repo: `packaging/PKGBUILD`,
  `packaging/debian/*`, `packaging/rpm/lion-greeter.spec`, plus a
  `Makefile` (build/test/check/install/uninstall/dist).
* New operator documents: `CHANGELOG.md` (this file), `STABILITY.md`
  (API stability tiers), `SECURITY.md` (threat model + reporting),
  `etc/lionos/greeter.toml.example`.
* Tests: 55 → **93 unit + 14 integration** (107 total); live D-Bus
  suite extended for the 0.6.0 surface.

### Fixed
* n/a (no known 0.5.0 defects; see TEST_REPORT.md for the regression
  matrix).

## [0.5.0] — 2026-09-30

### Added
* PAM conversation forwarding (`ConvBridge`, `ConversationPrompt` /
  `ReplyConversation`, single-use ids, 1024-byte answer cap, 30 s
  deadline, cooperative cancel) — stock 2FA/smartcard PAM stacks now
  work unmodified.
* Autologin: `[autologin] user/delay_ms/relogin`, countdown signals,
  `CancelAutologin`, dedicated `lion-greeter-autologin` PAM stack,
  `AutologinUnavailable` fallback that never charges the throttle.
* `mlockall` secret pinning with RLIMIT guard and
  Capabilities-reported truth (`mlock.rs`).
* Config file layer (`config.rs`, hand-parsed TOML subset, zero new
  deps) with the can-never-block-login guarantee; `--check-config`.
* Metrics: autologin_fires/aborts. systemd unit hardening
  (LimitMEMLOCK=infinity, @memory-lock syscall group).

## [0.4.0] — 2026-09-29
* Initial reviewed release: PAM auth on a worker thread, per-user
  exponential throttle, 600 ms constant failure latency, zeroized
  one-shot password, fd-close/uid-drop/RLIMIT_CORE session handoff,
  D-Bus surface (ListUsers/Authenticate/CancelAuth/metrics), user
  enumeration with avatars, progress signals, `--check-pam`.
