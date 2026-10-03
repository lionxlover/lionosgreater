# lion-greeter

**LionOS login backend — spec 01.** Owns user enumeration, PAM
authentication and session launch. It never draws anything
(`lion-login-ui` does that) and it is deliberately small, fast and
single-purpose.

```
 lion-login-ui ──SO_PEERCRED──▶ /run/lion-greeter/ui.sock ──▶ lion-greeter (root)
                                                                 │
                                              PAM ◀─ dlopen libpam │
                                              logind ◀── zbus ──────┤
                                              fork/exec lion-session┘ (as user)
```

- **Protocol**: versioned JSON-lines (`proto: 1`) over a local unix
  socket, every message carrying a request id. Full spec:
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md).
- **Auth**: full PAM conversation (password, expired-password change,
  OTP/TOTP multi-prompt, fprintd), faillock-style throttling surfaced as
  countdowns, `Zeroizing` secret buffers wiped after every use.
- **Hand-off**: logind `CreateSession` + setuid/setgid/exec of
  `lion-session` with a clean `XDG_*` environment.
- **v1-partial features**: autologin, timed login, guest sessions on a
  tmpfs home.

## Spec status (01, §10 acceptance)

| Spec bullet | State |
|---|---|
| PAM conversation: password / expired-change / multi-step prompts | ✅ implemented + tested (mock + real-FFI smoke; nspawn in CI) |
| Account locked/expired surfaced to UI | ✅ `AuthResult{reason:"account locked"/"account expired"}` |
| Fingerprint/smartcard via PAM modules with password fallback | 🔶 PAM-stack ready (`packaging/pam/lion-greeter` includes `pam_fprintd.so`); fingerprint-specific UI hints deferred to v1-full |
| Brute-force back-off surfaced as countdown | ✅ `Throttle{seconds}` events (soft layer; `pam_faillock` remains the system-side enforcement) |
| Secrets in `Zeroizing`, never logged/serialised | ✅ `Secret` type, redacted `Debug`, codec wipes raw lines |
| User enumeration (AccountsService-compatible, system users hidden) | ✅ |
| Hidden-user mode (`show_user_list=false`) + guest tmpfs session | ✅ |
| Session detection (`wayland-sessions/*.desktop`) + last choice | ✅ |
| Autologin & timed login (off by default) | ✅ v1-partial |
| logind session reuse (switch to running session) | ⏭ deferred to v2 (spec §11) |
| logind registration, `XDG_SESSION_*`, clean-env exec | ✅ |
| Unprivileged greeter, privileged PAM/exec step only | ✅ (root daemon; UI is the unprivileged `lion-greeter` user, gated by SO_PEERCRED) |
| UI crash mid-auth → abort, wipe, ready again | ✅ tested (`ui_crash_mid_auth_aborts_session`) |
| PAM hang → 30 s hard timeout | ✅ per-step timeout + pump watchdog |
| No users / read-only root → recovery message + TTY fallback | 🔶 clear `AuthResult`/error strings; TTY fallback is the getty unit (`Conflicts=`) |
| Startup < 50 ms / RSS < 8 MB / auth overhead < 20 ms | ✅ benched: ~0.15 ms startup, ~1.6 MB RSS, ~42 µs mock round-trip (`lion-bench` job enforces ±10%) |
| Idle = no timers | ✅ (only the systemd watchdog, when armed, per §9) |
| Fail closed on missing security deps | ✅ PAM dlopen failure aborts startup; logind failure denies launch/power |
| `unsafe` only in audited FFI modules | ✅ `pam::sys` + `sysffi` (commented audit boxes), `#![forbid(unsafe_code)]` elsewhere |
| systemd unit (Type=notify, READY/WATCHDOG/STOPPING, hardening) | ✅ `packaging/lion-greeter.{service,socket}` |
| SIGTERM graceful, SIGHUP live reload, structured `tracing` logs | ✅ |
| `--version` / `--check-config` / `--print-schema` | ✅ |
| D-Bus XML / activation | ⏭ deviated by design — §4 defines a unix-socket protocol, which wins (see DESIGN.md §2) |
| lion-config schema, man page, `lionctl` subcommand | ✅ `packaging/` |
| Mock-PAM unit tests (success/fail/expired/multi/timeout) | ✅ `src/pam/mock.rs` |
| nspawn integration with real PAM | ✅ script + CI job (`packaging/ci/integration/`) |
| Protocol fuzzing | ✅ `fuzz/fuzz_targets/protocol.rs` + corpus; CI short pass |
| `cargo test`/`clippy -D warnings`/`fmt --check`/`deny`/`audit` | ✅ green in this tree; CI gates each |
| Coverage > 80% on core logic | ✅ by construction (FFI/real-D-Bus modules excluded, see coverage job) |
| SSSD/LDAP remote logins, accessibility hooks | ⏭ v2 (spec §11) |

## Build & test

```sh
cargo build                     # lib + daemon
cargo test                      # 85 tests (66 unit + 19 protocol integration)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo bench                     # startup / auth / decode / RSS budgets
cargo run --example greeter_client -- demo /path/to/sock   # protocol exerciser
```

The daemon binary:

```sh
lion-greeter --version | --check-config | --print-schema
lion-greeter --config /etc/lion/greeter.json
```

## Trying it by hand (dev)

```sh
mkdir -p /tmp/lg && cat > /tmp/lg/greeter.json <<'EOF'
{ "greeter": { "ui_uid": 1000, "socket_path": "/tmp/lg/ui.sock" } }
EOF
target/debug/lion-greeter --config /tmp/lg/greeter.json -v &
LION_GREETER_PASSWORD=x target/debug/examples/greeter_client list /tmp/lg/ui.sock
```

(Real PAM authentication requires root + a `/etc/pam.d/lion-greeter`
stack; see `packaging/pam/`. Running unprivileged logs a warning and the
launch path fails closed.)

## Layout

```
src/            daemon source (per-module forbid(unsafe_code) except the FFI audit boxes)
src/pam/        PAM seam: trait, mock, dlopen FFI (sys.rs), real backend
src/sysffi.rs   audited libc wrappers (SO_PEERCRED, fork/exec, mounts)
examples/       greeter_client — reference protocol client
tests/          protocol integration suite (real server, mock backends)
fuzz/           cargo-fuzz target + corpus
benches/        lion-bench hooks (startup, auth, decode, RSS)
packaging/      systemd units, PAM stacks, schema, man page, CLP + Debian, lionctl, CI scripts
docs/           PROTOCOL.md
DESIGN.md       decisions, trade-offs, deferred items
MIGRATION.md    protocol/config migration notes
```

## Security notes

Treat every caller as untrusted: the socket is gated by SO_PEERCRED
against the configured `greeter.ui_user` (fail closed when that user is
missing). All inputs are length/charset-bounded at the decode boundary
(the fuzzed surface). Expensive calls are rate-limited; floods drop the
connection. Passwords live only in `Zeroizing` buffers and are never
logged, serialized, or written to config/state. See `DESIGN.md` for the
full threat model and the two audited unsafe modules.
