# Migration notes — lion-greeter

This is release 0.1.0 (spec 01, MVP + v1-partial). Notes for packagers,
administrators and client authors on upgrading.

## Protocol (proto 1)

- 0.1.0 is the first protocol release; there is nothing to migrate from
  within LionOS.
- **Compatibility policy**: within `proto: 1`, changes are additive only
  — new response fields, new error codes, new event fields. Clients must
  ignore unknown fields (the reference client does).
- Bumping to `proto: 2` (only for breaking changes) requires: the daemon
  keeps answering `proto: 1` for one release cycle, `proto_version`
  errors carry the supported version, and both protocols are documented
  side-by-side in `docs/PROTOCOL.md`.
- Ids: from 0.1.0, *every* response — including decode errors — echoes
  the request id whenever it could be parsed (field-level failures
  included). Earlier dev builds (pre-release) always used `id: 0` on
  decode errors; clients written against those builds must not rely on
  that.

## Configuration (lion-config, `greeter.*`)

| Key | Since | Notes |
|---|---|---|
| `greeter.autologin.user` / `.session` / `.service` | 0.1.0 | autologin requires the `lion-autologin` PAM group |
| `greeter.timed_login.user` / `.delay_seconds` | 0.1.0 | cancels on any client request |
| `greeter.show_user_list` | 0.1.0 | `false` → "type your username" mode |
| `greeter.allow_guest` + `greeter.guest.*` | 0.1.0 | guest account `lion-guest` must exist |
| `greeter.default_session` | 0.1.0 | |
| `greeter.ui_user` / `greeter.ui_uid` | 0.1.0 | `ui_uid` is a dev/test override |
| `greeter.socket_path` | 0.1.0 | shipping path `/run/lion-greeter/ui.sock` |
| `greeter.pam.service` / `.timeout_seconds` | 0.1.0 | |
| `greeter.throttle.enabled` / `.cap_seconds` | 0.1.0 | soft layer; pam_faillock stays authoritative |
| `greeter.min_uid` / `max_uid` | 0.1.0 | |
| `greeter.wayland_sessions_dir` / `accountsservice_dir` / `state_dir` | 0.1.0 | |
| `greeter.passwd_path` / `group_path` | 0.1.0 | test/nspawn fixtures; keep default in production |
| `greeter.seat` / `greeter.power.allowed` | 0.1.0 | |

The loader is strict: unknown keys, wrong types and out-of-range values
are hard errors at startup (fail closed) and during `--check-config`.
Renaming a key therefore requires a release note entry here and a
`lion-config` schema update in the same release.

## Packaging

- PAM stacks: `/etc/pam.d/lion-greeter` and
  `/etc/pam.d/lion-greeter-autologin` ship as conffiles — local edits
  survive; removing the package leaves them (dpkg conffile semantics,
  CLP mirrors them).
- systemd: enable `lion-greeter.socket` (not the service — the socket
  activates it); the service aliases `display-manager.service` and
  therefore conflicts with getty@tty1 and any other DM.
- Upgrades: `systemctl restart lion-greeter.service` drops connected
  UIs (they reconnect via the socket unit within seconds); a rolling
  config change can instead use `SIGHUP` (live reload, no disconnect).

## State

- `/var/lib/lion-greeter/last-session/<user>` (0700, root): per-user
  session memory. Safe to delete; users fall back to
  `greeter.default_session` / AccountsService `Session=`.
- No other persistent state. No secrets are ever written.
