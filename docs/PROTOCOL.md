# lion-greeter UI protocol — `proto: 1`

Spec 01 §4. One JSON object per line (JSON-lines, UTF-8, LF-delimited,
no CR required). Every message — request, response and event — carries
`"proto": 1` and a `request id` echoed from the originating request.

- Transport: `AF_UNIX` stream socket `/run/lion-greeter/ui.sock`
  (0660 root:lion-greeter). The daemon verifies `SO_PEERCRED` on accept
  and drops connections from any other uid (fail closed).
- Bounds (enforced by the daemon; clients should stay well inside):
  8192 bytes per line, 64 bytes for identifiers, 1024 bytes for answer
  text, sustained 64 messages/second, per-op rate gaps, 8 concurrent
  connections.
- Protocol mismatches (`proto != 1`) are fatal: the daemon replies once
  and closes. All other errors are per-request error objects.

## Requests (client → daemon)

```json
{"proto":1,"id":1,"op":"ListUsers"}
{"proto":1,"id":2,"op":"ListSessions"}
{"proto":1,"id":3,"op":"StartAuth","user":"alice"}
{"proto":1,"id":4,"op":"AnswerPrompt","text":"secret-or-visible-answer"}
{"proto":1,"id":5,"op":"CancelAuth"}
{"proto":1,"id":6,"op":"Launch","session":"lion"}
{"proto":1,"id":7,"op":"Power","action":"reboot"}   // reboot|poweroff|suspend
```

Unknown ops, unknown fields, out-of-bounds values → `bad_request`
(never a panic; the parser is the fuzzed surface).

## Responses (daemon → client)

Success:

```json
{"proto":1,"id":1,"ok":true,"result":{ ... }}
```

Failure:

```json
{"proto":1,"id":1,"ok":false,"error":{"code":"no_such_user","message":"no such user"}}
```

Error codes: `bad_request`, `proto_version`, `unknown_op`,
`rate_limited`, `busy`, `no_such_user`, `not_authenticated`,
`throttled`, `not_allowed`, `no_such_session`, `launch_failed`,
`power_denied`, `internal`.

### Result payloads

`ListUsers`:

```json
{"users":[{"name":"alice","uid":1000,"real_name":"Alice Lion",
           "shell":"/bin/bash","avatar":"/var/lib/AccountsService/icons/alice",
           "last_session":"lion","is_guest":false}],
 "show_user_list":true,"allow_guest":false}
```

`ListSessions` (installable session types; the builtin `lion` session is
always first):

```json
{"sessions":[{"id":"lion","name":"Lion","exec":"lion-session","builtin":true},
             {"id":"sway","name":"Sway","exec":"sway","builtin":false}],
 "default":"lion"}
```

`StartAuth`:

```json
{"started":true,"user":"alice"}
```

`Launch` (`session_id` = logind session id):

```json
{"session_id":"c2","pid":4242}
```

`Power` / `AnswerPrompt` / `CancelAuth`:

```json
{}
```

## Events (daemon → client, asynchronous)

Events carry the id of the `StartAuth` request that opened the
conversation. `Prompt{kind:info}` with id `0` is used for daemon-level
messages (timed-login countdowns).

```json
{"proto":1,"id":3,"event":"Prompt","kind":"secret","text":"Password: "}
{"proto":1,"id":3,"event":"AuthResult","ok":false,"reason":"authentication failed"}
{"proto":1,"id":3,"event":"Throttle","seconds":8}
```

- `Prompt.kind`: `secret` (echo off), `visible` (echo on), `info`,
  `error`.
- `AuthResult.reason` (stable, generic, non-revealing): `ok`,
  `authentication failed`, `account expired`, `account locked`,
  `password change failed`, `cancelled`, `timed out`,
  `authentication service unavailable`.
- `Throttle.seconds`: remaining lock-out; emitted right after a failed
  `AuthResult` and again (via the `throttled` error) on premature retry.

## Conversation flows

Password login:

```text
C: StartAuth{alice}            S: {started:true} … Prompt{secret,"Password: "}
C: AnswerPrompt{"pw"}          S: {} … AuthResult{ok:true,reason:"ok"}
C: Launch{"lion"}              S: {session_id:"c2",pid:4242}
```

Expired password (chauthtok through the same conversation):

```text
Prompt{secret,"Current password: "} → AnswerPrompt
Prompt{secret,"New password: "}      → AnswerPrompt
Prompt{secret,"Retype new password: "} → AnswerPrompt
AuthResult{ok:true|false, …}
```

Multi-step (OTP):

```text
Prompt{secret,"Password: "} → AnswerPrompt
Prompt{visible,"OTP code: "} → AnswerPrompt
AuthResult{…}
```

Cancellation & failure modes:

- `CancelAuth` → `AuthResult{ok:false,reason:"cancelled"}` (idempotent).
- Client disconnect mid-conversation → the daemon aborts PAM, wipes
  buffers and is immediately ready for a reconnected UI.
- No answer within the PAM step timeout (default 30 s) →
  `AuthResult{ok:false,reason:"timed out"}`.

## Timed login

When `greeter.timed_login.user` is configured, a connected client
receives per-second countdown `Prompt{kind:info,id:0}` lines
(`"Logging in as NAME in N s"`). Any request from the client cancels the
countdown; at zero the daemon starts the passwordless transaction and,
if PAM permits it, launches the session automatically.

## Versioning

Additive changes (new result fields, new error codes, new event fields)
do not bump `proto`. A future `proto: 2` is reserved for breaking
changes; the daemon answers `proto_version` and closes the connection on
any `proto` it does not speak. See `MIGRATION.md`.
