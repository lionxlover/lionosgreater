#!/usr/bin/env bash
# Live D-Bus integration test for lion-greeter 0.6.1.
#
# Runs the real release binary against a private dbus-daemon (wired via
# DBUS_SYSTEM_BUS_ADDRESS) and exercises the full surface:
#   * classic methods/properties (regression from 0.4)
#   * conversation-forwarding plumbing (ReplyConversation stale-id
#     refusal, empty-batch and >1 KiB answer-cap guards)
#   * 0.6.1: CancelAuth racing libpam mid-verification — the attempt
#     resolves as canceled (never a bogus wrong-password), the
#     AuthCanceled signal fires, and the esc-raced failure still
#     counts toward the throttle
#   * autologin countdown + CancelAutologin, live over the bus
#   * 0.6.0: XDG session listing from a fixture directory,
#     AuthenticateSession validation, DefaultSession/LastSession
#     properties, seat-switch refusal without logind, AuthMethods
#     property with a live fprintd probe
#   * graceful mlock degradation (this sandbox caps RLIMIT_MEMLOCK=64K,
#     so Capabilities must NOT advertise "mlock")
#   * CLI inspection modes (--check-config/--list-sessions/--list-methods
#     with a real config file and session dir)
#
# Exit code: number of failed checks (0 = all green).

set -u
# Self-locating: resolve the repo root from this script's own path, so
# the suite works from any checkout / extracted zip without edits.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
BIN=$ROOT/target/release/lion-greeter
if [ ! -x "$BIN" ]; then
  echo "release binary missing at $BIN — run: cargo build --release" >&2
  exit 125
fi
WORK=$(mktemp -d /tmp/lion-greeter-live.XXXXXX)
PASS=0; FAIL=0

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  [PASS] $*"; }
bad()  { FAIL=$((FAIL+1)); say "  [FAIL] $*"; }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2' want '$3')"; fi; }
has()  { case "$2" in *"$3"*) ok "$1";; *) bad "$1 (missing '$3' in: ${2:0:200})";; esac; }
nothas(){ case "$2" in *"$3"*) bad "$1 (unexpected '$3')";; *) ok "$1";; esac; }

# ── private bus ────────────────────────────────────────────────────────
cat > "$WORK/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=$WORK/bus.sock</listen>
  <policy context="default">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
dbus-daemon --config-file="$WORK/bus.conf" --nopidfile --print-address=1 > "$WORK/bus.addr" 2>/dev/null &
BUS_PID=$!
for _ in $(seq 1 50); do [ -S "$WORK/bus.sock" ] && break; sleep 0.1; done
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=$WORK/bus.sock"
BUSCTL="busctl --address=$DBUS_SYSTEM_BUS_ADDRESS"
NAME=org.lionos.Greeter
PATH_O=/org/lionos/Greeter
IFACE=org.lionos.Greeter1

say "== lion-greeter 0.6.1 live D-Bus test (bus: $WORK/bus.sock) =="

# ── phase 1: daemon up, 0.4 surface regression ────────────────────────
STATE_DIR="$WORK/state"; mkdir -p "$STATE_DIR"

# 0.6.0 session fixtures: the daemon lists these through
# LION_GREETER_SESSIONS_PATH exactly as it would /usr/share/wayland-sessions.
SESS_DIR="$WORK/sessions"; mkdir -p "$SESS_DIR"
cat > "$SESS_DIR/lion.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=LionOS Desktop
Comment=The default LionOS Wayland session
Exec=lion-session
DesktopNames=LionOS;
EOF
printf '[Desktop Entry]\nType=Application\nName=Hidden\nExec=x\nHidden=true\n' > "$SESS_DIR/hidden.desktop"
printf 'not a desktop file at all\n' > "$SESS_DIR/broken.desktop"

cat > "$SESS_DIR/x11-games.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Legacy X11 Thing
Exec=xinit-thing
EOF
# x11 classification via directory name:
X11_DIR="$WORK/x11-sessions"; mkdir -p "$X11_DIR"
mv "$SESS_DIR/x11-games.desktop" "$X11_DIR/x11-games.desktop"
export LION_GREETER_SESSIONS_PATH="$SESS_DIR:$X11_DIR"

STATE_DIRECTORY="$STATE_DIR" RUST_LOG=info "$BIN" --daemon > "$WORK/daemon.log" 2>&1 &
D_PID=$!
for _ in $(seq 1 100); do
  $BUSCTL status "$NAME" >/dev/null 2>&1 && break; sleep 0.1
done
if $BUSCTL status "$NAME" >/dev/null 2>&1; then ok "daemon owns $NAME"; else bad "daemon did not acquire $NAME"; cat "$WORK/daemon.log"; fi

V=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" Version 2>/dev/null | awk -F'"' '{print $2}')
check "Version property" "$V" "0.6.1"

CAPS=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" Capabilities 2>/dev/null)
has    "Capabilities advertises conversation relay" "$CAPS" 'conversation'
has    "Capabilities advertises autologin"          "$CAPS" 'autologin'
has    "Capabilities advertises cancel (0.4 parity)" "$CAPS" 'cancel'
has    "Capabilities advertises sessions (0.6.0)"    "$CAPS" 'sessions'
has    "Capabilities advertises auth-methods (0.6.0)" "$CAPS" 'auth-methods'
nothas "Capabilities hides mlock under 64K limit"   "$CAPS" 'mlock'
# logind is not on the private test bus: the seat capability must be
# hidden, and every seat method must refuse — never error out the bus.
nothas "Capabilities hides seat-switch without logind" "$CAPS" 'seat-switch'

AU=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" AutologinUser 2>/dev/null | awk -F'"' '{print $2}')
check "AutologinUser empty without config" "$AU" ""

LU=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ListUsers 2>/dev/null)
has "ListUsers returns JSON user entries" "$LU" 'username'
has "ListUsers includes eligible uid>=1000 user" "$LU" 'full_name'

# conversation API: stale id must be refused (u64 -> signature 't')
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ReplyConversation tas 999 1 "x" 2>/dev/null)
has "ReplyConversation refuses stale id" "$R" 'false'

# conversation answer guards: an empty batch or an over-long answer is
# refused before any id lookup (MAX_ANSWER_BYTES = 1024 — a hostile
# client must not park megabytes in the root daemon's heap)
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ReplyConversation tas 999 0 2>/dev/null)
has "ReplyConversation refuses empty answer batch" "$R" 'false'
LONG_ANSWER=$(awk 'BEGIN{s="";for(i=0;i<1088;i++)s=s "A";print s}')
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ReplyConversation tas 999 1 "$LONG_ANSWER" 2>/dev/null)
has "ReplyConversation refuses over-long (>1 KiB) answer" "$R" 'false'

# cancel when nothing armed
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" CancelAutologin 2>/dev/null)
has "CancelAutologin idle->false" "$R" "false"

# authenticate bogus user (never touches PAM): same-path failure
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" Authenticate ss "nosuchuser" "pw" 2>/dev/null)
has "Authenticate unknown user fails cleanly" "$R" "false"

# authenticate real user with wrong password: exercises the LIVE PAM
# bridge (pam_unix prompts; the bridge answers from the stored password)
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" Authenticate ss "z" "definitely-wrong-password" 2>/dev/null)
has "Authenticate wrong password fails (bridge answered pam_unix)" "$R" "false"
sleep 1.5  # let the 600 ms constant-latency elapse

# throttling kicks in on repeat failure for the same user
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" Authenticate ss "z" "wrong-again" 2>/dev/null)
has "Throttle engages on repeated failure" "$R" "false"

M=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" GetMetrics 2>/dev/null)
has "Metrics exposes autologin_fires" "$M" 'autologin_fires'
has "Metrics counts attempts"         "$M" 'auth_attempts'
has "Metrics exposes seat_switches (0.6.0)" "$M" 'seat_switches'

# ── phase 1.5: the 0.6.0 surface, live ─────────────────────────────────
say "== phase 1.5: sessions / seat / auth methods =="

LS=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ListSessions 2>/dev/null)
has "ListSessions lists the fixture session"    "$LS" 'lion'
has "ListSessions carries the display name"    "$LS" 'LionOS Desktop'
has "ListSessions classifies wayland dir"      "$LS" 'wayland'
has "ListSessions classifies x11 dir"          "$LS" 'x11'
nothas "ListSessions filters Hidden=true"       "$LS" 'Hidden'
nothas "ListSessions filters broken files"      "$LS" 'broken'

FLS=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" LastSession 2>/dev/null | awk -F'"' '{print $2}')
check "LastSession empty before any login" "$FLS" ""

DS=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" DefaultSession 2>/dev/null | awk -F'"' '{print $2}')
check "DefaultSession empty without config" "$DS" ""

AM=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" AuthMethods 2>/dev/null)
has "AuthMethods always offers password" "$AM" 'password'
has "AuthMethods is JSON with availability" "$AM" 'available'

# Seat surface without logind: polite refusal, empty snapshot.
LSS=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ListSeatSessions 2>/dev/null | awk -F'"' '{print $2}')
check "ListSeatSessions empty without logind" "$LSS" "[]"

R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" SwitchToVT u 2 2>/dev/null)
has "SwitchToVT refuses without logind" "$R" 'unavailable'
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" SwitchToVT u 99 2>/dev/null)
has "SwitchToVT refuses out-of-range VT"   "$R" 'range'
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ActivateSession s "12" 2>/dev/null)
has "ActivateSession refuses without logind" "$R" 'unavailable'
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" ActivateSession s "../evil" 2>/dev/null)
has "ActivateSession rejects malformed id"  "$R" 'Malformed'
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" LockSession s "c1" 2>/dev/null)
has "LockSession refuses without logind"    "$R" 'unavailable'

# AuthenticateSession validation ordering: a bogus session id is
# rejected BEFORE any auth happens (no throttle charge, no PAM call).
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" AuthenticateSession sss "z" "pw" "not-installed" 2>/dev/null)
has "AuthenticateSession rejects uninstalled id" "$R" 'not installed'
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" AuthenticateSession sss "z" "pw" "../etc/passwd" 2>/dev/null)
has "AuthenticateSession rejects malformed id"   "$R" 'Malformed'
# A VALID session id resolves and proceeds into (failing) auth: the
# failure message must be an auth one, not a session one.
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" AuthenticateSession sss "z" "wrong-password" "lion" 2>/dev/null)
has  "AuthenticateSession with valid id reaches auth"  "$R" 'false'
nothas "AuthenticateSession valid id not a session error" "$R" 'not installed'
sleep 1.5

kill "$D_PID" 2>/dev/null; wait "$D_PID" 2>/dev/null

# ── phase 1.7: CancelAuth racing libpam (fresh daemon: clean throttle) ──
# pam_authenticate is an uninterruptible FFI call; a cancel that lands
# mid-verification must still be honored at result time (0.6.1) — the
# UI that pressed Esc sees "Sign-in was canceled", never a bogus
# "wrong password", and the failure still counts toward the throttle.
say "== phase 1.7: CancelAuth mid-flight =="
mkdir -p "$WORK/state3"
STATE_DIRECTORY="$WORK/state3" RUST_LOG=info "$BIN" --daemon > "$WORK/daemon3.log" 2>&1 &
D3_PID=$!
for _ in $(seq 1 100); do $BUSCTL status "$NAME" >/dev/null 2>&1 && break; sleep 0.1; done

timeout -s INT 12 dbus-monitor --address "$DBUS_SYSTEM_BUS_ADDRESS" \
  "type='signal',sender='$NAME',interface='$IFACE',member='AuthCanceled'" \
  > "$WORK/cancel.log" 2>/dev/null &
CMON_PID=$!
sleep 0.3

CANCEL_SEEN=""
for ATTEMPT in 1 2; do
  DELAY=0.02; [ "$ATTEMPT" = 2 ] && DELAY=0.05
  $BUSCTL call "$NAME" "$PATH_O" "$IFACE" Authenticate ss "z" "cancel-race-test-wrong-pw" \
    > "$WORK/cancel_auth$ATTEMPT.out" 2>/dev/null &
  AUTH_PID=$!
  # Wait past PamContext::start (≈1-5 ms) so the cancel lands while
  # the worker is INSIDE pam_authenticate (50-200 ms of hash work) —
  # the 0.6.1 result-time-honored path, not the worker's pre-pam
  # clean-cancel check. Slot is Some from registration until
  # run_login returns, so a true here means the race is live.
  sleep "$DELAY"
  for _ in $(seq 1 40); do
    C=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" CancelAuth 2>/dev/null)
    case "$C" in *true*) CANCEL_SEEN=yes; break;; esac
    sleep 0.003
  done
  wait "$AUTH_PID" 2>/dev/null
  CA_OUT=$(cat "$WORK/cancel_auth$ATTEMPT.out" 2>/dev/null)
  if [ "$CANCEL_SEEN" = yes ] && grep -q "Sign-in was canceled" <<<"$CA_OUT"; then
    ok "CancelAuth mid-flight honored (attempt $ATTEMPT: canceled verdict)"
    break
  fi
  # Miss (bus round-trip lost the race): the attempt failed normally;
  # retry once — the throttle allows two free failures per boot.
  sleep 0.5
done
[ "$CANCEL_SEEN" = yes ] \
  && ok "CancelAuth=true reported while attempt in flight" \
  || bad "CancelAuth never saw an in-flight attempt"
CA_FINAL=$(cat "$WORK/cancel_auth1.out" "$WORK/cancel_auth2.out" 2>/dev/null)
has "raced attempt reports 'Sign-in was canceled' (not wrong-password)" "$CA_FINAL" 'Sign-in was canceled'

# The esc-raced failure must still count toward the throttle. Two free
# failures exist per boot. Two cancel outcomes exist: worker-noticed
# (cancel landed before pam started — clean cancel, pam never ran, no
# failure recorded) and result-time honored (cancel raced pam — the
# failure records). Either way a bounded number of plain failures
# reaches the "Too many attempts" lockout: the attempt that STARTS the
# lockout still says "Incorrect username or password" with
# retry_after_ms>0; the NEXT one is blocked.
R2=""
for i in 1 2 3 4 5; do
  R2=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" Authenticate ss "z" "plain-wrong-pw-$i" 2>/dev/null)
  grep -q 'Too many attempts' <<<"$R2" && break
  sleep 0.3
done
has "esc-raced failure still counted (throttle engages)" "$R2" 'Too many attempts'
sleep 0.5
kill "$CMON_PID" 2>/dev/null; wait "$CMON_PID" 2>/dev/null
grep -q "AuthCanceled" "$WORK/cancel.log" 2>/dev/null \
  && ok "AuthCanceled signal observed live" \
  || bad "AuthCanceled signal missing"
kill "$D3_PID" 2>/dev/null; wait "$D3_PID" 2>/dev/null

# ── phase 2: autologin countdown, live ─────────────────────────────────
say "== phase 2: autologin countdown =="
cat > "$WORK/greeter.toml" <<EOF
[autologin]
user = "z"
delay_ms = 3000
relogin = true

[session]
default = "lion"
EOF
mkdir -p "$WORK/state2"
# capture signals while the daemon counts down
timeout -s INT 6 dbus-monitor --address "$DBUS_SYSTEM_BUS_ADDRESS" \
  "type='signal',sender='$NAME',interface='$IFACE'" > "$WORK/signals.log" 2>/dev/null &
MON_PID=$!
sleep 0.3
STATE_DIRECTORY="$WORK/state2" LION_GREETER_CONFIG="$WORK/greeter.toml" RUST_LOG=info \
  "$BIN" --daemon > "$WORK/daemon2.log" 2>&1 &
D_PID=$!
for _ in $(seq 1 100); do $BUSCTL status "$NAME" >/dev/null 2>&1 && break; sleep 0.1; done

AU=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" AutologinUser 2>/dev/null | awk -F'"' '{print $2}')
check "AutologinUser reflects config" "$AU" "z"
DM=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" AutologinDelayMs 2>/dev/null | awk '{print $2}')
check "AutologinDelayMs reflects config" "$DM" "3000"
DS=$($BUSCTL get-property "$NAME" "$PATH_O" "$IFACE" DefaultSession 2>/dev/null | awk -F'"' '{print $2}')
check "DefaultSession reflects [session] default" "$DS" "lion"

sleep 2  # mid-countdown
R=$($BUSCTL call "$NAME" "$PATH_O" "$IFACE" CancelAutologin 2>/dev/null)
has "CancelAutologin during countdown->true" "$R" "true"
sleep 1

wait "$MON_PID" 2>/dev/null
SIGS=$(cat "$WORK/signals.log")
has "AutologinCountdown signal observed"  "$SIGS" "AutologinCountdown"
has "AutologinAborted(canceled) observed" "$SIGS" "canceled"

kill "$D_PID" 2>/dev/null; wait "$D_PID" 2>/dev/null

# ── phase 3: CLI inspection modes ──────────────────────────────────────
say "== phase 3: CLI modes =="
VV=$("$BIN" --version)
has "--version mentions conversation-forwarding" "$VV" "conversation-forwarding"
has "--version mentions autologin service"      "$VV" "lion-greeter-autologin"
has "--version mentions mlockall"               "$VV" "mlockall"

CC=$(LION_GREETER_CONFIG="$WORK/greeter.toml" "$BIN" --check-config 2>&1)
has "--check-config prints parsed user"    "$CC" "user=z"
has "--check-config prints delay"          "$CC" "delay_ms=3000"
has "--check-config reports file applied"  "$CC" "applied in full"

BAD_CFG="$WORK/broken.toml"; printf '[autologin\nuser = "z"\n' > "$BAD_CFG"
CB=$(LION_GREETER_CONFIG="$BAD_CFG" "$BIN" --check-config 2>&1)
has "--check-config flags broken file"  "$CB" "FAILED"
has "--check-config: logins still work" "$CB" "logins still work"

LUS=$("$BIN" --list-users | head -20)
has "--list-users emits JSON" "$LUS" '"username"'

CLS=$(LION_GREETER_SESSIONS_PATH="$SESS_DIR:$X11_DIR" "$BIN" --list-sessions 2>/dev/null)
has "--list-sessions lists fixture session" "$CLS" 'lion'
has "--list-sessions carries names"        "$CLS" 'LionOS Desktop'
nothas "--list-sessions filters Hidden"    "$CLS" 'Hidden'

# methods: module dir points nowhere, so only password is available.
CLM=$(LION_GREETER_PAM_MODULES_DIR=/nonexistent "$BIN" --list-methods 2>/dev/null)
has "--list-methods offers password"    "$CLM" '"password"'
has "--list-methods flags unavailability" "$CLM" '"available": false'

# A faked module makes fingerprint flag-present-but-unavailable
# (daemon down in this harness): capability, not policy, is what we
# report — the honest state.
FAKE_DIR="$WORK/pam-mods"; mkdir -p "$FAKE_DIR"; : > "$FAKE_DIR/pam_fprintd.so"
CLM2=$(LION_GREETER_PAM_MODULES_DIR="$FAKE_DIR" "$BIN" --list-methods 2>/dev/null)
has "--list-methods sees fprintd module presence" "$CLM2" 'pam_module_present'
nothas "--list-methods: fingerprint not offered without daemon" "$CLM2" '"method":"fingerprint","available":true'

# ── wrap up ────────────────────────────────────────────────────────────
kill "$BUS_PID" 2>/dev/null
say ""
say "== daemon log (excerpt) =="
rg "mlock|RLIMIT|autologin|conversation" "$WORK/daemon.log" "$WORK/daemon2.log" 2>/dev/null | head -8
say "== results: $PASS passed, $FAIL failed =="
rm -rf "$WORK"
exit $FAIL
