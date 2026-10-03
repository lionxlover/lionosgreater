#!/bin/bash
# systemd-nspawn integration test (spec 01 §10): a real PAM stack, a real
# logind, and the real launcher, inside a throwaway container.
#
# usage: nspawn-run.sh /path/to/lion-greeter-binary
#
# Runs as root (CI provides sudo). The container gets:
#   - the built daemon binary
#   - the shipped PAM stacks + a test user with a known password
#   - systemd as PID1 (logind active, system bus up)
# The driver (tests/nspawn.rs) then exercises:
#   password auth success/failure, throttling, session launch with real
#   logind registration, and setuid exec into a stub lion-session.

set -eu

BIN=$(readlink -f "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=/tmp/lion-greeter-nspawn

command -v systemd-nspawn >/dev/null || { echo "systemd-nspawn not available"; exit 1; }

rm -rf "$ROOT"
mkdir -p "$ROOT"/{usr/bin,usr/lib/systemd/system,etc/pam.d,etc/lion,run,home,var/lib,usr/sbin}
cp "$BIN" "$ROOT/usr/bin/lion-greeter"
cp "$HERE/../../pam/lion-greeter" "$ROOT/etc/pam.d/"
cp "$HERE/../../pam/lion-greeter-autologin" "$ROOT/etc/pam.d/"
cp "$HERE/../../systemd/nspawn-trigger.service" "$ROOT/usr/lib/systemd/system/" 2>/dev/null || true

# stub session target: a shell script that records its env and exits
cat > "$ROOT/usr/bin/lion-session" <<'EOF'
#!/bin/sh
env | sort > /run/lion-session-env.txt
echo "lion-session ran as $(id -un) uid=$(id -u)"
EOF
chmod 0755 "$ROOT/usr/bin/lion-session"

# users: root + test user 'otto' with password 'hunter2'
cp /etc/passwd /etc/group "$ROOT/etc/"
sed -i '/otto/d' "$ROOT/etc/passwd"
echo 'otto:x:2000:2000:Otto Test:/home/otto:/bin/bash' >> "$ROOT/etc/passwd"
echo 'otto:x:2000:' >> "$ROOT/etc/group"
mkdir -p "$ROOT/home/otto"
cp -r /root/.ssh "$ROOT/home/otto" 2>/dev/null || true
# shadow: generate the hash inside the container (chpasswd below)
cp /etc/shadow "$ROOT/etc/shadow" 2>/dev/null || touch "$ROOT/etc/shadow"

cat > "$ROOT/etc/lion/greeter.json" <<'EOF'
{ "greeter": { "ui_uid": 0, "pam": { "timeout_seconds": 10 } } }
EOF

# boot with systemd, set the test password, run the driver, poweroff
systemd-nspawn --boot --directory "$ROOT" \
    --bind-ro="$HERE/../../.." \
    /bin/sh -c '
      echo "otto:hunter2" | chpasswd
      lion-greeter --check-config
      systemd-run --wait /bin/sh /bind/nspawn-driver.sh
      poweroff
    '
