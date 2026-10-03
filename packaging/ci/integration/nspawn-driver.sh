# nspawn-driver.sh — runs INSIDE the container (bind-mounted from the
# source tree). Speaks the real protocol to the daemon over the real
# socket with the real PAM stack.

set -u
SOCK=/run/lion-greeter/ui.sock

echo "== start daemon (socket-activated path skipped; direct) =="
systemd-run --unit=lion-greeter.service --property=Type=notify \
    /usr/bin/lion-greeter --config /etc/lion/greeter.json &
sleep 1

python3 - <<'EOF'
import json, socket, sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(30)
sock.connect("/run/lion-greeter/ui.sock")
sock.sendall(b'{"proto":1,"id":1,"op":"ListUsers"}\n')
print("ListUsers:", sock.recv(65536)[:120])

# real PAM: wrong password first
sock.sendall(b'{"proto":1,"id":2,"op":"StartAuth","user":"otto"}\n')
sock.sendall(b'{"proto":1,"id":3,"op":"AnswerPrompt","text":"wrong"}\n')
print("auth(wrong):", sock.recv(65536)[:200])

# real PAM: correct password
sock.sendall(b'{"proto":1,"id":4,"op":"StartAuth","user":"otto"}\n')
sock.sendall(b'{"proto":1,"id":5,"op":"AnswerPrompt","text":"hunter2"}\n')
data = sock.recv(65536)
print("auth(right):", data[:200])
if b'"ok":false' in data:
    # throttle may hold after the failure; drain and retry after sleep
    import time
    time.sleep(2)
    sock.sendall(b'{"proto":1,"id":6,"op":"StartAuth","user":"otto"}\n')
    sock.sendall(b'{"proto":1,"id":7,"op":"AnswerPrompt","text":"hunter2"}\n')
    data = sock.recv(65536)
    print("auth(retry):", data[:200])

# launch: real logind registration + exec of the stub lion-session
sock.sendall(b'{"proto":1,"id":8,"op":"Launch","session":"lion"}\n')
data = sock.recv(65536)
print("launch:", data[:200])
assert b'"ok":true' in data, "launch failed"
EOF

echo "== session process env =="
cat /run/lion-session-env.txt 2>/dev/null | head -20

echo "== logind session registered? =="
loginctl list-sessions --no-legend | head -5

echo "NSPAWN-INTEGRATION: DONE"
