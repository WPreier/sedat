#!/usr/bin/env bash
set -euo pipefail
BASE="${SEDAT_URL:-http://127.0.0.1:8080}"

echo "[e2e] proxy known host"
code=$(curl -sS -o /tmp/sedat_e2e_body -w '%{http_code}' -H 'Host: localhost' "$BASE/")
test "$code" = "200"
grep -qi 'Mock-Seda\|upstream\|client_ip' /tmp/sedat_e2e_body

echo "[e2e] unknown host -> 404"
code=$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "$BASE/")
test "$code" = "404"

echo "[e2e] embedded docs"
curl -sS -H 'Host: localhost' "$BASE/sedat" | grep -qi SeDat

echo "[e2e] OK"
