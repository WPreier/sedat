#!/usr/bin/env bash
set -euo pipefail
BASE="${1:-http://127.0.0.1:8080}"
echo "== known host =="
curl -sS -H 'Host: localhost' "$BASE/" | head -n 5
echo
echo "== unknown host (expect 404) =="
curl -sS -o /dev/null -w 'status=%{http_code}\n' -H 'Host: evil.test' "$BASE/"
echo "== docs =="
curl -sS -H 'Host: localhost' "$BASE/sedat" | head -n 3
