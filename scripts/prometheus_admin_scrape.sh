#!/usr/bin/env bash
# Scrape SeDat Prometheus metrics from the admin Unix socket (no public HTTP).
# Usage: scripts/prometheus_admin_scrape.sh [/path/to/admin.sock]
set -euo pipefail
SOCK="${1:-./state/admin.sock}"
if [[ ! -S "$SOCK" ]]; then
  echo "admin socket not found: $SOCK" >&2
  exit 1
fi
# Strip the "OK metrics" first line for Prometheus text parsers.
if command -v socat >/dev/null 2>&1; then
  printf 'metrics\n' | socat - "UNIX-CONNECT:${SOCK}" | sed '1{/^OK metrics$/d;}'
elif command -v nc >/dev/null 2>&1; then
  printf 'metrics\n' | nc -U "$SOCK" | sed '1{/^OK metrics$/d;}'
else
  echo "need socat or nc -U to scrape admin socket" >&2
  exit 1
fi
