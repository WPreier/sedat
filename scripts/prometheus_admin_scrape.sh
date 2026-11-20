#!/usr/bin/env bash
# Scrape SeDat Prometheus metrics from the admin Unix socket (no public HTTP).
# Usage: scripts/prometheus_admin_scrape.sh [/path/to/admin.sock]
# If SEDAT_ADMIN_TOKEN is set, AUTH is sent first (P10.4).
set -euo pipefail
SOCK="${1:-./state/admin.sock}"
if [[ ! -S "$SOCK" ]]; then
  echo "admin socket not found: $SOCK" >&2
  exit 1
fi
if [[ -n "${SEDAT_ADMIN_TOKEN:-}" ]]; then
  CMD=$(printf 'AUTH %s\nmetrics\n' "$SEDAT_ADMIN_TOKEN")
else
  CMD=$(printf 'metrics\n')
fi
# Strip the "OK metrics" first line for Prometheus text parsers.
# Also drop a leading "OK auth" line when token auth is used.
if command -v socat >/dev/null 2>&1; then
  printf '%s' "$CMD" | socat - "UNIX-CONNECT:${SOCK}" | sed '/^OK auth$/d;/^OK metrics$/d'
elif command -v nc >/dev/null 2>&1; then
  printf '%s' "$CMD" | nc -U "$SOCK" | sed '/^OK auth$/d;/^OK metrics$/d'
else
  echo "need socat or nc -U to scrape admin socket" >&2
  exit 1
fi
