#!/usr/bin/env bash
# Fully automated Pebble DNS-01 issuance (no LE staging network).
# Expects Pebble at https://localhost:14000/dir with PEBBLE_VA_ALWAYS_VALID=1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STATE="${SEDAT_STATE_DIR:-$(mktemp -d)}"
mkdir -p "$STATE"
CFG="$STATE/sedat-pebble.toml"
DNS_FILE="$STATE/acme-dns-challenge.txt"

cat >"$CFG" <<EOF
schema_version = 1

[server]
listen = "127.0.0.1:18080"
listen_tls = "127.0.0.1:18443"
http_redirect_listen = "127.0.0.1:18081"
state_dir = "$STATE"
admin_socket = "$STATE/admin.sock"

[tls]
enabled = false

[acme]
enabled = true
directory = "pebble"
email = "ci@example.com"
domains = ["test.local"]
dns_provider = "file"
dns_file = "$DNS_FILE"

[[routes.hosts]]
host = "test.local"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"

[proxy_protocol]
outbound = "off"
inbound_enabled = false
inbound_allowlist = []

[hardening]
landlock = "off"
seccomp = "off"

[logging]
level = "info"
EOF

echo "==> waiting for Pebble directory"
for i in $(seq 1 60); do
  if curl -skf https://localhost:14000/dir >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -skf https://localhost:14000/dir >/dev/null

echo "==> cargo test / build (ensure binary)"
cargo build -q

echo "==> running issuance helper via example binary path"
# Use a small rustc-driven one-shot through `cargo run` with env:
# Prefer dedicated test binary when available; fall back to library test harness.
export SEDAT_PEBBLE_ISSUE_CFG="$CFG"
export SEDAT_PEBBLE_ISSUE_STATE="$STATE"
cargo test -q --test pebble_issue -- --ignored --nocapture

test -f "$STATE/cert.pem"
test -f "$STATE/key.pem"
echo "OK pebble issuance wrote $STATE/cert.pem"
