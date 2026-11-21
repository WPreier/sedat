#!/usr/bin/env bash
# Entrypoint for compose service `pebble-issue` (profile acme).
# Avoids Compose `$`-interpolation pitfalls in inline YAML scripts.
set -euo pipefail
command -v cargo
mkdir -p /src/state/pebble-ci
for i in $(seq 1 60); do
  if curl -skf https://pebble:14000/dir >/dev/null; then
    echo "pebble ready after ${i}s"
    break
  fi
  sleep 1
done
curl -skf https://pebble:14000/dir
cargo test --test pebble_issue -- --ignored --nocapture
test -f /src/state/pebble-ci/cert.pem
echo OK pebble-issue
