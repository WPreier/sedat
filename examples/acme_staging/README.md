# Phase 3 – ACME staging / Pebble runbook

## Local self-signed (offline)

```bash
# Enable TLS in config (tls.enabled=true) or acme.enabled with domains
# Without a reachable CA, SeDat installs self-signed for local HTTPS.
cargo run -- --config examples/acme_staging/sedat.toml
openssl s_client -connect 127.0.0.1:8443 -servername localhost </dev/null | head
```

## Pebble (Compose profile `acme`)

```bash
docker compose -f docker-compose.dev.yml --profile acme up pebble
# Point acme.directory = "pebble" and dns_provider = "file"
# With PEBBLE_VA_ALWAYS_VALID=1, file DNS + order_once completes without real DNS.

# One-shot CI-style issuance:
docker compose -f docker-compose.dev.yml --profile acme run --rm pebble-issue
# or: scripts/ci_pebble_issue.sh
```

On renewal failure the previous certificate remains active (fail-closed hot-swap).
