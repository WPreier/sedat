# Phase 8 – E2E: SeDat + Mock-Seda (Seda stub)

Real Seda binary may be unavailable; this runbook uses **Mock-Seda**.

```bash
# 1. Start mock upstream
docker compose -f docker-compose.dev.yml up -d mock-seda

# 2. Run SeDat (host or compose profile proxy)
cargo run -- --config examples/config/good.toml --listen 127.0.0.1:8080

# 3. Exercise path
./examples/e2e_seda/run_e2e.sh

# Optional: ACME profile
docker compose -f docker-compose.dev.yml --profile acme up -d pebble
```

Expected:

- `GET /` with `Host: localhost` → 200 from Mock-Seda (PROXY v2 client IP visible)
- Unknown host → 404
- `/sedat` → embedded markdown
- Admin (Linux): `echo status | socat - UNIX-CONNECT:./state/admin.sock`

## Release checklist

See [docs/phases/P08_e2e_release.md](../../docs/phases/P08_e2e_release.md).
