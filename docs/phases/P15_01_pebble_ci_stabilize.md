# P15.1 – Stabilize Pebble CI

## Summary

Newer `ghcr.io/letsencrypt/pebble` broke the CI job in stages:

| Failure | Cause | Fix |
|---------|-------|-----|
| Directory never ready (`curl` exit 7) | Compose prefixed `pebble` but image **ENTRYPOINT is `/app`** | Flags-only `command`; drop bogus `-dnsserver` |
| `missing field newNonce` | Pebble **requires `User-Agent`**; problem JSON misread as Directory | Inject `User-Agent: sedat-acme/0.1` in `acme_http_client` |
| `missing field token` (authz) | `:latest` offers `dns-persist-01` without `token`; `instant-acme` 0.7 rejects | Pin image to `2.7.0` (later: upgrade `instant-acme` ≥ 0.8.5) |

| Change | Detail |
|--------|--------|
| Compose `pebble.image` | Pin `ghcr.io/letsencrypt/pebble:2.7.0` |
| Compose `pebble.command` | `["-config", "/test/config/pebble-config.json"]` |
| CI wait | Fail fast + dump `ps`/logs; hard gate (no soft-fail) |
| Compose `pebble-issue` | Explicit `PATH`; bash **without** `-l`; `scripts/compose_pebble_issue.sh` |
| ACME client | Always send `User-Agent` for Pebble |

Local: do not use `bash -lc` as rust-image entrypoint (login shell resets
`PATH` → `cargo: command not found`).

## Verify

```bash
docker compose -f docker-compose.dev.yml --profile acme up -d pebble
curl -skf -A "sedat-acme/0.1" https://localhost:14000/dir
PEBBLE_DIRECTORY=https://localhost:14000/dir \
  SEDAT_PEBBLE_ISSUE_STATE=/tmp/sedat-pebble \
  cargo test --test pebble_issue -- --ignored --nocapture
docker compose -f docker-compose.dev.yml --profile acme down
```
