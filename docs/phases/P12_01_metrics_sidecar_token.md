# P12.1 – Metrics sidecar token

## Summary

When an **admin token** is configured (same sources as the Unix socket —
`SEDAT_ADMIN_TOKEN` / `admin_token_file` / `admin_token`), the loopback
Prometheus sidecar requires:

```http
Authorization: Bearer <token>
```

Missing or wrong credentials → **401** + JSONL `metrics_auth_fail` (secret never
logged). Empty token config → previous behavior (loopback-only, no Bearer).
Admin socket `AUTH` protocol is **unchanged**.

## Secure defaults

| Token configured? | `/metrics` |
|-------------------|------------|
| No | Open on loopback (dev-friendly) |
| Yes | Fail-closed Bearer required |

## Scrape examples

```bash
# curl
curl -sH "Authorization: Bearer $SEDAT_ADMIN_TOKEN" http://127.0.0.1:9090/metrics

# Prometheus scrape_configs
# - job_name: sedat
#   static_configs: [{ targets: ["127.0.0.1:9090"] }]
#   authorization:
#     type: Bearer
#     credentials: "<same as SEDAT_ADMIN_TOKEN>"
```

Admin socket scrape (no HTTP Bearer) remains:

```bash
printf 'AUTH %s\nmetrics\n' "$SEDAT_ADMIN_TOKEN" | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

## Tests

- `src/admin/auth` `bearer_and_metrics_gate`
- `src/admin` `metrics_sidecar_open_without_token`, `metrics_sidecar_requires_bearer_when_token_set`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib bearer_and_metrics && cargo test --lib metrics_sidecar"
```
