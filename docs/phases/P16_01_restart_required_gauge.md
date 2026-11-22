# P16.1 – Prometheus `sedat_restart_required` gauge

## Summary

P15.3 surfaces restart-only drift on admin `status` / `reload` / `selftest`.
Scrapers still had to parse text replies.

**Fix:** Emit fixed-cardinality Prometheus gauges from the same boot snapshot:

```text
# HELP sedat_restart_required Restart required for this boot-bound config key (1=yes).
# TYPE sedat_restart_required gauge
sedat_restart_required{key="server.listen"} 0
sedat_restart_required{key="server.listen_tls"} 0
…
sedat_restart_required{key="acme.enable"} 0
```

| Change | Detail |
|--------|--------|
| `src/config/diff.rs` | `RESTART_ONLY_KEYS`, `restart_required_gauges` |
| `src/admin/mod.rs` | Append gauges in `prometheus_text` (admin + sidecar) |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- restart_required_gauges metrics_expose_restart --nocapture"
```
