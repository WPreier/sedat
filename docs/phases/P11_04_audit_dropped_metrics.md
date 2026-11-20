# P11.4 – Prometheus `audit_dropped` counter

## Summary

JSONL audit drops (lock contention or write I/O failure) are already counted by
[`AuditSink::dropped`](../../src/audit.rs). P11.4 exposes that value on the
existing Prometheus text path (admin `metrics` and loopback `/metrics` sidecar).

## Metric

```text
# HELP sedat_audit_dropped_total JSONL audit events dropped (lock busy or I/O error).
# TYPE sedat_audit_dropped_total counter
sedat_audit_dropped_total 0
```

| Name | Type | Meaning |
|------|------|---------|
| `sedat_audit_dropped_total` | counter | Cumulative dropped audit events since process start |

When audit is disabled, the counter stays `0` (emits are no-ops without drop
increments for the disabled/empty-path fast path that returns before try_lock
failure — disabled sink still has a lock, but `path` is unset so successful
locks write nothing; contention can still increment).

## Surfaces

- Admin socket: `metrics` → body includes the counter
- HTTP sidecar: `GET /metrics` on `server.metrics_listen` (loopback)

## Tests

- Unit: `src/audit` `drops_when_lock_busy`
- Unit: `src/admin` `status_format`, `metrics_expose_audit_dropped_counter`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib drops_when_lock_busy && cargo test --lib metrics_expose_audit_dropped"
```
