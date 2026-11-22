# P17.1 – Split `health` / `ready` (restart_required gate)

## Summary

After P15.3/P16, restart-only drift is visible on `status`, `reload`, selftest,
Prometheus, and JSONL — but admin `health`/`ready` were aliases that always
returned `OK healthy`. Operators (and scripts) that only probe readiness missed
boot-bound drift.

**Fix:**

| Command | Role | Behavior |
|---------|------|----------|
| `health` | Liveness | Always `OK healthy`; appends ` restart_required=…` when drifted |
| `ready` | Readiness | `OK ready` when clean; `ERR not_ready restart_required=…` when drifted |

Same key set as P15.3 (`RestartOnlySnapshot`).

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- ready_fails_on_restart no_token_allows_commands --nocapture"
```
