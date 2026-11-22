# P15.3 – Restart-required drift reporting

## Summary

After P14.6, live reload still cannot apply listen binds, Landlock/seccomp,
metrics sidecar bind, or ACME enable-from-cold. Operators could successfully
`reload` and miss that those knobs still need a process restart.

**Fix:** Capture a `RestartOnlySnapshot` at process boot. Compare against the
active config on admin `status` / `reload` (suffix ` restart_required=…`) and
fail selftest check `restart_required` when drift is present.

| Change | Detail |
|--------|--------|
| `src/config/diff.rs` | `RestartOnlySnapshot`, `restart_required_keys`, note formatter |
| `src/admin/mod.rs` | `AdminState.boot`; status/reload annotate drift |
| `src/admin/selftest.rs` | Check `restart_required` (PASS only when empty) |
| `src/main.rs` | Snapshot at admin start (`acme_started` flag) |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- restart_required status_reports_restart selftest_fails_restart --nocapture"
```
