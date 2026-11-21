# P14.1 – Broaden hot-reload (limits + static TLS + SIGHUP)

## Summary

Config `reload` already swapped routes via `ArcSwap` and refreshed audit/token
gates. This step closes the main remaining live gaps called out in IDEAS
(“Hot-reload … partial”):

| On reload | Behavior |
|-----------|----------|
| `limits.*` knobs used by `Limiter` (conn/header/body/timeouts/H3 caps) | **`Limiter::reconfigure`** |
| Static `tls.cert_path` / `tls.key_path` | **Hot-swap** into `TlsState` when wired; load errors keep previous cert |
| Unix **SIGHUP** | Same path as admin `reload` |

## Still requires process restart

Originally: listen, Landlock/seccomp, metrics bind, ACME enable/loop, ban-share.
**P14.6** hot-reloads ban-share + live ACME knobs; remaining restart-only list is
in [P14_06_hot_reload_remaining.md](P14_06_hot_reload_remaining.md).

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- reconfigure_updates_connection_cap live_reload_updates_limits --nocapture"
```
