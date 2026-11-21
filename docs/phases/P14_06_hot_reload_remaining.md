# P14.6 – Hot-reload remaining knobs (ban-share + ACME)

## Summary

P14.1 live-reloaded limits and static TLS. This step extends admin/`SIGHUP`
`reload` for the remaining **safe** knobs without weakening fail-closed:

| On reload | Behavior |
|-----------|----------|
| Ban-share path / secret / poll | Rebuild `BanShareStore`; invalid config **keeps previous** store |
| ACME knobs (domains, directory, renew window, DNS, `enabled=false`) | `AcmeManager::replace_config` when the renewal loop was started at boot; idle when disabled |
| ACME enable from cold (`enabled=false` → `true` without a boot-time manager) | **Restart required** (reply `acme=restart_required_to_enable`) |

## Still requires process restart

| Knob | Why |
|------|-----|
| `server.listen` / TLS listen / QUIC bind | Sockets already bound; rebinding mid-flight is unsafe |
| Landlock / seccomp | Sandbox applied once at startup; cannot widen/reapply safely |
| `server.metrics_listen` | Metrics sidecar bind address fixed at boot |
| ACME enable when loop never started | No `AcmeManager` task to attach; fail-closed note on reload |

Listen / sandbox / metrics-bind remain restart-only **by design**.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- reconfigure_ban_share replace_config_updates --nocapture"
```
