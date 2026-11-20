# P10.10 – systemd Memory / cgroup Limits

## Summary

Ship sensible **cgroup v2** resource caps in [`deploy/sedat.service`](../../deploy/sedat.service)
so a compromised or runaway SeDat process cannot exhaust host RAM/PIDs/FDs.
Defaults are conservative for a small VPS reverse proxy; operators may raise them.

## Unit knobs

| Directive | Default | Role |
|-----------|---------|------|
| `MemoryHigh=` | `384M` | Soft throttle / reclaim pressure |
| `MemoryMax=` | `512M` | Hard ceiling (OOM within cgroup) |
| `TasksMax=` | `4096` | Thread/process cap |
| `LimitNOFILE=` | `65535` | FD budget for many connections |
| `CPUQuota=` | `200%` | Soft CPU share (2 cores worth) |
| `OOMScoreAdjust=` | `200` | Prefer cgroup OOM over critical system units |

Also tightened: `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictSUIDSGID`,
`LockPersonality` (alongside existing `NoNewPrivileges` / `ProtectSystem`).

## Docker equivalent

In Compose (see `docker-compose.dev.yml` proxy profile):

```yaml
mem_limit: 512m
mem_reservation: 384m
pids_limit: 4096
```

Or run flags: `--memory=512m --memory-reservation=384m --pids-limit=4096`.

## Verify

```bash
# Keys present in unit (any OS):
cargo test --test systemd_unit

# On a systemd host after install:
systemd-analyze verify /etc/systemd/system/sedat.service
systemctl show sedat -p MemoryMax -p MemoryHigh -p TasksMax
```

## Notes

- Align in-process `[limits] max_connections` with FD/memory budget —
  formulas in [P11_05_limits_cgroup_sizing.md](P11_05_limits_cgroup_sizing.md)
  and [OPERATIONS.md](../OPERATIONS.md).
- After drop, SeDat’s Landlock + seccomp-BPF still apply; cgroups are the outer fence.
