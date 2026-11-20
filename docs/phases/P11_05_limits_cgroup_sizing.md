# P11.5 – `max_connections` ↔ cgroup sizing

## Summary

Align in-process `[limits].max_connections` with outer systemd/cgroup ceilings
(`MemoryMax`, `LimitNOFILE`, `TasksMax`). Defaults ship coherent; operators
who raise concurrency must raise the unit/Compose caps in the same change.

## Default bundle (keep together)

| Knob | Default | Where |
|------|---------|--------|
| `limits.max_connections` | `1024` | `sedat.toml` |
| `MemoryHigh` / `mem_reservation` | `384M` | systemd / Compose |
| `MemoryMax` / `mem_limit` | `512M` | systemd / Compose |
| `LimitNOFILE` | `65535` | systemd |
| `TasksMax` / `pids_limit` | `4096` | systemd / Compose |

## Practical formulas

Let `C = limits.max_connections`.

### File descriptors

Each proxied connection typically holds **client + upstream** sockets (≈ **2 FDs**),
plus a fixed headroom for listeners, admin Unix socket, metrics, ACME, logs, DNS:

```text
LimitNOFILE  ≥  2 × C  +  256
```

Shipped default: `2 × 1024 + 256 = 2304` ≪ `65535` (comfortable margin for
HTTP/2 streams sharing connections and transient FDs).

### Memory

Rough TLS/HTTP reverse-proxy budget (order-of-magnitude, not a guarantee):

```text
MemoryMax_MiB  ≥  baseline_MiB  +  (C × per_conn_KiB) / 1024
```

Suggested starting constants for SeDat + rustls on a small VPS:

| Constant | Start with | Notes |
|----------|------------|--------|
| `baseline_MiB` | `64`–`128` | process + TLS listener + idle pools |
| `per_conn_KiB` | `250`–`400` | buffers / TLS state under load |

Example for `C = 1024`, baseline `128`, per-conn `350 KiB`:

```text
128 + (1024 × 350) / 1024  ≈  128 + 350  =  478 MiB
```

→ shipped **`MemoryMax=512M`** matches default `C=1024`. Prefer
`MemoryHigh ≈ 0.75 × MemoryMax` (shipped `384M` / `512M`).

If you raise `C` to `4096`, plan ≈ `128 + 1400 ≈ 1.5G` MemoryMax (then
re-measure under load).

### Tasks / PIDs

```text
TasksMax  ≥  C  +  64
```

Tokio does not map 1:1 task↔connection forever, but the cap must not sit
below peak concurrency. Shipped `4096` covers default `C=1024` with room.

## Operator checklist

1. Change `limits.max_connections` in TOML.
2. Recompute `LimitNOFILE` / `MemoryMax` / `TasksMax` with the formulas above.
3. Update `deploy/sedat.service` (or drop-in) **and** Compose `mem_*` / `pids_limit`.
4. `systemctl daemon-reload && systemctl restart sedat` (or recreate container).
5. Watch RSS vs `MemoryHigh` and refused accepts when the in-process limiter trips.

## Tests

- `tests/systemd_unit.rs` — unit keys present; FD/memory defaults coherent with `C=1024`.

## See also

- [OPERATIONS.md](../OPERATIONS.md) — full ops section
- [CONFIG.md](../CONFIG.md) — TOML vs deploy caps
- [P10_10_systemd_memory.md](P10_10_systemd_memory.md) — unit/Compose knobs
