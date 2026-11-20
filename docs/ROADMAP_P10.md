# SeDat – Roadmap P10 (Ops / Edge Hardening)

Phase **P10** schedules remaining extras from [ROADMAP_P09.md](ROADMAP_P09.md) plus
cross-cutting correlation and edge controls. **E8** (HTTP/3 attack corpus) and
**E9** (config signing) are **explicitly skipped** for this phase.

**Do not edit** Cursor plan files — this roadmap is the source of truth for P10.
Implement as **separate steps**; after each step: Zwischenfazit, verification,
version patch bump, commit + push, then wait for review before the next step.

## Goals / Non-goals

**Goals**

1. End-to-end request correlation across SeDat → upstream (after PROXY framing).
2. SIEM-friendly JSONL audit sink.
3. Temporary IP bans after rate-limit bursts + logging.
4. Admin capability tokens and admin selftest.
5. Upstream IP pin; optional upstream mTLS; ACME ARI; seccomp-BPF profiles.
6. systemd Memory/cgroup limits.

**Non-goals**

- E8 HTTP/3 amplification corpus (later).
- E9 Config signing (no).
- Schema bump unless a step requires breaking semantics (prefer additive defaults).

## Dependency order (approved)

```text
P10.1 Request-ID über PROXY          ← foundation for log/audit correlation
         │
P10.2 E5 JSONL-Audit-Log             ← can include request_id fields
         │
P10.3 Temporäre IP-Bans + Logging    ← uses rate-limit path; audit/log id
         │
P10.4 E4 Admin-Tokens                ← admin ACL before selftest
         │
P10.5 E6 Admin-selftest              ← needs tokens + stable admin cmds
         │
P10.6 E3 Upstream-IP-Pin             ← connect-time safety
P10.7 E1 optional mTLS Upstream      ← builds on pin / upstream connect
         │
P10.8 E2 ACME ARI                    ← independent ACME ops
P10.9 E7 Seccomp-BPF                 ← hardening profiles
P10.10 systemd Memory/cgroup Limits  ← deploy unit only
```

Suggested order matches the above (1→10). Deviate only if a later discovery forces it; document here.

---

## Step breakdown

### P10.1 – Request-ID über PROXY

| | |
|--|--|
| **Status** | **done** (this session) |
| **Depends on** | Outbound PROXY + HTTP forward path |
| **Config** | `[logging] request_id = true` (default), `request_id_header = "x-request-id"` |
| **Behavior** | Generate or sanitize inbound id; inject HTTP header **after** PROXY framing; echo on response; log `request_id`. **Not** a PROXY v2 TLV (works with `off`/`v1`/`v2`). Invalid inbound id → regenerate (request still proceeds). |
| **Verify** | `cargo test` (unit `request_id` + `tests/proxy_h1.rs`); curl and check response/`mock` upstream header |
| **Phase note** | [phases/P10_01_request_id.md](phases/P10_01_request_id.md) |

### P10.2 – E5 JSONL-Audit-Log

| | |
|--|--|
| **Status** | pending |
| **Depends on** | P10.1 (optional `request_id` field in events); P09.7 security_diff |
| **Config** | Likely `[logging] audit_jsonl = "path"` or under `state_dir` (TBD) |
| **Behavior** | Append-only JSONL for reload/security events (and optionally proxy denials); rotate under state |
| **Verify** | Unit tests for line format; Docker/local: trigger reload, assert JSONL lines |

### P10.3 – Temporäre IP-Bans + Logging

| | |
|--|--|
| **Status** | pending |
| **Depends on** | Rate limiter; P10.1/P10.2 for correlation |
| **Config** | Ban threshold / TTL under `[limits]` (TBD) |
| **Behavior** | After N consecutive 429s (or empty-bucket series), temporary ban; log with request_id / client IP |
| **Verify** | Integration: burst → 429 → ban window; logs include reason |

### P10.4 – E4 Admin-Tokens

| | |
|--|--|
| **Status** | pending |
| **Depends on** | Admin socket ACL (P09.5) |
| **Config** | Token file / env; fail-closed if misconfigured when required |
| **Behavior** | Optional `AUTH <token>` before admin commands |
| **Verify** | Unit/integration: reject without token when enabled; accept with token |

### P10.5 – E6 Admin-selftest

| | |
|--|--|
| **Status** | pending |
| **Depends on** | P10.4 (auth); PROXY/TLS/limits surfaces |
| **Behavior** | Admin `selftest`: PROXY probe, TLS ALPN, limit counters |
| **Verify** | Admin command returns structured OK/FAIL; Docker smoke |

### P10.6 – E3 Upstream-IP-Pin

| | |
|--|--|
| **Status** | pending |
| **Depends on** | Route upstream connect |
| **Config** | Per-route allowlist of IPs/CIDRs (TBD) |
| **Behavior** | Resolve/connect only if peer matches pin; fail-closed |
| **Verify** | Tests: allowed IP connects; wrong IP rejected |

### P10.7 – E1 optional mTLS Upstream

| | |
|--|--|
| **Status** | pending (optional / kann, nicht muss) |
| **Depends on** | P10.6 helpful but not hard-required |
| **Config** | Client cert/key paths; default off |
| **Behavior** | Optional TLS+client-auth to upstream |
| **Verify** | Integration with mock mTLS upstream; default remains plaintext HTTP upstream |

### P10.8 – E2 ACME ARI

| | |
|--|--|
| **Status** | pending |
| **Depends on** | ACME renew path |
| **Behavior** | Prefer CA ARI windows when available; safe fallback |
| **Verify** | Unit/mock ARI response; renew scheduler respects window |

### P10.9 – E7 Seccomp-BPF profiles

| | |
|--|--|
| **Status** | pending |
| **Depends on** | P09.1 hardening scaffolding |
| **Behavior** | Ship/generate known-good BPF profiles for `required` |
| **Verify** | Linux Docker: `seccomp=required` starts; forbidden syscall blocked in test harness |

### P10.10 – systemd Memory/cgroup Limits

| | |
|--|--|
| **Status** | pending |
| **Depends on** | `deploy/sedat.service` |
| **Behavior** | `MemoryMax=` / related cgroup knobs in unit |
| **Verify** | Unit file review; optional systemd-nspawn/smoke on Linux |

---

## Skipped

| Item | Reason |
|------|--------|
| E8 HTTP/3 attack corpus | Deferred (“later”) |
| E9 Config signing | Explicitly out (“no”) |

---

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Request-ID über PROXY | **done** |
| 2 | E5 JSONL-Audit-Log | pending |
| 3 | Temporäre IP-Bans + Logging | pending |
| 4 | E4 Admin-Tokens | pending |
| 5 | E6 Admin-selftest | pending |
| 6 | E3 Upstream-IP-Pin | pending |
| 7 | E1 optional mTLS Upstream | pending |
| 8 | E2 ACME ARI | pending |
| 9 | E7 Seccomp-BPF | pending |
| 10 | systemd Memory/cgroup Limits | pending |

## Doc & test deliverables

- Update: `CONFIG.md`, `OPERATIONS.md`, `SECURITY.md`, `CONNECTION.md`, `IDEAS.md` as each step lands
- Phase notes: `docs/phases/P10_*.md`
- Version: patch bump + `CHANGELOG.md` per step
- Tests: `cargo test` via Docker when host has no Rust toolchain
