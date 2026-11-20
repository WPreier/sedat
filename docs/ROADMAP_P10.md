# SeDat – Roadmap P10 (Ops / Edge Hardening)

Phase **P10** schedules remaining extras from [ROADMAP_P09.md](ROADMAP_P09.md) plus
cross-cutting correlation and edge controls. **Status: complete** (steps 1–10).
**E8** (HTTP/3 attack corpus) and **E9** (config signing) remain **explicitly
skipped** for this phase (E8 = later).

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
| **Status** | **done** |
| **Depends on** | P10.1 (`request_id` on denials); P09.7 security_diff |
| **Config** | `[logging] audit_jsonl = ""` (default off), `audit_jsonl_max_bytes = 10485760` |
| **Behavior** | Append-only JSONL (`startup`, `config_reload`, `proxy_deny`); `request_id` on denials when available; size rotate to `*.jsonl.1`; non-blocking drops |
| **Verify** | `cargo test audit`; enable path and trigger 429 / reload |
| **Phase note** | [phases/P10_02_jsonl_audit.md](phases/P10_02_jsonl_audit.md) |

### P10.3 – Temporäre IP-Bans + Logging

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | Rate limiter; P10.1/P10.2 for correlation |
| **Config** | `[limits] ban_after_rate_limit_strikes = 20` (0=off), `ban_duration_secs = 60` |
| **Behavior** | After N consecutive rate-limit denials → temporary ban (`403` fail-closed); `tracing` + JSONL `ip_ban`/`ip_unban` with `request_id` |
| **Verify** | `cargo test ip_ban` / `--lib limits` |
| **Phase note** | [phases/P10_03_ip_bans.md](phases/P10_03_ip_bans.md) |

### P10.4 – E4 Admin-Tokens

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | Admin socket ACL (P09.5) |
| **Config** | `server.admin_token` / `admin_token_file` / env `SEDAT_ADMIN_TOKEN` (empty = FS ACL only) |
| **Behavior** | When token set: require `AUTH <token>` (constant-time); audit `admin_auth_fail` on failure |
| **Verify** | `cargo test admin` |
| **Phase note** | [phases/P10_04_admin_tokens.md](phases/P10_04_admin_tokens.md) |

### P10.5 – E6 Admin-selftest

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | P10.4 (auth); PROXY/TLS/limits surfaces |
| **Behavior** | Admin `selftest`: config/listens/state/PROXY encode/limits/TLS paths/uptime; JSONL `admin_selftest` |
| **Verify** | `cargo test selftest` |
| **Phase note** | [phases/P10_05_admin_selftest.md](phases/P10_05_admin_selftest.md) |

### P10.6 – E3 Upstream-IP-Pin

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | Route upstream connect |
| **Config** | Per-path `upstream_allowlist = ["10.0.0.0/8", …]` (empty = off) |
| **Behavior** | Resolve → filter by pin → connect → re-check peer; fail-closed 502 |
| **Verify** | `cargo test upstream_pin` |
| **Phase note** | [phases/P10_06_upstream_ip_pin.md](phases/P10_06_upstream_ip_pin.md) |

### P10.7 – E1 optional mTLS Upstream

| | |
|--|--|
| **Status** | **done** (optional / kann, nicht muss) |
| **Depends on** | P10.6 helpful but not hard-required |
| **Config** | `https://` upstream + optional `upstream_mtls_cert` / `_key` / `_ca` (default off) |
| **Behavior** | Optional TLS (+ client-auth) to upstream; PROXY skipped on HTTPS wire |
| **Verify** | `cargo test upstream_mtls`; default remains plaintext `http://` |
| **Phase note** | [phases/P10_07_upstream_mtls.md](phases/P10_07_upstream_mtls.md) |

### P10.8 – E2 ACME ARI

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | ACME renew path |
| **Config** | `acme.ari` (default true), `acme.renew_days_before` (default 30) |
| **Behavior** | Prefer CA ARI windows when available; expiry fallback otherwise |
| **Verify** | `cargo test ari` (unit + mock directory) |
| **Phase note** | [phases/P10_08_acme_ari.md](phases/P10_08_acme_ari.md) |

### P10.9 – E7 Seccomp-BPF profiles

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | P09.1 hardening scaffolding |
| **Config** | `[hardening] seccomp = auto\|off\|required` (unchanged knobs; real BPF now) |
| **Behavior** | Built-in allowlist BPF (`sedat-default-v1`); `auto` falls back to NO_NEW_PRIVS |
| **Verify** | `cargo test hardening::` in Linux Docker (mount → EPERM in child) |
| **Phase note** | [phases/P10_09_seccomp_bpf.md](phases/P10_09_seccomp_bpf.md) |

### P10.10 – systemd Memory/cgroup Limits

| | |
|--|--|
| **Status** | **done** |
| **Depends on** | `deploy/sedat.service` |
| **Behavior** | `MemoryHigh`/`MemoryMax`/`TasksMax`/`LimitNOFILE`/`CPUQuota` in unit; Docker mem/pids mirror |
| **Verify** | `cargo test --test systemd_unit`; `systemd-analyze verify` on Linux hosts |
| **Phase note** | [phases/P10_10_systemd_memory.md](phases/P10_10_systemd_memory.md) |

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
| 2 | E5 JSONL-Audit-Log | **done** |
| 3 | Temporäre IP-Bans + Logging | **done** |
| 4 | E4 Admin-Tokens | **done** |
| 5 | E6 Admin-selftest | **done** |
| 6 | E3 Upstream-IP-Pin | **done** |
| 7 | E1 optional mTLS Upstream | **done** |
| 8 | E2 ACME ARI | **done** |
| 9 | E7 Seccomp-BPF | **done** |
| 10 | systemd Memory/cgroup Limits | **done** |

## P10 status

**P10 backlog complete** for the approved sequence (steps 1–10). Explicitly out of
scope for this phase: **E8** HTTP/3 attack corpus (**later**), **E9** config
signing (**no**).

## Doc & test deliverables

- Update: `CONFIG.md`, `OPERATIONS.md`, `SECURITY.md`, `CONNECTION.md`, `IDEAS.md` as each step lands
- Phase notes: `docs/phases/P10_*.md`
- Version: patch bump + `CHANGELOG.md` per step
- Tests: `cargo test` via Docker when host has no Rust toolchain
