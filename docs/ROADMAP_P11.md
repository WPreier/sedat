# SeDat – Roadmap P11 (Ops polish after P10)

Post-P10 follow-ups from [IDEAS.md](IDEAS.md) **Deferred / Open backlog**.
**E8** stays later; **E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P11.1 Admin bans / unban          ← Limiter surface + token-aware admin
P11.2 Request-ID early-deny audit ← close remaining deny-path gaps
P11.3 PROXY-reject JSONL event    ← pre-HTTP drops into audit
P11.4 Prometheus audit_dropped    ← SIEM/ops visibility
P11.5 Docs: max_connections ↔ cgroup formula
P11.6 Selftest deepen (TCP/ALPN/JSON/allowlist)   ← optional bundle
… later: sliding bans, replica ban sync, time-based rotate, metrics token …
```

## Step breakdown

### P11.1 – Admin `bans` + `unban <ip>`

| | |
|--|--|
| **Status** | **done** (v0.1.11) |
| **Behavior** | Admin socket commands list active temporary bans and clear one IP; AUTH-aware; JSONL on unban |
| **Verify** | Unit tests for Limiter + admin dispatch |
| **Phase note** | [phases/P11_01_admin_bans.md](phases/P11_01_admin_bans.md) |

### P11.2 – Request-ID on early deny paths

| | |
|--|--|
| **Status** | **done** (v0.1.12) |
| **Behavior** | Correlation id on handler denials **and** pre-hyper 400/431; response header + JSONL/tracing |
| **Phase note** | [phases/P11_02_request_id_early_deny.md](phases/P11_02_request_id_early_deny.md) |

### P11.3 – PROXY-reject JSONL

| | |
|--|--|
| **Status** | **done** (v0.1.13) |
| **Behavior** | JSONL `proxy_reject` when inbound PROXY framing is rejected pre-HTTP |
| **Phase note** | [phases/P11_03_proxy_reject_jsonl.md](phases/P11_03_proxy_reject_jsonl.md) |

### P11.4 – Prometheus `audit_dropped`

| | |
|--|--|
| **Status** | **done** (v0.1.14) |
| **Behavior** | Expose `sedat_audit_dropped_total` on admin/metrics + sidecar |
| **Phase note** | [phases/P11_04_audit_dropped_metrics.md](phases/P11_04_audit_dropped_metrics.md) |

### P11.5 – Ops formula docs

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Document aligning `max_connections` with `MemoryMax` / `LimitNOFILE` |

### P11.6 – Selftest deepen

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Upstream TCP/TLS-ALPN checks; optional JSON output; allowlist parse checks |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Admin bans / unban | **done** (v0.1.11) |
| 2 | Request-ID early deny | **done** (v0.1.12) |
| 3 | PROXY-reject JSONL | **done** (v0.1.13) |
| 4 | audit_dropped metrics | **done** (v0.1.14) |
| 5 | cgroup↔limits docs | pending |
| 6 | Selftest deepen | pending |
