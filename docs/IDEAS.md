# SeDat – Ideas & open questions

Items here are **not** blockers unless promoted into a roadmap (`ROADMAP_P*.md`).

## Adopted / done (P09–P10)

See [ROADMAP_P09.md](ROADMAP_P09.md) and [ROADMAP_P10.md](ROADMAP_P10.md). Highlights:

- Admin Unix socket, Landlock, seccomp-BPF, PROXY after TLS, config-diff audit
- Request-ID, JSONL audit, IP bans, admin tokens, selftest, upstream IP pin
- Optional upstream mTLS, ACME ARI, systemd MemoryMax / Compose mem/pids

## Deferred / Open backlog

Durable list of follow-ups after **P10 complete**. Promoted work lives in
[ROADMAP_P11.md](ROADMAP_P11.md).

### Explicitly deferred / declined

| Item | Status | Notes |
|------|--------|-------|
| **E8 HTTP/3 attack corpus** | **later** (large) | Mirror H2 corpus for QUIC when `http3` is on |
| **E9 Config signing (ed25519)** | **rejected** | Explicitly declined for P10; keep as “no” unless product revisits |

### Ops / limits / bans

| Item | Notes | Suggested |
|------|-------|-----------|
| Admin `bans` / `unban <ip>` | List + clear temporary bans over admin socket | **done P11.1** |
| Ban-State über Replicas teilen | Shared ban map (Redis/etc.) for multi-instance | later |
| Sliding ban / Verlängerung bei Strike während Ban | Extend TTL if abuse continues while banned | later |
| Doc formula: `limits.max_connections` ↔ `MemoryMax` / `LimitNOFILE` | Ops guidance aligning TOML + cgroup | P11 docs |
| Multiple DNS providers | Trait ready; Cloudflare first | as needed |

### Audit / logging / metrics

| Item | Notes | Suggested |
|------|-------|-----------|
| Prometheus counter for `audit_dropped` | `sedat_audit_dropped_total` on admin/metrics | **done P11.4** |
| PROXY-Rejects (pre-HTTP) as JSONL event | JSONL `proxy_reject` with reason/stage | **done P11.3** |
| Zeitbasierte Log-Rotation neben Size-Rotate | Age-based rotate for `audit_jsonl` | later |

### Admin / auth / selftest

| Item | Notes | Suggested |
|------|-------|-----------|
| Token auch für Metrics-Sidecar | Auth on loopback `/metrics` when token set | later |
| Token-Rotation ohne Reload | Hot-swap admin token (file watch / admin cmd) | later |
| Selftest: Upstream-TCP + TLS-ALPN | Deeper connectivity checks | later |
| `selftest --json` | Machine-readable selftest output | later |
| Allowlist parseable check in selftest | Validate `upstream_allowlist` / PROXY CIDRs | later |

### Proxy / upstream / request-id

| Item | Notes | Suggested |
|------|-------|-----------|
| Upstream pin: Hostname-Literal + periodisches Re-Resolve | Pin by name + refresh DNS on interval | later |
| Request-ID on all early deny paths | Close remaining gaps (pre-hyper 400/431) | **done P11.2** |
| Hot-reload without process restart | Routes/certs partially done; broaden | partial |

### Won't do (prod)

| Item | Notes |
|------|-------|
| Windows service wrapper | Use WSL/Docker |
| Pingora backend | Rejected for MVP |
| OCSP stapling as hard requirement | LE OCSP sunset |

## Spec gaps resolved in Phase 0

- Stack choice: hyper/tokio/rustls (not Pingora)
- Primary platform: Linux; Windows via WSL/Docker
- PROXY trust model documented
