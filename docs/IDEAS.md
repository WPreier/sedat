# SeDat – Ideas & open questions

Items here are **not** blockers unless promoted into a roadmap (`ROADMAP_P*.md`).

## Adopted / done (P09–P10)

See [ROADMAP_P09.md](ROADMAP_P09.md) and [ROADMAP_P10.md](ROADMAP_P10.md). Highlights:

- Admin Unix socket, Landlock, seccomp-BPF, PROXY after TLS, config-diff audit
- Request-ID, JSONL audit, IP bans, admin tokens, selftest, upstream IP pin
- Optional upstream mTLS, ACME ARI, systemd MemoryMax / Compose mem/pids

## Deferred / Open backlog

Durable list of follow-ups after **P10–P13**. Active promotion:
[ROADMAP_P14.md](ROADMAP_P14.md).

### Explicitly deferred / declined

| Item | Status | Notes |
|------|--------|-------|
| **E8 HTTP/3 attack corpus** | **done P13.1** | Programmatic QUIC corpus (`tests/h3_attack_corpus.rs`); not a GB archive |
| **E9 Config signing (ed25519)** | **rejected** | Explicitly declined for P10; keep as “no” unless product revisits |

### Ops / limits / bans

| Item | Notes | Suggested |
|------|-------|-----------|
| Admin `bans` / `unban <ip>` | List + clear temporary bans over admin socket | **done P11.1** |
| Ban-State über Replicas teilen | File-backed HMAC shared ban map (not Redis) | **done P12.6** |
| Sliding ban / Verlängerung bei Strike während Ban | Extend TTL if abuse continues while banned | **done P12.2** |
| Doc formula: `limits.max_connections` ↔ `MemoryMax` / `LimitNOFILE` | Ops guidance aligning TOML + cgroup | **done P11.5** |
| Multiple DNS providers | Cloudflare API + webhook; `file` default | **done P13.2** |

### Audit / logging / metrics

| Item | Notes | Suggested |
|------|-------|-----------|
| Prometheus counter for `audit_dropped` | `sedat_audit_dropped_total` on admin/metrics | **done P11.4** |
| PROXY-Rejects (pre-HTTP) as JSONL event | JSONL `proxy_reject` with reason/stage | **done P11.3** |
| Zeitbasierte Log-Rotation neben Size-Rotate | Age-based rotate for `audit_jsonl` | **done P12.4** |

### Admin / auth / selftest

| Item | Notes | Suggested |
|------|-------|-----------|
| Token auch für Metrics-Sidecar | Auth on loopback `/metrics` when token set | **done P12.1** |
| Token-Rotation ohne Reload | Hot-swap admin token (`reload-token` + overlap) | **done P12.3** |
| Selftest: Upstream-TCP + TLS-ALPN | Deeper connectivity checks | **done P11.6** |
| `selftest --json` | Machine-readable selftest output | **done P11.6** |
| Allowlist parseable check in selftest | Validate `upstream_allowlist` / PROXY CIDRs | **done P11.6** |

### Proxy / upstream / request-id

| Item | Notes | Suggested |
|------|-------|-----------|
| Upstream pin: Hostname-Literal + periodisches Re-Resolve | Pin by name + refresh DNS on interval | **done P12.5** |
| Request-ID on all early deny paths | Close remaining gaps (pre-hyper 400/431) | **done P11.2** |
| Hot-reload without process restart | Live limits + static TLS + SIGHUP (P14.1); listen/sandbox/ACME/ban-share still restart | **done P14.1** (partial→broadened) |
| HTTP/3 full request proxy | `h3` + `h3-quinn` 0.0.10 → `handle_request`; body buffered | **done P14.2** |
| HTTP/3 streamed bodies | H3 edge streams req/resp; `max_body_bytes` → 413 | **done P14.3** |
| TCP upstream body streaming | Chunked outbound + streamed upstream response | **done P14.4** |

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
