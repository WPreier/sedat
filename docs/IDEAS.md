# SeDat – Ideas & open questions

Items here are **not** blockers. Triaged in Phase 8 / P09.

## Adopted into plan (implemented)

- Admin Unix socket (not public HTTP admin) — `src/admin`
- Threat-model doc + negative tests — `docs/THREAT_MODEL.md`, `tests/attack_hygiene.rs`
- Pebble + Mock-DNS for ACME — Compose profile `acme` + CI `pebble-issue`
- Mock-Seda with PROXY trust check — `deploy/mock-seda`
- Inbound PROXY allowlist (default off) — wired in accept path
- Metrics/health only on admin/loopback — admin `health`/`metrics` + optional sidecar
- Config schema version + migration path — `config::migrate`, `--migrate-config`
- Landlock / NO_NEW_PRIVS after drop — `[hardening]`, `src/hardening`
- Admin socket group ACL — `server.admin_group` → `0660`
- PROXY after TLS — `inbound_placement = "after_tls"`
- Config-diff audit on reload — `config::security_diff`
- HTTP/2 Continuations corpus — `tests/h2_attack_corpus.rs`

## Adopted into P10 (in progress — see [ROADMAP_P10.md](ROADMAP_P10.md))

- Request-ID across PROXY — **done** (`logging.request_id`, HTTP `x-request-id` after framing)
- JSONL audit sink (E5), temporary IP bans, admin tokens (E4), selftest (E6), upstream IP pin (E3), optional mTLS (E1), ACME ARI (E2), seccomp-BPF (E7), systemd MemoryMax — **pending**

## Open / later (see also ROADMAP_P09 extras / P10)

| Idea | Notes | Triage |
|------|-------|--------|
| Full seccomp BPF profiles | Ship known-good profiles for `required` | P10.9 (E7) |
| ARI (ACME Renewal Info) | Prefer when CA supports | P10.8 (E2) |
| Multiple DNS providers | Trait ready; Cloudflare first | Extend as needed |
| mTLS to upstream Seda | Private-net spoof defense | P10.7 (E1, optional) |
| Admin capability tokens | Beyond FS ACL | P10.4 (E4) |
| JSONL audit sink | SIEM-friendly | P10.2 (E5) |
| Config signing (ed25519) | Signed active TOML only | **Skipped** (E9 no) |
| HTTP/3 attack corpus | Mirror H2 corpus | **Skipped for P10** (E8 later) |
| Hot-reload without process restart | In-process reload of routes/certs | Partial (config + certs) |
| Windows service wrapper | Out of scope; use WSL/Docker | Won't do for prod |
| Pingora backend option | Explicitly rejected for MVP | Won't do |
| OCSP stapling dependency | Avoid; LE OCSP sunset | Won't do as hard req |

## Spec gaps resolved in Phase 0

- Stack choice: hyper/tokio/rustls (not Pingora)
- Primary platform: Linux; Windows via WSL/Docker
- PROXY trust model documented
