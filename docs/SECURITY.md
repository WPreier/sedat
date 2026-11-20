# SeDat – Security

## Principles

- **Fail-closed:** invalid config / untrusted PROXY / unknown Host → reject.
- **Least privilege:** bind then drop; optional Landlock / seccomp-BPF after drop (Linux).
- **Explicit trust:** PROXY and admin paths require allowlists / socket ACLs.
- **Memory-safe TLS:** rustls only; TLS 1.2 and 1.3 (prefer 1.3).

## Threat model

Full write-up: **[THREAT_MODEL.md](THREAT_MODEL.md)** (assets, trust boundaries, attack IDs T1–T12, test mapping).

| Threat | Mitigation |
|--------|------------|
| Config injection / bad reload | Fail-closed; line+reason; previous active kept; **security-diff audit** on successful reload |
| PROXY spoofing | Outbound PROXY to Seda; inbound PROXY default off + CIDR allowlist; untrusted PROXY frames dropped; optional **PP2-over-TLS** (`inbound_placement = "after_tls"`) |
| Domain fronting | SNI ↔ Host consistency check |
| Request smuggling | Reject CL+TE; strict header parsing; reject absolute-URI tricks; size caps |
| Slowloris / header bomb | Request timeout on connections; header count/size caps |
| HTTP/2 CONTINUATION / HPACK bomb | hyper limits + size caps; negative corpus `tests/h2_attack_corpus.rs` |
| Edge DoS | Token-bucket per verified client IP; connection limits; temporary IP ban after strike series |
| Upstream DNS rebinding / SSRF-ish redirect | Optional per-route `upstream_allowlist` pin (fail-closed) |
| Spoofed / unauthenticated upstream peer | Optional HTTPS + mTLS client cert (`upstream_mtls_*`, default off) |
| Privilege / RCE blast radius | Drop after bind; **Landlock + seccomp-BPF** (`[hardening]`, Linux `auto`) |
| Log blocking | Async bounded channel; drop+metric on overflow |
| Cert loss on renew fail | Hot-swap; keep previous cert on ACME failure |
| Mass-renewal stampedes | Optional ACME ARI windows (RFC 9773); expiry fallback |
| Admin exposure | Unix socket `0600` default, or `0660` + `server.admin_group`; optional capability token (`AUTH`); no public HTTP admin |
| Metrics exposure | Admin socket / optional **loopback-only** sidecar; never public control plane |
| Schema surprise upgrades | Exact `schema_version`; migrate helper fail-closed |

Automated negative tests: `tests/attack_hygiene.rs`, `tests/h2_attack_corpus.rs`. Manual scripts: `examples/hardening/`.

## TLS policy

- Protocols: **TLS 1.2 and 1.3 only** (1.3 preferred).
- No TLS 1.0/1.1, SSLv2/3.
- Certificates: ACME **DNS-01** (staging default in dev; production explicit). Local CA: **Pebble** via Compose profile `acme` (CI job issues without LE network).
- OCSP stapling: **not** a hard operational dependency (LE OCSP sunset).
- Port 80: HTTPS redirect only (DNS-01 does not need HTTP-01).

## PROXY Protocol

- **Outbound to Seda:** PROXY v2 recommended (v1 optional).
- **Inbound from clients/LB:** default **disabled**. Enable only with `proxy_protocol.inbound_allowlist` CIDRs. Empty allowlist + enabled → validation error. PROXY signatures from untrusted peers are **dropped**.
- **Placement:** `inbound_placement = "before_tls"` (default) or `"after_tls"` (PP2 over TLS). With `after_tls`, plaintext PROXY framing is rejected; only post-handshake PROXY is trusted.
- Seda / Mock-Seda must listen on localhost/private net and trust only SeDat.

## Hardening (Linux)

```toml
[hardening]
landlock = "auto"   # auto | off | required
seccomp = "auto"    # auto | off | required  (BPF allowlist; auto→NO_NEW_PRIVS fallback)
```

Applied **after** privilege drop. Unsupported kernels: `auto` skips; `required` fails closed.

## Rate limits & hygiene

- Token bucket per client IP (after TLS / inbound PROXY rewrite, before expensive proxy work).
- **Temporary IP ban (P10.3):** after `ban_after_rate_limit_strikes` consecutive denials (default 20), ban for `ban_duration_secs` (default 60) → **403** until expiry. Set strikes to `0` to disable. Ban/unban logged + optional JSONL.
- Caps: connections, request line, header count/size, body size.
- Unknown Host: reject (default).

## Admin / metrics / health

- Control plane: Unix admin socket — `status`, `health`, `metrics`, `reload`, `cert`, `selftest` (+ `AUTH` when token configured).
- Socket ACL: owner `0600`, or `0660` when `server.admin_group` is set.
- **Admin token (P10.4):** when `SEDAT_ADMIN_TOKEN` / `admin_token_file` / `admin_token` is set, require `AUTH <token>` (constant-time verify). Empty token = FS ACL only (document as weak for production). Failed auth audited as `admin_auth_fail`.
- Optional `server.metrics_listen = "127.0.0.1:9090"` loopback Prometheus sidecar (`GET /metrics`) — not gated by admin token.
- Scrape without sidecar: `scripts/prometheus_admin_scrape.sh` (pass token via `SEDAT_ADMIN_TOKEN` if required).
- **Never** expose SeDat metrics/health as a public HTTP control plane.

## Logging

Non-blocking `tracing` writer with bounded channel. Overflow: drop events and increment metric — never block the request path.

Reload audit target: `sedat::audit` (trust-boundary key diffs).

**Request-ID (P10.1):** by default SeDat generates or reuses a sanitized `x-request-id`, forwards it on the upstream HTTP request **after** PROXY framing, echoes it to the client, and logs `request_id`. Invalid inbound ids are replaced (request continues). Disable with `logging.request_id = false`. Correlation uses the HTTP header, not a PROXY v2 TLV.

**JSONL audit (P10.2 / E5):** optional `logging.audit_jsonl` append-only file (default **off**). Records `config_reload` diffs and `proxy_deny` events; denials include `request_id` when available. Never blocks the request path (drop on lock contention).

## Checklist (P09)

- [x] Landlock after drop (`auto`)
- [x] Seccomp-BPF allowlist (P10.9) — see [phases/P10_09_seccomp_bpf.md](phases/P10_09_seccomp_bpf.md)
- [x] Prometheus via admin + optional loopback sidecar
- [x] Pebble CI issuance (`pebble-issue` workflow / compose)
- [x] HTTP/2 Continuations corpus
- [x] Admin group ACL (`0660`)
- [x] PROXY after TLS mode
- [x] Config-diff audit on reload

## Checklist (P10)

- [x] Request-ID across PROXY (`x-request-id` HTTP header after framing)
- [x] JSONL audit sink (E5)
- [x] Temporary IP bans after rate-limit series
- [x] Admin capability tokens (E4)
- [x] Admin selftest (E6)
- [x] Upstream IP pin (E3)
- [x] Optional upstream mTLS (P10.7) — default off; see [phases/P10_07_upstream_mtls.md](phases/P10_07_upstream_mtls.md)
- [x] ACME ARI (P10.8) — prefer CA windows, expiry fallback; see [phases/P10_08_acme_ari.md](phases/P10_08_acme_ari.md)
- [ ] systemd MemoryMax — see [ROADMAP_P10.md](ROADMAP_P10.md)

## Reporting

Security issues: prefer private disclosure to the maintainer; do not open public issues with exploit details until patched.
