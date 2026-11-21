# Changelog

All notable changes to SeDat are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.16] – 2026-11-21

### Added

- **P11.6 deepen admin selftest:** allowlist CIDR parse checks; short-timeout
  upstream TCP + TLS/ALPN probes (capped); `selftest json` / `--json` machine
  output. Phase note
  [docs/phases/P11_06_selftest_deepen.md](docs/phases/P11_06_selftest_deepen.md).
- **P11 complete** — see [docs/ROADMAP_P11.md](docs/ROADMAP_P11.md).

## [0.1.15] – 2026-11-21

### Added

- **P11.5 limits ↔ cgroup sizing docs:** practical formulas linking
  `limits.max_connections` to `MemoryMax` / `LimitNOFILE` / `TasksMax` in
  OPERATIONS + CONFIG; unit comments and a defaults coherence test. Phase note
  [docs/phases/P11_05_limits_cgroup_sizing.md](docs/phases/P11_05_limits_cgroup_sizing.md).

## [0.1.14] – 2026-11-21

### Added

- **P11.4 Prometheus `audit_dropped`:** counter `sedat_audit_dropped_total`
  on admin `metrics` and the loopback `/metrics` sidecar (JSONL drops under
  lock contention or I/O error). Phase note
  [docs/phases/P11_04_audit_dropped_metrics.md](docs/phases/P11_04_audit_dropped_metrics.md).

## [0.1.13] – 2026-11-20

### Added

- **P11.3 PROXY-reject JSONL:** inbound PROXY policy failures emit
  `proxy_reject` (`reason`, `stage=plaintext|after_tls`, `request_id=null`)
  before the connection is dropped. Phase note
  [docs/phases/P11_03_proxy_reject_jsonl.md](docs/phases/P11_03_proxy_reject_jsonl.md).

## [0.1.12] – 2026-11-20

### Added

- **P11.2 Request-ID on early denials:** pre-hyper smuggling (400) and
  incomplete/oversized header blocks (431) now echo `x-request-id` (when
  enabled) and emit JSONL `proxy_deny` with the same id; handler denials
  already covered via `deny_response`. Phase note
  [docs/phases/P11_02_request_id_early_deny.md](docs/phases/P11_02_request_id_early_deny.md).

## [0.1.11] – 2026-11-20

### Added

- **P11.1 Admin bans / unban:** admin socket commands `bans` (list active
  temporary bans with remaining TTL) and `unban <ip>` (clear one ban);
  token-auth aware; JSONL `admin_unban` on success. Phase note
  [docs/phases/P11_01_admin_bans.md](docs/phases/P11_01_admin_bans.md).
- Open backlog written to [docs/IDEAS.md](docs/IDEAS.md); roadmap
  [docs/ROADMAP_P11.md](docs/ROADMAP_P11.md).

## [0.1.10] – 2026-11-20

### Added

- **P10.10 systemd / cgroup limits:** `deploy/sedat.service` sets `MemoryHigh`,
  `MemoryMax`, `TasksMax`, `LimitNOFILE`, `CPUQuota` plus extra Protect*
  knobs; Compose proxy profile mirrors memory/pids. Phase note
  [docs/phases/P10_10_systemd_memory.md](docs/phases/P10_10_systemd_memory.md).
- **P10 complete** (E8 deferred, E9 skipped) — see [docs/ROADMAP_P10.md](docs/ROADMAP_P10.md).

## [0.1.9] – 2026-11-20

### Added

- **P10.9 / E7 Seccomp-BPF:** built-in syscall allowlist (`sedat-default-v1`) via
  `seccompiler`, installed with TSYNC after drop. `hardening.seccomp=auto` falls
  back to NO_NEW_PRIVS if BPF fails; `required` is fail-closed. Docker profile
  mirror: `deploy/seccomp/sedat.json`.
- Phase note [docs/phases/P10_09_seccomp_bpf.md](docs/phases/P10_09_seccomp_bpf.md).

## [0.1.8] – 2026-11-20

### Added

- **P10.8 / E2 ACME ARI:** prefer RFC 9773 `renewalInfo` suggested windows when
  the CA directory exposes them (`acme.ari = true` by default); otherwise renew
  at `notAfter − acme.renew_days_before` (default 30). Renewal loop no longer
  re-issues every 24h blindly.
- Phase note [docs/phases/P10_08_acme_ari.md](docs/phases/P10_08_acme_ari.md).

## [0.1.7] – 2026-11-20

### Added

- **P10.7 / E1 optional upstream mTLS:** `https://` upstreams with optional
  `upstream_mtls_cert` / `upstream_mtls_key` / `upstream_mtls_ca` (all default
  empty / off). Plaintext `http://` remains the recommended default for Seda.
  Outbound PROXY is skipped on HTTPS (TLS ClientHello first).
- Phase note [docs/phases/P10_07_upstream_mtls.md](docs/phases/P10_07_upstream_mtls.md).

## [0.1.6] – 2026-11-20

### Added

- **P10.6 / E3 Upstream IP pin:** optional per-route `upstream_allowlist`
  (IPs/CIDRs). When set, DNS results and connected peer must match
  (fail-closed 502 / audit `upstream_ip_pin`).
- Phase note [docs/phases/P10_06_upstream_ip_pin.md](docs/phases/P10_06_upstream_ip_pin.md).

## [0.1.5] – 2026-11-20

### Added

- **P10.5 / E6 Admin selftest:** `selftest` admin command runs structured
  health checks (config, listens, PROXY encode, limits, TLS paths, uptime);
  optional JSONL `admin_selftest` event.
- Phase note [docs/phases/P10_05_admin_selftest.md](docs/phases/P10_05_admin_selftest.md).

## [0.1.4] – 2026-11-20

### Added

- **P10.4 / E4 Admin tokens:** optional `AUTH <token>` on the admin Unix socket
  (`SEDAT_ADMIN_TOKEN` > `admin_token_file` > `admin_token`). Empty = FS ACL
  only. Constant-time verify; failed auth → JSONL `admin_auth_fail`.
- Phase note [docs/phases/P10_04_admin_tokens.md](docs/phases/P10_04_admin_tokens.md).

## [0.1.3] – 2026-11-20

### Added

- **P10.3 Temporary IP bans:** after consecutive rate-limit denials
  (`limits.ban_after_rate_limit_strikes`, default 20; `0` disables), ban the
  client IP for `ban_duration_secs` (default 60) with **403** fail-closed
  responses; log ban/unban via tracing and JSONL (`ip_ban` / `ip_unban`) with
  `request_id` when available.
- Phase note [docs/phases/P10_03_ip_bans.md](docs/phases/P10_03_ip_bans.md).

## [0.1.2] – 2026-11-20

### Added

- **P10.2 / E5 JSONL audit sink:** optional `logging.audit_jsonl` append-only
  file (default off) for `startup`, `config_reload`, and `proxy_deny` events;
  includes `request_id` on denials when available; size-based rotate via
  `audit_jsonl_max_bytes`.
- Phase note [docs/phases/P10_02_jsonl_audit.md](docs/phases/P10_02_jsonl_audit.md).

## [0.1.1] – 2026-11-20

### Added

- **P10.1 Request-ID:** generate/propagate `x-request-id` (configurable) on each
  proxied request; inject as HTTP header **after** outbound PROXY framing; echo
  on responses; include `request_id` in proxy logs (`logging.request_id`,
  `logging.request_id_header`).
- Roadmap [docs/ROADMAP_P10.md](docs/ROADMAP_P10.md) and phase note
  [docs/phases/P10_01_request_id.md](docs/phases/P10_01_request_id.md).

## [0.1.0] – 2026-11-20

### Added

- Initial SeDat reverse-proxy implementation (HTTP/1.1 + HTTP/2, TLS/ACME,
  PROXY protocol, hardening, admin socket, P09 ops extras).
