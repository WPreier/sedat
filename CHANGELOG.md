# Changelog

All notable changes to SeDat are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.37] – 2026-11-22

### Added

- **P16.3 Prometheus uptime + bans:** expose `sedat_uptime_seconds` and
  `sedat_bans_active` gauges on admin/metrics. Phase note
  [docs/phases/P16_03_uptime_bans_gauges.md](docs/phases/P16_03_uptime_bans_gauges.md).

## [0.1.36] – 2026-11-22

### Added

- **P16.2 config_reload restart_required:** JSONL `config_reload` events include
  `restart_required: […]` (boot-bound keys still needing process restart). Phase note
  [docs/phases/P16_02_reload_restart_required_audit.md](docs/phases/P16_02_reload_restart_required_audit.md).

## [0.1.35] – 2026-11-22

### Added

- **P16.1 Prometheus restart_required gauges:** expose
  `sedat_restart_required{key="…"}` (0/1) for all boot-bound keys from the P15.3
  snapshot so scrapers/alerts need not parse admin text. Phase note
  [docs/phases/P16_01_restart_required_gauge.md](docs/phases/P16_01_restart_required_gauge.md).

## [0.1.34] – 2026-11-22

### Added

- **P15.3 Restart-required drift:** boot snapshot of listen/sandbox/metrics/ACME-cold
  knobs; admin `status`/`reload` annotate `restart_required=…` and selftest fails
  when live config drifts. Next: [docs/ROADMAP_P16.md](docs/ROADMAP_P16.md). Phase note
  [docs/phases/P15_03_restart_required_drift.md](docs/phases/P15_03_restart_required_drift.md).

## [0.1.33] – 2026-11-22

### Changed

- **P15.2 instant-acme 0.8:** upgrade so `Challenge.token` is optional (newer
  Pebble `dns-persist-01` omits it). Unpin Compose Pebble to `:latest`. Phase note
  [docs/phases/P15_02_instant_acme_token.md](docs/phases/P15_02_instant_acme_token.md).

## [0.1.32] – 2026-11-21

### Fixed

- **P15.1 Pebble CI hard-green:** ACME HTTP client sends `User-Agent`; Compose
  pins `ghcr.io/letsencrypt/pebble:2.7.0` (avoids `:latest` `dns-persist-01`
  breaking `instant-acme` 0.7 `token` deser). Pebble job is a hard gate again.
  Phase note
  [docs/phases/P15_01_pebble_ci_stabilize.md](docs/phases/P15_01_pebble_ci_stabilize.md).

## [0.1.31] – 2026-11-21

### Fixed

- **P15.1 Stabilize Pebble CI:** Compose Pebble `command` matches image ENTRYPOINT
  `/app` (flags only; drop bogus `-dnsserver`); CI wait fails fast with container
  logs. Roadmap [docs/ROADMAP_P15.md](docs/ROADMAP_P15.md); phase note
  [docs/phases/P15_01_pebble_ci_stabilize.md](docs/phases/P15_01_pebble_ci_stabilize.md).

## [0.1.30] – 2026-11-21

### Changed

- **P14.6 Hot-reload remaining knobs:** admin/`SIGHUP` reload hot-swaps ban-share
  store (invalid config keeps previous — fail-closed) and live ACME knobs when
  the renewal loop was started at boot (`enabled=false` idles). Still restart-only:
  listen binds, Landlock/seccomp, metrics bind, ACME enable from cold. Phase note
  [docs/phases/P14_06_hot_reload_remaining.md](docs/phases/P14_06_hot_reload_remaining.md).

## [0.1.29] – 2026-11-21

### Added

- **P14.5 Upstream chunked decode:** decode upstream `Transfer-Encoding: chunked`
  responses into a plain streamed body (TE takes precedence over Content-Length;
  trailers discarded). Oversize vs `max_body_bytes` fail-closed. Phase note
  [docs/phases/P14_05_upstream_chunked_decode.md](docs/phases/P14_05_upstream_chunked_decode.md).

## [0.1.28] – 2026-11-21

### Changed

- **P14.4 TCP upstream body streaming:** outbound HTTP/1.1 uses chunked
  transfer (no full request buffer); upstream responses stream via channel
  under `max_body_bytes`. Oversize is fail-closed (**413**). Phase note
  [docs/phases/P14_04_tcp_upstream_stream.md](docs/phases/P14_04_tcp_upstream_stream.md).

## [0.1.27] – 2026-11-21

### Changed

- **P14.3 H3 streamed bodies:** H3 edge streams request DATA into a channel body
  and response frames out (no full intermediate buffer); oversize vs
  `max_body_bytes` is fail-closed with **413**. Proxy success path no longer
  re-collects response bodies. Phase note
  [docs/phases/P14_03_h3_streamed_bodies.md](docs/phases/P14_03_h3_streamed_bodies.md).

## [0.1.26] – 2026-11-21

### Added

- **P14.2 HTTP/3 request proxy:** feature `http3` now includes hyperium `h3`
  0.0.8 + `h3-quinn` 0.0.10; QUIC streams resolve requests and run through
  `proxy::handle_request` (bodies buffered under `max_body_bytes`). Smoke test
  `tests/h3_proxy.rs`; CI clippy/tests with `--features http3`. Phase note
  [docs/phases/P14_02_h3_request_proxy.md](docs/phases/P14_02_h3_request_proxy.md).

## [0.1.25] – 2026-11-21

### Added

- **P14.1 Broaden hot-reload:** `Limiter::reconfigure` on admin/`SIGHUP` reload;
  static TLS cert/key hot-swap when paths are set; Unix SIGHUP handler.
  Restart still required for listen/sandbox/ACME/ban-share. Roadmap
  [docs/ROADMAP_P14.md](docs/ROADMAP_P14.md); phase note
  [docs/phases/P14_01_hot_reload_broaden.md](docs/phases/P14_01_hot_reload_broaden.md).

## [0.1.24] – 2026-11-21

### Added

- **P13.2 Multiple DNS providers:** working Cloudflare DNS-01 (API v4, zone
  lookup, TXT present/cleanup) and generic HTTP **webhook** provider; injectable
  `DnsHttpTransport` for mocks. Secrets via `SEDAT_CLOUDFLARE_API_TOKEN` /
  `SEDAT_DNS_WEBHOOK_BEARER`. Default remains `dns_provider = "file"` + ACME
  `directory = "staging"`. Phase note
  [docs/phases/P13_02_dns_providers.md](docs/phases/P13_02_dns_providers.md).

## [0.1.23] – 2026-11-21

### Added

- **P13.1 / E8 HTTP/3 attack corpus:** programmatic QUIC connection flood, UDP
  junk, and stream-open storm tests (`tests/h3_attack_corpus.rs`) behind
  `--features http3`, with strict caps (no multi-GB archive). Roadmap
  [docs/ROADMAP_P13.md](docs/ROADMAP_P13.md); phase note
  [docs/phases/P13_01_e8_h3_corpus.md](docs/phases/P13_01_e8_h3_corpus.md).

### Fixed

- **`http3` feature build:** drop broken optional `h3` / `h3-quinn` 0.0.7
  (quinn 0.11 `StreamId` API drift); feature is Quinn-only for the experimental
  listener + corpus. Set QUIC ALPN to `h3`.
- **CI vs rustc 1.100:** `cargo fmt` sweep + clippy cleanups
  (`manual_contains`, `io_other_error`, `&Box<T>`, etc.); allow
  `clippy::field_reassign_with_default` for test helpers.

## [0.1.22] – 2026-11-21

### Added

- **P12.6 Shared ban state:** optional file-backed HMAC JSON map
  (`limits.ban_share_path` + `SEDAT_BAN_SHARE_SECRET` / secret file); max expiry
  wins; unban tombstones; disabled by default; fail-closed without secret.
  **P12 complete.** Phase note
  [docs/phases/P12_06_shared_ban_state.md](docs/phases/P12_06_shared_ban_state.md).

## [0.1.21] – 2026-11-21

### Added

- **P12.5 Upstream pin re-resolve:** `upstream_allowlist` accepts hostname
  literals beside IP/CIDR; cached DNS refresh via `upstream_dns_refresh_secs`
  (default 60, `0` = every connect); fail-closed if the expanded pin is empty or
  peers leave it. Phase note
  [docs/phases/P12_05_upstream_pin_reresolve.md](docs/phases/P12_05_upstream_pin_reresolve.md).

## [0.1.20] – 2026-11-21

### Added

- **P12.4 Time-based audit rotation:** `logging.audit_jsonl_max_age_secs`
  (default `0` = off) rotates `audit_jsonl` to `*.jsonl.1` beside the existing
  size trigger. Phase note
  [docs/phases/P12_04_audit_age_rotate.md](docs/phases/P12_04_audit_age_rotate.md).

## [0.1.19] – 2026-11-21

### Added

- **P12.3 Token rotation without full reload:** admin `reload-token` re-reads
  `SEDAT_ADMIN_TOKEN` / `admin_token_file` / `admin_token` into a live gate
  shared by socket `AUTH` and metrics Bearer; dual-token overlap via
  `admin_token_overlap_secs` (default 300); fail-closed if sources would clear
  auth. JSONL `admin_token_reload`. Phase note
  [docs/phases/P12_03_token_rotation.md](docs/phases/P12_03_token_rotation.md).

## [0.1.18] – 2026-11-21

### Added

- **P12.2 Sliding / extending bans:** while banned, continued hits refresh TTL
  to `now + ban_duration_secs` (`ban_extend_while_banned = true` by default);
  JSONL `ip_ban_extend` (throttled by `ban_extend_min_interval_secs`, default 1).
  Phase note [docs/phases/P12_02_sliding_bans.md](docs/phases/P12_02_sliding_bans.md).

## [0.1.17] – 2026-11-21

### Added

- **P12.1 Metrics sidecar token:** when an admin token is set, loopback
  `GET /metrics` requires `Authorization: Bearer <token>` (fail-closed);
  JSONL `metrics_auth_fail` on reject. Admin socket AUTH unchanged. Phase note
  [docs/phases/P12_01_metrics_sidecar_token.md](docs/phases/P12_01_metrics_sidecar_token.md).
- Roadmap [docs/ROADMAP_P12.md](docs/ROADMAP_P12.md).

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
