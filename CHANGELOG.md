# Changelog

All notable changes to SeDat are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
