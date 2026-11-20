# Changelog

All notable changes to SeDat are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
