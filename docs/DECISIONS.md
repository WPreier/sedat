# SeDat – Architecture Decision Records

## ADR-001: HTTP stack = tokio + hyper (not Pingora)

- **Status:** Accepted
- **Context:** Need minimal, rustls-friendly proxy with full control and future HTTP/3.
- **Decision:** Use tokio + hyper 1.x + h2; later quinn/h3 behind a feature flag.
- **Avoid:** Early commitment to Pingora (heavy, rustls experimental, H3 incomplete).

## ADR-002: TLS = rustls, 1.2 + 1.3 only

- **Status:** Accepted
- **Decision:** rustls with TLS 1.2/1.3 (prefer 1.3). No OpenSSL hard dependency.
- **Avoid:** TLS 1.0/1.1, SSLv2/3.

## ADR-003: Certificates via ACME DNS-01 (instant-acme)

- **Status:** Accepted
- **Decision:** DNS-01 with `instant-acme`; staging default in dev; persist account; renew ~30d.
- **Avoid:** Manual-only cert ops; HTTP-01 as sole method.

## ADR-004: OCSP not an operational hard dependency

- **Status:** Accepted
- **Context:** Let’s Encrypt OCSP sunset; empty staples common.
- **Decision:** Do not require OCSP stapling for “secure” posture.

## ADR-005: Client IP via PROXY Protocol v2 + trust allowlist

- **Status:** Accepted
- **Decision:** Outbound PROXY v2 to Seda; inbound PROXY default off + CIDR allowlist.
- **Avoid:** Blind `X-Forwarded-For`; accepting PROXY from arbitrary clients.

## ADR-006: TOML config, hidden active copy, fail-closed

- **Status:** Accepted
- **Decision:** Same philosophy as Seda: active hidden copy, line+reason errors, `--resetconfig`, schema version.
- **Avoid:** YAML ambiguity; silent defaults on parse failure.

## ADR-007: Privilege drop + systemd / Docker hardening

- **Status:** Accepted
- **Decision:** Bind → drop user; systemd notify+watchdog; Docker cap_drop / no-new-privileges / read-only where possible.
- **Avoid:** Running as root permanently.

## ADR-008: Non-blocking logging

- **Status:** Accepted
- **Decision:** tracing + bounded async channel; overflow drops, never blocks request path.

## ADR-009: HTTP/3 behind feature/config flag

- **Status:** Accepted
- **Decision:** `features = ["http3"]` and `experimental.h3`; h1/h2 remain primary.

## ADR-010: Single binary with embedded docs

- **Status:** Accepted
- **Decision:** Embed `/sedat` and `/seda` docs; default 404 page; no runtime asset server required.
