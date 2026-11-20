# SeDat – Requirements

Companion: **[Seda](https://github.com/WPreier/seda)** delivers static pages from memory. SeDat is the edge reverse proxy in front of Seda.

## Functional

1. **Reverse proxy** with virtual-host and path-prefix routing to one or more upstreams.
2. **TLS termination** (rustls): TLS 1.2 + 1.3 only.
3. **ACME DNS-01** certificate issuance and renewal (`instant-acme`); staging default in development.
4. **Protocols:** HTTP/1.1, HTTP/2; HTTP/3 optional behind feature/config flag.
5. **PROXY Protocol v2** outbound to Seda (v1 optional); inbound PROXY only with explicit allowlist (default off).
6. **Config lifecycle:** TOML, hidden active copy, fail-closed with line+reason, `--resetconfig`, schema version, hot-reload.
7. **Embedded documentation** at `/sedat` and `/seda` (configurable, default on).
8. **Embedded default 404** page (single binary, no external assets).
9. **Admin Unix socket** for status, reload, cert-info (no public HTTP admin).
10. **Port 80** HTTPS redirect when TLS is enabled (no HTTP-01 challenge required).

## Non-functional / security

1. Fail-closed configuration and trust boundaries.
2. Privilege drop after binding privileged ports (Linux).
3. Connection, header, body, idle/read-rate, and per-IP rate limits.
4. Non-blocking logging (bounded channel; never block request path).
5. SNI ↔ Host consistency checks.
6. Strict header hygiene / smuggling defenses.
7. Primary platform: **Linux**; Windows development via **WSL2 / Docker**.

## Explicit non-goals (MVP)

- Pingora-based implementation
- Windows-native production privilege model / systemd
- Public HTTP admin UI
- OCSP stapling as a hard security dependency
- Blind trust in `X-Forwarded-For`

## Acceptance (MVP / Phase 8)

- Client → SeDat (HTTPS) → Mock-Seda or Seda with PROXY v2 works end-to-end.
- Invalid config does not replace active config.
- CI green on Linux; WSL/Docker path documented.
- Phase docs under `docs/phases/` present for P0–P8.
