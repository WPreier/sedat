# SeDat – Architecture

## Overview

SeDat is a minimal reverse proxy that terminates TLS, obtains certificates via ACME DNS-01, applies edge limits, and forwards requests to Seda (or other upstreams) with PROXY Protocol v2.

```text
Client
  │  HTTPS (HTTP/1.1 | HTTP/2 | optional HTTP/3)
  ▼
SeDat
  │  TLS terminate · SNI · rate-limit · route
  │  privilege-dropped process
  ▼
PROXY Protocol v2 (recommended) or plain HTTP
  │
  ▼
Seda / upstream (localhost or private network only)
```

## Process model

1. Parse CLI / load active config (fail-closed).
2. Bind listeners (may require elevated privileges for :443 / :80).
3. **Privilege drop** to unprivileged user (Linux).
4. Spawn accept loops (h1/h2 TCP; optional h3 UDP).
5. Admin Unix-domain socket (status / reload / cert-info).
6. ACME renewal task + config hot-reload watcher.

## Module map

| Module | Responsibility |
|--------|----------------|
| `config` | TOML parse, validate, active copy, reload, schema version |
| `proxy` | Routing, forwarding, 404 embed, header hygiene |
| `tls` | rustls acceptor, SNI, cert hot-swap |
| `acme` | DNS-01 via `instant-acme`, account persist, renewal |
| `limits` | Connection / header / body / rate / Slowloris caps |
| `hardening` | Privilege drop, capabilities hints |
| `admin` | Unix socket control plane |
| `embed` | `/sedat` / `/seda` documentation routes |
| `http3` | Feature-gated QUIC/h3 listener |

## Stack (defaults)

- **Runtime:** tokio
- **HTTP:** hyper 1.x + h2
- **TLS:** rustls (TLS 1.2 + 1.3 only)
- **ACME:** instant-acme (DNS-01)
- **HTTP/3:** quinn + h3 behind `experimental.h3` / feature `http3`

Not used: Pingora, OpenSSL as hard dependency, HTTP-01 as sole challenge.

## Trust boundaries

1. **Public listeners** – untrusted clients; strict header/size limits; unknown Host rejected.
2. **Admin socket** – trusted local operators only (filesystem permissions).
3. **Upstream** – SeDat is the only allowed PROXY source; Seda must not be public.
4. **Inbound PROXY** – disabled by default; only behind explicit CIDR allowlist.

## Routing

Virtual hosts + path-prefix routes from config. Default: reject unknown Host with embedded 404/400. Embedded docs paths (`/sedat`, `/seda`) short-circuit when enabled.

## Config lifecycle (summary)

User edits a visible TOML file. On successful validation SeDat copies it to a hidden **active** config (mode `0600`). Failures report **line + reason** and keep the previous active config. See [CONFIG.md](CONFIG.md).

## Related docs

- [SECURITY.md](SECURITY.md) – security principles and checklist
- [THREAT_MODEL.md](THREAT_MODEL.md) – assets, abuse cases, test mapping
- [OPERATIONS.md](OPERATIONS.md) – deploy, systemd, Docker
- [DECISIONS.md](DECISIONS.md) – ADRs
- [CONNECTION.md](CONNECTION.md) – SeDat ↔ Seda
