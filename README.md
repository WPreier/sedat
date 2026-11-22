# SeDat

**SeDat** (türkisch: „der Rechtschaffene“) – minimaler, hoch sicherer Reverse-Proxy in Rust.

Companion-Projekt: **[Seda](https://github.com/WPreier/seda)** (Static Memory Client).

```
Internet → SeDat (TLS, h1/h2/h3*, ACME DNS-01, Limits)
        → PROXY Protocol v2 → Seda / Mock-Seda
```

\* HTTP/3 hinter Feature-Flag `http3` / `experimental.h3`.

## Status

**MVP / Release-Kandidat** – Phasen P0–P8 implementiert. Primärplattform: **Linux**. Windows-Entwicklung über **WSL2** oder **Docker**.

## Quick start

```bash
cargo test
cargo run -- --config examples/config/good.toml --listen 127.0.0.1:8080
```

Docker:

```bash
docker compose -f docker-compose.dev.yml up --build mock-seda
docker build -f deploy/Dockerfile -t sedat:dev .
```

Siehe [docs/DEV_SETUP.md](docs/DEV_SETUP.md).

## Dokumentation

| Thema | Link |
|-------|------|
| **Installation** | [docs/INSTALL.md](docs/INSTALL.md) |
| **Update / Rollback** | [docs/UPDATE.md](docs/UPDATE.md) |
| Operations | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Config & Lifecycle | [docs/CONFIG.md](docs/CONFIG.md) |
| Beispiel-TOML (vollständig) | [examples/config/full.example.toml](examples/config/full.example.toml) |
| Dev-Setup (Linux/WSL/Docker) | [docs/DEV_SETUP.md](docs/DEV_SETUP.md) |
| Requirements | [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) |
| Architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Security / Threat model | [docs/SECURITY.md](docs/SECURITY.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Connection to Seda | [docs/CONNECTION.md](docs/CONNECTION.md) |
| Decisions (ADR) | [docs/DECISIONS.md](docs/DECISIONS.md) |
| Ideas / Roadmaps | [docs/IDEAS.md](docs/IDEAS.md) · [docs/phases/](docs/phases/) |

Einstieg Prod: **INSTALL** → Beispiel-Config → **OPERATIONS**. Bestehende Installation: **UPDATE**.

## CLI

```text
sedat [--config PATH] [--listen ADDR] [--resetconfig] [--validate] [--migrate-config] [--version]
```
