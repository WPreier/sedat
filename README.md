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

- [Requirements](docs/REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Operations](docs/OPERATIONS.md)
- [Config & Lifecycle](docs/CONFIG.md)
- [Connection to Seda](docs/CONNECTION.md)
- [Decisions (ADR)](docs/DECISIONS.md)
- [Ideas](docs/IDEAS.md)
- [Phase notes](docs/phases/)

## CLI

```text
sedat [--config PATH] [--listen ADDR] [--resetconfig] [--validate] [--version]
```
