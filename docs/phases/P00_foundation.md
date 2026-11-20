# Phase 0 – Specs & Fundament

## 1. Ziel und Nicht-Ziele

**Ziel:** Entscheidungsfähige Specs, Cargo-Skelett, CI, Dev-Setup (Linux/WSL/Docker).

**Nicht-Ziele:** Proxy-Logik, TLS, ACME (kommen in späteren Phasen).

## 2. Defaults + Begründung

Siehe [DECISIONS.md](../DECISIONS.md): hyper/tokio/rustls, DNS-01, PROXY v2, TOML fail-closed, Linux-primär.

## 3. Testmatrix

| Art | Was | Plattform |
|-----|-----|-----------|
| Unit | `version` / smoke | alle |
| Tooling | `cargo fmt`, `clippy -D warnings` | CI Linux |
| Example | `hello_listen` starts | alle |

## 4. Praktisches Beispiel

```bash
cargo test
cargo run --example hello_listen
# erwartet: Listening on 127.0.0.1:18080 — placeholder 503
```

## 5. Spec-Diff

- Neu: ARCHITECTURE, SECURITY, OPERATIONS, IDEAS, DECISIONS, DEV_SETUP
- Ausbau: REQUIREMENTS, CONFIG, CONNECTION
- Neu: CI, docker-compose.dev.yml, Cargo.toml

## 6. Risiken / nächste Schritte

- Windows ohne WSL: nur best-effort → Phase 1+ mit Docker absichern
- Specs noch ohne Laufzeitbeweis → Phase 1 Config-Lifecycle
