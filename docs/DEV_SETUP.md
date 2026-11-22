# SeDat – Development setup

Same test command everywhere:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Native Linux

1. Install Rust (rustup): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. `git clone … && cd sedat`
3. `cargo test`
4. Optional: `docker compose -f docker-compose.dev.yml up` for Mock-Seda / Pebble

## WSL2 (Windows)

1. Install WSL2 + Ubuntu.
2. Inside WSL: install rustup as on Linux.
3. Clone/mount the repo and run `cargo test`.
4. For Docker-backed services, use Docker Desktop with WSL2 backend.

> Privilege-drop and systemd tests run under Linux/WSL; they are skipped on native Windows.

## Docker-only (no local Rust)

```bash
docker run --rm --dns 8.8.8.8 \
  -v "$PWD:/src" -w /src rust:latest \
  bash -c 'export PATH=/usr/local/cargo/bin:$PATH; cargo test'
```

Or build the release image:

```bash
docker build -f deploy/Dockerfile -t sedat:dev .
```

> If crates.io DNS fails inside Docker Desktop, pass `--dns 8.8.8.8`.

## Windows native (best-effort)

```powershell
winget install Rustlang.Rustup
# restart shell so cargo is on PATH
cargo test
```

Not supported for production: privilege drop, Unix admin socket (use named alternative in tests), systemd.

## Useful examples

| Example | Command |
|---------|---------|
| Placeholder listen | `cargo run --example hello_listen` |
| Config fail-closed | `cargo run --example config_demo` |
| Minimales TOML | `examples/config/good.toml` |
| Vollbeispiel TOML | `examples/config/full.example.toml` (siehe README dort) |
| H1 proxy demo | see `examples/proxy_h1/` |
| ACME staging | see `examples/acme_staging/` |
| Hardening scripts | see `examples/hardening/` |
| HTTP/3 | see `examples/http3/` (feature `http3`) |
| E2E | see `examples/e2e_seda/` |

Produktion / Update: [INSTALL.md](INSTALL.md) · [UPDATE.md](UPDATE.md) · [CONFIG.md](CONFIG.md) · [OPERATIONS.md](OPERATIONS.md).
