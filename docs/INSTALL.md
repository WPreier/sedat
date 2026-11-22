# SeDat – Installationsanleitung

Primärplattform: **Linux**. Entwicklung auch über **WSL2** oder **Docker**.
Windows nativ ist nur Build/Test best-effort (kein Privilege-Drop / systemd /
Landlock). Siehe [DEV_SETUP.md](DEV_SETUP.md).

Verwandt: [UPDATE.md](UPDATE.md) · [OPERATIONS.md](OPERATIONS.md) ·
[CONFIG.md](CONFIG.md) · Beispiel
[examples/config/full.example.toml](../examples/config/full.example.toml).

## Voraussetzungen

| Tool | Zweck |
|------|--------|
| **Rust** (rustup, stable ≥ 1.75) | Build aus Quellcode |
| **git** | Repository |
| **systemd** (Prod) | Unit `deploy/sedat.service` |
| **Docker** (optional) | CI-Parität, Mock-Seda, Pebble |
| **socat** (optional) | Admin-Socket (`health` / `ready` / `selftest`) |

Rust installieren (Linux/WSL):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustc --version
```

## Build aus Quellcode

```bash
git clone https://github.com/WPreier/sedat.git
cd sedat
cargo test
cargo build --release
# Binary: target/release/sedat
```

HTTP/3 (optional Feature):

```bash
cargo build --release --features http3
```

Docker-Image:

```bash
docker build -f deploy/Dockerfile -t sedat:local .
```

## Erste Konfiguration

1. Default-TOML erzeugen und aktivieren:

```bash
./target/release/sedat --config ./sedat.toml --resetconfig
./target/release/sedat --config ./sedat.toml --validate
```

2. Für Produktion die annotierte Vorlage nutzen und anpassen:

- [examples/config/full.example.toml](../examples/config/full.example.toml)
- Kurz: [examples/config/good.toml](../examples/config/good.toml)

3. Mindestens setzen:

- `server.listen` / `listen_tls` / ggf. `http_redirect_listen`
- `server.state_dir` (Persistent, z. B. `/var/lib/sedat`)
- `server.admin_socket` (z. B. `/run/sedat/admin.sock` oder unter `state_dir`)
- `[[routes.hosts]]` + Upstream (privates Netz, `http://…` empfohlen)
- Linux: `server.user` / `server.group` für Privilege-Drop nach Bind
- TLS: entweder `[tls]` mit Dateien **oder** `[acme]` DNS-01 (Staging zuerst)

## Verzeichnisse & Rechte (Linux)

Beispiel-Layout:

```text
/etc/sedat/sedat.toml          # User-Config (root:sedat, 0640)
/var/lib/sedat/                # state_dir (active config, ACME, Audit)
/run/sedat/admin.sock          # Admin-Unix-Socket
/usr/local/bin/sedat           # Binary
```

```bash
sudo useradd --system --home /var/lib/sedat --shell /usr/sbin/nologin sedat
sudo mkdir -p /etc/sedat /var/lib/sedat /run/sedat
sudo cp target/release/sedat /usr/local/bin/sedat
sudo cp examples/config/full.example.toml /etc/sedat/sedat.toml
# … TOML anpassen …
sudo chown -R root:sedat /etc/sedat
sudo chmod 640 /etc/sedat/sedat.toml
sudo chown -R sedat:sedat /var/lib/sedat
```

In der TOML:

```toml
[server]
user = "sedat"
group = "sedat"
state_dir = "/var/lib/sedat"
admin_socket = "/run/sedat/admin.sock"
```

SeDat bindet zuerst (ggf. als root / mit `CAP_NET_BIND_SERVICE`) und droppt
danach auf `user`/`group`. Sandbox: `[hardening] landlock/seccomp = "auto"`.

## systemd

Unit: [`deploy/sedat.service`](../deploy/sedat.service).

```bash
sudo cp deploy/sedat.service /etc/systemd/system/
# ExecStart und Pfade prüfen (Default: /etc/sedat/sedat.toml, WorkingDirectory=/var/lib/sedat)
sudo systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/sedat.service
sudo systemctl enable --now sedat
systemctl status sedat --no-pager
```

cgroup-Limits (`MemoryMax`, `LimitNOFILE`, …) müssen zu
`limits.max_connections` passen — siehe [OPERATIONS.md](OPERATIONS.md).

## Firewall / Listener

| Port / Socket | Typ | Hinweis |
|---------------|-----|---------|
| TCP 80 (Redirect) | öffentlich optional | `http_redirect_listen` |
| TCP 443 | öffentlich | HTTPS h1/h2 |
| UDP 443 | öffentlich optional | nur mit `experimental.h3 = true` **und** Build `--features http3` |
| Admin-Unix-Socket | lokal | **kein** öffentliches HTTP-Admin |
| `metrics_listen` | nur Loopback | z. B. `127.0.0.1:9090` |

Beispiel nftables/ufw: TCP 443 (und ggf. 80) erlauben; Admin-Socket und Metrics
nicht exposed.

## ACME DNS-01 (Tipp)

1. Zuerst **`directory = "staging"`** (Let’s Encrypt Staging) oder Pebble in Dev.
2. `dns_provider`: `file` (manuell/CI), `cloudflare`, oder `webhook`.
3. Secrets über Env (`SEDAT_CLOUDFLARE_API_TOKEN`, `SEDAT_DNS_WEBHOOK_BEARER`), nicht committen.
4. Nach erfolgreichem Staging auf `production` wechseln und Prozess **neu starten**,
   wenn ACME zuvor cold war (`restart_required` / P15.3).

Details: [CONFIG.md](CONFIG.md), [phases/P13_02_dns_providers.md](phases/P13_02_dns_providers.md).

## Verifikation nach Start

```bash
# Prozess
systemctl is-active sedat

# Admin (ohne Token, wenn admin_token leer)
echo status | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo health | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo ready  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo selftest | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

- **`health`**: Liveness (Prozess lebt; optional `restart_required=…`).
- **`ready`**: Readiness — `ERR not_ready` bei Boot-Drift (P17.1).
- **`selftest`**: strukturierte Checks inkl. Sandbox-Modi (P17.5).

Mit Token:

```bash
printf 'AUTH %s\nready\nselftest\n' "$SEDAT_ADMIN_TOKEN" \
  | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

HTTP-Smoke (ohne TLS):

```bash
curl -sS -H 'Host: localhost' http://127.0.0.1:8080/ | head
```

## Docker / Compose (Kurz)

```bash
docker compose -f docker-compose.dev.yml up --build mock-seda
docker build -f deploy/Dockerfile -t sedat:local .
```

Prod-Image: Non-root, `cap_drop`, optional Host-Seccomp-Profil — siehe
[OPERATIONS.md](OPERATIONS.md) „Docker hardening“.

## Nächste Schritte

- Betrieb & Reload: [OPERATIONS.md](OPERATIONS.md)
- Updates: [UPDATE.md](UPDATE.md)
- Threat Model: [THREAT_MODEL.md](THREAT_MODEL.md)
