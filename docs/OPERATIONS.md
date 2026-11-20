# SeDat – Operations

## Platforms

| Environment | Support |
|-------------|---------|
| Linux (native / systemd) | **Primary production** |
| WSL2 + Docker | Development & CI parity |
| Windows native | Build/test best-effort; **no** privilege-drop / systemd / Landlock |

See [DEV_SETUP.md](DEV_SETUP.md).

## Quick start (dev)

```bash
cargo build
cargo run -- --config examples/config/good.toml --listen 127.0.0.1:8080
```

Docker:

```bash
docker compose -f docker-compose.dev.yml up --build
```

## Config paths

- User config: `--config PATH` (editable).
- Active copy: `.sedat.active.toml` next to state dir (mode `0600`).
- Reset: `sedat --resetconfig --config PATH`.
- Reload: admin `reload` — fail-closed; emits **security-diff audit** lines (`sedat::audit`).

## Listeners

- HTTP (redirect): default `:80` in production sketches.
- HTTPS: `:443` (h1/h2); optional UDP `:443` for HTTP/3 when `experimental.h3 = true`.
- Admin: Unix socket path from config (e.g. `/run/sedat/admin.sock`).
- Optional metrics sidecar: `server.metrics_listen = "127.0.0.1:9090"` (loopback only).

## systemd (sketch)

Unit file: [`deploy/sedat.service`](../deploy/sedat.service).

- `Type=notify`, `WatchdogSec=` set.
- Start as root (or with `CAP_NET_BIND_SERVICE`), drop via SeDat config `user`/`group`.
- `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true` recommended.
- Align with `[hardening] landlock/seccomp = "auto"` inside the process.

## Docker hardening

See [`deploy/Dockerfile`](../deploy/Dockerfile) and compose:

- `USER` non-root after image setup
- `cap_drop: [ALL]`
- `security_opt: [no-new-privileges:true]`
- read-only rootfs + writable state volume

## ACME / Pebble CI

- Dev/staging endpoint by default; **Pebble** alias `acme.directory = "pebble"` for local CA tests.
- Production: set `acme.directory = "production"` explicitly.
- DNS-01 provider trait; file/manual + Cloudflare stub.
- Account JSON persisted under state dir.
- Full DNS-01 order/finalize path; on failure previous cert stays active.
- CI: GitHub Actions job `pebble-issue` and Compose service `pebble-issue` (profile `acme`) with `PEBBLE_VA_ALWAYS_VALID=1` — no LE staging network.

```bash
docker compose -f docker-compose.dev.yml --profile acme up pebble
# or one-shot:
docker compose -f docker-compose.dev.yml --profile acme run --rm pebble-issue
# local helper:
# scripts/ci_pebble_issue.sh
```

See `examples/acme_staging/README.md` and [ROADMAP_P09.md](ROADMAP_P09.md).

## Admin

Unix-domain socket after bind:

- Default mode **`0600`** (owner only).
- With `server.admin_group = "sedat-admin"` → mode **`0660`** + group ownership.
- **Token (P10.4):** empty `admin_token` / file / env → FS ACL only (dev-friendly). When a token is set (`SEDAT_ADMIN_TOKEN` > `admin_token_file` > `admin_token`), send `AUTH <token>` first. Failed auth → JSONL `admin_auth_fail` when audit enabled. See [phases/P10_04_admin_tokens.md](phases/P10_04_admin_tokens.md).

```bash
# status / health / metrics / reload / cert (Linux)
# With token:
printf 'AUTH %s\nstatus\n' "$SEDAT_ADMIN_TOKEN" | socat - UNIX-CONNECT:/run/sedat/admin.sock
# Without token (FS ACL only):
echo status  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo health  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo metrics | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo reload  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo cert    | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

## Health / metrics

- Admin commands `health` / `metrics` (Prometheus text exposition).
- Optional loopback HTTP sidecar (`GET /metrics`) when `metrics_listen` is set.
- Script: `scripts/prometheus_admin_scrape.sh [admin.sock]`.
- No built-in public HTTP `/metrics` or `/health` control endpoint.

## PROXY after TLS

For LBs that terminate nothing and send PROXY inside TLS (PP2 over TLS):

```toml
[proxy_protocol]
inbound_enabled = true
inbound_allowlist = ["10.0.0.0/8"]
inbound_placement = "after_tls"
```

Default remains `before_tls` + inbound off (fail-closed).

## Request-ID correlation

Enabled by default:

```toml
[logging]
request_id = true
request_id_header = "x-request-id"
```

- Wire: HTTP header **after** outbound PROXY bytes (not a PROXY TLV).
- Client may supply a valid id; invalid values are replaced.
- Successful proxy logs include `request_id`; the same header is echoed on the response.

See [phases/P10_01_request_id.md](phases/P10_01_request_id.md) and [ROADMAP_P10.md](ROADMAP_P10.md).

## JSONL audit sink

Disabled by default. Enable with a path under the state directory:

```toml
[logging]
audit_jsonl = "./state/audit.jsonl"
audit_jsonl_max_bytes = 10485760
```

Events (one JSON object per line): `startup`, `config_reload` (security-diff), `proxy_deny`
(with `request_id` when available), `ip_ban` / `ip_unban`. Contended writes are dropped
(non-blocking). See [phases/P10_02_jsonl_audit.md](phases/P10_02_jsonl_audit.md).

## Temporary IP bans

After consecutive rate-limit denials, SeDat can temporarily ban the client IP:

```toml
[limits]
ban_after_rate_limit_strikes = 20  # 0 disables
ban_duration_secs = 60
```

- While banned: **403** (fail-closed) until TTL expires.
- Logging: `tracing` warn/info + JSONL `ip_ban` / `ip_unban` (with `request_id` when available).
- See [phases/P10_03_ip_bans.md](phases/P10_03_ip_bans.md).

## Firewall

- Allow TCP 80/443 (and UDP 443 if HTTP/3 enabled).
- Block direct access to Seda from the internet.
- Do not expose admin socket or metrics sidecar beyond loopback / admin group.

## Release notes

Version via Cargo/`--version`. Optional SBOM via `cargo cyclonedx` (documented in Phase 8). Checklist: [phases/P08_e2e_release.md](phases/P08_e2e_release.md). P09: [ROADMAP_P09.md](ROADMAP_P09.md). P10: [ROADMAP_P10.md](ROADMAP_P10.md).
