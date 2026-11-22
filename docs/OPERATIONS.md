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
- Reload: admin `reload` or Unix **SIGHUP** — fail-closed; live limits + ban-share + static TLS + ACME knobs when the loop started at boot (P14.1/P14.6); emits **security-diff audit** (`sedat::audit`). Restart still required for listen/sandbox/metrics bind and ACME enable-from-cold — `status`/`reload` show `restart_required=…` and selftest fails that check until restart (P15.3).

## Listeners

- HTTP (redirect): default `:80` in production sketches.
- HTTPS: `:443` (h1/h2); optional UDP `:443` for HTTP/3 when `experimental.h3 = true`.
- Admin: Unix socket path from config (e.g. `/run/sedat/admin.sock`).
- Optional metrics sidecar: `server.metrics_listen = "127.0.0.1:9090"` (loopback only).
  When an admin token is set, scrapes need `Authorization: Bearer <token>` (P12.1).

## systemd

Unit file: [`deploy/sedat.service`](../deploy/sedat.service).

- `Type=notify`, `WatchdogSec=` set.
- Start as root (or with `CAP_NET_BIND_SERVICE`), drop via SeDat config `user`/`group`.
- `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true` recommended.
- Align with `[hardening] landlock/seccomp = "auto"` inside the process.
- **cgroup limits (P10.10):** `MemoryHigh=384M`, `MemoryMax=512M`, `TasksMax=4096`,
  `LimitNOFILE=65535`, `CPUQuota=200%` — tune for the host; see
  [phases/P10_10_systemd_memory.md](phases/P10_10_systemd_memory.md).
- **Sizing vs TOML (P11.5):** keep `limits.max_connections` aligned with those
  caps — formulas below and
  [phases/P11_05_limits_cgroup_sizing.md](phases/P11_05_limits_cgroup_sizing.md).

```bash
sudo cp deploy/sedat.service /etc/systemd/system/
sudo systemctl daemon-reload
systemd-analyze verify /etc/systemd/system/sedat.service
sudo systemctl enable --now sedat
systemctl show sedat -p MemoryMax -p MemoryHigh -p TasksMax
```

## Sizing: `max_connections` ↔ MemoryMax / LimitNOFILE

In-process limiter (`[limits] max_connections`, default **1024**) rejects new
accepts when full. Outer cgroups/ulimits must still fit that concurrency or the
process hits FD/OOM failures *before* the limiter helps.

Let `C = limits.max_connections`.

| Resource | Rule of thumb | Default check (`C=1024`) |
|----------|---------------|---------------------------|
| **FDs** | `LimitNOFILE ≥ 2×C + 256` | `2304` ≪ `65535` |
| **RAM** | `MemoryMax_MiB ≥ 64…128 + (C × 250…400 KiB)/1024` | ≈ `478 MiB` → shipped `512M` |
| **Soft RAM** | `MemoryHigh ≈ 0.75 × MemoryMax` | `384M` / `512M` |
| **Tasks** | `TasksMax ≥ C + 64` | `4096` ≥ `1088` |

When raising `C`, update **both** `sedat.toml` and `deploy/sedat.service` /
Compose `mem_limit` + `pids_limit` in the same change. Re-measure RSS under
load; the KiB/connection band is a starting point for TLS reverse-proxy work,
not a hard SLA.

Cross-links: [CONFIG.md](CONFIG.md) (`[limits]` + deploy caps),
[phases/P11_05_limits_cgroup_sizing.md](phases/P11_05_limits_cgroup_sizing.md).

## Docker hardening

See [`deploy/Dockerfile`](../deploy/Dockerfile) and compose:

- `USER` non-root after image setup
- `cap_drop: [ALL]`
- `security_opt: [no-new-privileges:true]`
- optional host profile: `security_opt: ["seccomp=deploy/seccomp/sedat.json"]`
  (SeDat also applies an in-process BPF allowlist when `hardening.seccomp` ≠ `off`)
- read-only rootfs + writable state volume
- **memory/pids (P10.10):** Compose `mem_limit` / `mem_reservation` / `pids_limit`
  mirror the systemd ceilings (see `docker-compose.dev.yml` proxy profile).

Seccomp modes: [phases/P10_09_seccomp_bpf.md](phases/P10_09_seccomp_bpf.md).

## ACME / Pebble CI

- Dev/staging endpoint by default; **Pebble** alias `acme.directory = "pebble"` for local CA tests.
- Production: set `acme.directory = "production"` explicitly.
- DNS-01 provider trait; file/manual + Cloudflare stub.
- Account JSON persisted under state dir.
- Full DNS-01 order/finalize path; on failure previous cert stays active.
- CI: GitHub Actions job `pebble-issue` and Compose service `pebble-issue` (profile `acme`) with `PEBBLE_VA_ALWAYS_VALID=1` — no LE staging network.
- Pebble image ENTRYPOINT is `/app`; Compose must pass **flags only**
  (`command: ["-config", "/test/config/pebble-config.json"]`). Do not prefix
  `pebble` (container exits immediately; directory probe never succeeds).
  With `PEBBLE_VA_ALWAYS_VALID=1`, a custom `-dnsserver` is not required.
- Local `pebble-issue` service: keep the official `rust` image PATH
  (`/usr/local/cargo/bin`). Prefer `bash -c` / plain `bash` over `bash -lc`
  (login shells reset PATH → `cargo: command not found`).
- ACME client uses **instant-acme 0.8** (`Challenge.token` optional) so newer
  Pebble challenges (e.g. `dns-persist-01`) deserialize; Compose uses
  `pebble:latest`. See
  [phases/P15_02_instant_acme_token.md](phases/P15_02_instant_acme_token.md).

```bash
docker compose -f docker-compose.dev.yml --profile acme up -d pebble
# wait for directory:
curl -skf https://localhost:14000/dir
# or one-shot:
docker compose -f docker-compose.dev.yml --profile acme run --rm pebble-issue
# local helper:
# scripts/ci_pebble_issue.sh
```

See `examples/acme_staging/README.md` and [ROADMAP_P09.md](ROADMAP_P09.md).

## ACME ARI (renewal scheduling)

When ACME is enabled, SeDat prefers the CA’s **ARI** suggested window (RFC 9773)
if the directory advertises `renewalInfo`. Otherwise it renews
`renew_days_before` days before `notAfter` (default 30). Disable ARI queries with
`acme.ari = false`. Details: [phases/P10_08_acme_ari.md](phases/P10_08_acme_ari.md).

## Admin

Unix-domain socket after bind:

- Default mode **`0600`** (owner only).
- With `server.admin_group = "sedat-admin"` → mode **`0660`** + group ownership.
- **Token (P10.4 / P12.3):** empty `admin_token` / file / env → FS ACL only (dev-friendly). When a token is set (`SEDAT_ADMIN_TOKEN` > `admin_token_file` > `admin_token`), send `AUTH <token>` first. Failed auth → JSONL `admin_auth_fail` when audit enabled. Rotate without process restart: update the file/env, then `reload-token` (overlap window `admin_token_overlap_secs`, default 300; fail-closed if sources empty). See [phases/P10_04_admin_tokens.md](phases/P10_04_admin_tokens.md), [phases/P12_03_token_rotation.md](phases/P12_03_token_rotation.md).
- **Selftest (P10.5 / P11.6):** `selftest` returns PASS/FAIL lines (config, PROXY, limits, TLS paths, allowlists, upstream TCP/TLS-ALPN, uptime); `selftest json` for machine-readable output; audits `admin_selftest`. See [phases/P10_05_admin_selftest.md](phases/P10_05_admin_selftest.md), [phases/P11_06_selftest_deepen.md](phases/P11_06_selftest_deepen.md).
- **Bans (P11.1):** `bans` lists active temporary IP bans; `unban <ip>` clears one (JSONL `admin_unban`). See [phases/P11_01_admin_bans.md](phases/P11_01_admin_bans.md).

```bash
# status / health / metrics / reload / reload-token / cert / selftest / bans / unban (Linux)
# With token:
printf 'AUTH %s\nselftest\n' "$SEDAT_ADMIN_TOKEN" | socat - UNIX-CONNECT:/run/sedat/admin.sock
printf 'AUTH %s\nbans\nunban 203.0.113.50\n' "$SEDAT_ADMIN_TOKEN" | socat - UNIX-CONNECT:/run/sedat/admin.sock
printf 'AUTH %s\nreload-token\n' "$SEDAT_ADMIN_TOKEN" | socat - UNIX-CONNECT:/run/sedat/admin.sock
# Without token (FS ACL only):
echo status  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo health  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo metrics | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo reload  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo cert    | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo bans    | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo selftest| socat - UNIX-CONNECT:/run/sedat/admin.sock
```

## Health / metrics

- Admin commands `health` / `metrics` (Prometheus text exposition).
- Optional loopback HTTP sidecar (`GET /metrics`) when `metrics_listen` is set.
  With admin token configured: `Authorization: Bearer …` required (P12.1); see
  [phases/P12_01_metrics_sidecar_token.md](phases/P12_01_metrics_sidecar_token.md).
- Includes `sedat_audit_dropped_total` (P11.4) for JSONL audit drops.
- Script: `scripts/prometheus_admin_scrape.sh [admin.sock]` (Unix socket; uses `AUTH`).
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
- **Early denials (P11.2):** 429/403/400/431/421/404/502 (handler + pre-hyper smuggling/header-bomb) also echo the header and audit with the same id. See [phases/P11_02_request_id_early_deny.md](phases/P11_02_request_id_early_deny.md).

See [phases/P10_01_request_id.md](phases/P10_01_request_id.md) and [ROADMAP_P10.md](ROADMAP_P10.md).

## JSONL audit sink

Disabled by default. Enable with a path under the state directory:

```toml
[logging]
audit_jsonl = "./state/audit.jsonl"
audit_jsonl_max_bytes = 10485760   # size; 0 = off
audit_jsonl_max_age_secs = 86400   # optional daily age rotate; 0 = off (default)
```

Events (one JSON object per line): `startup`, `config_reload` (security-diff), `proxy_deny`
(with `request_id` when available), `proxy_reject` (inbound PROXY policy fail, pre-HTTP),
`ip_ban` / `ip_ban_extend` / `ip_unban`, `admin_unban`, `admin_token_reload`. Contended writes are dropped
(non-blocking; count as `sedat_audit_dropped_total`). See
[phases/P10_02_jsonl_audit.md](phases/P10_02_jsonl_audit.md),
[phases/P11_03_proxy_reject_jsonl.md](phases/P11_03_proxy_reject_jsonl.md),
[phases/P11_04_audit_dropped_metrics.md](phases/P11_04_audit_dropped_metrics.md),
[phases/P12_04_audit_age_rotate.md](phases/P12_04_audit_age_rotate.md).

## Upstream IP pin

Optional per-route allowlist (empty = unrestricted):

```toml
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://backend.internal:9080"
upstream_allowlist = ["10.0.0.5", "10.0.0.0/8", "db.internal"]  # IP/CIDR/hostname
upstream_dns_refresh_secs = 60  # DNS cache for upstream + hostname pins; 0 = every connect
```

When set, SeDat only connects to peers in the expanded pin (fail-closed). Hostname
entries are re-resolved on the refresh interval (P12.5). See
[phases/P10_06_upstream_ip_pin.md](phases/P10_06_upstream_ip_pin.md),
[phases/P12_05_upstream_pin_reresolve.md](phases/P12_05_upstream_pin_reresolve.md).

## Optional upstream HTTPS / mTLS

Default remains plaintext `http://`. To speak TLS (and optionally present a client
cert) to the upstream:

```toml
[[routes.hosts.paths]]
prefix = "/"
upstream = "https://backend.internal:9443"
upstream_mtls_cert = "./certs/sedat-client.crt"
upstream_mtls_key  = "./certs/sedat-client.key"
upstream_mtls_ca   = "./certs/upstream-ca.crt"
```

Leave cert/key/CA empty for off. Prefer `proxy_protocol.outbound = "off"` with
HTTPS upstreams (PROXY before TLS is skipped anyway). See
[phases/P10_07_upstream_mtls.md](phases/P10_07_upstream_mtls.md).

## Temporary IP bans

After consecutive rate-limit denials, SeDat can temporarily ban the client IP:

```toml
[limits]
ban_after_rate_limit_strikes = 20  # 0 disables
ban_duration_secs = 60
ban_extend_while_banned = true     # default: slide TTL on continued hits
ban_extend_min_interval_secs = 1   # audit throttle; TTL still refreshes every hit
```

- While banned: **403** (fail-closed) until TTL expires.
- Sliding (P12.2, default on): each request while banned refreshes TTL to
  `now + ban_duration_secs` (window does not grow beyond that). Set
  `ban_extend_while_banned = false` for fixed TTL.
- Logging: `tracing` warn/info + JSONL `ip_ban` / `ip_ban_extend` / `ip_unban`
  (with `request_id` when available). Extend audits are throttled by
  `ban_extend_min_interval_secs` (default 1s; `0` = every extend).
- Admin: `bans` / `unban <ip>` (P11.1) — manual clear audits `admin_unban`.
- **Replica share (P12.6, optional):** set `ban_share_path` +
  `SEDAT_BAN_SHARE_SECRET` (or secret file) on a shared volume; max expiry wins;
  unban tombstones. See [phases/P12_06_shared_ban_state.md](phases/P12_06_shared_ban_state.md).
- See [phases/P10_03_ip_bans.md](phases/P10_03_ip_bans.md),
  [phases/P11_01_admin_bans.md](phases/P11_01_admin_bans.md),
  [phases/P12_02_sliding_bans.md](phases/P12_02_sliding_bans.md).

## Firewall

- Allow TCP 80/443 (and UDP 443 if HTTP/3 enabled).
- Block direct access to Seda from the internet.
- Do not expose admin socket or metrics sidecar beyond loopback / admin group.

## Release notes

Version via Cargo/`--version`. Optional SBOM via `cargo cyclonedx` (documented in Phase 8). Checklist: [phases/P08_e2e_release.md](phases/P08_e2e_release.md). P09: [ROADMAP_P09.md](ROADMAP_P09.md). P10: [ROADMAP_P10.md](ROADMAP_P10.md). P11: [ROADMAP_P11.md](ROADMAP_P11.md). P12: [ROADMAP_P12.md](ROADMAP_P12.md).
