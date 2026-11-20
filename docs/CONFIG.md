# SeDat – Config & Lifecycle

## Philosophy (aligned with Seda)

- Operator edits a **user-visible** TOML file.
- On successful validation, SeDat writes a **hidden active copy** (e.g. `.sedat.active.toml`, mode `0600`).
- Parse/validation errors report **line number + reason**; the previous active config remains in force.
- `--resetconfig` restores the embedded default config to the user path and re-activates it.
- `schema_version` field enables fail-closed upgrades / migrations (see below).
- Successful reload emits a **security-diff audit** of trust-boundary keys (see P09.7).

## Schema overview

```toml
schema_version = 1

[server]
listen = "0.0.0.0:8080"
listen_tls = "0.0.0.0:8443"
http_redirect_listen = "0.0.0.0:8081"  # optional :80 in prod
user = "sedat"       # Linux privilege drop target (optional)
group = "sedat"
state_dir = "./state"
admin_socket = "./state/admin.sock"  # Unix only
# admin_group = "sedat-admin"        # optional → socket 0660 + group
# admin_token = ""                   # empty = FS ACL only; prefer env/file in prod
# admin_token_file = "./state/admin.token"
# metrics_listen = "127.0.0.1:9090"  # optional loopback Prometheus sidecar

[tls]
enabled = false
# cert_path / key_path for static certs; ACME overrides when enabled

[acme]
enabled = false
directory = "staging"   # or "production" | "pebble" | URL
email = "admin@example.com"
domains = ["example.com"]
dns_provider = "file"   # file | cloudflare
dns_file = "./state/acme-dns-challenge.txt"
ari = true                 # prefer RFC 9773 renewalInfo when CA supports it
renew_days_before = 30     # fallback lead time if ARI unavailable (1..=90)

[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"   # recommended default (plaintext)
# upstream = "https://backend.internal:9443"  # optional TLS to upstream
# upstream_allowlist = ["127.0.0.1", "10.0.0.0/8"]  # empty = no pin
# upstream_mtls_cert = "./certs/client.crt"   # optional mTLS (both cert+key)
# upstream_mtls_key  = "./certs/client.key"
# upstream_mtls_ca   = "./certs/upstream-ca.crt"  # empty = webpki roots

[proxy_protocol]
outbound = "v2"          # off | v1 | v2
inbound_enabled = false
inbound_allowlist = []   # CIDRs, only if inbound_enabled
inbound_placement = "before_tls"  # before_tls | after_tls (PP2 over TLS)

[limits]
max_connections = 1024
max_header_bytes = 16384
max_headers = 100
max_body_bytes = 1048576
request_timeout_secs = 30
idle_timeout_secs = 60
rate_limit_per_ip = 100
rate_limit_burst = 20
ban_after_rate_limit_strikes = 20   # 0 = disable temporary bans
ban_duration_secs = 60

[embedded_docs]
enabled = true
sedat_path = "/sedat"
seda_path = "/seda"

[experimental]
h3 = false

[hardening]
landlock = "auto"   # auto | off | required
seccomp = "auto"    # auto | off | required

[logging]
level = "info"
request_id = true                 # generate/propagate correlation id (default)
request_id_header = "x-request-id"  # HTTP header after PROXY framing
audit_jsonl = ""                  # empty = disabled; e.g. "./state/audit.jsonl"
audit_jsonl_max_bytes = 10485760  # rotate to *.jsonl.1; 0 = never
```

## Validation

All client-visible string fields (hosts, paths, header names, upstream URLs) are validated with **regex** and semantic checks. Failures are fail-closed.

Additional P09 / P10 rules:

- `metrics_listen` must be loopback (`127.0.0.1` / `::1` / `localhost`) when set.
- `inbound_placement` must be `before_tls` or `after_tls`.
- `hardening.landlock` / `seccomp` must be `auto` | `off` | `required`.
- Inbound PROXY still requires a non-empty allowlist when enabled.
- `logging.request_id_header` must be a valid HTTP token (alphanumeric / `-`).
- `logging.audit_jsonl` must be empty or a local file path (no URL schemes).
- `ban_duration_secs` must be `> 0` when `ban_after_rate_limit_strikes > 0`.
- `server.admin_token` max 512 bytes; `admin_token_file` must be empty or a local path.
- Admin token precedence: `SEDAT_ADMIN_TOKEN` → `admin_token_file` → `admin_token`.
- `upstream_allowlist` entries must be valid IPs/CIDRs when set.
- `upstream` may be `http://` or `https://`. `upstream_mtls_*` requires `https://`;
  cert+key must both be set or both empty; PEM paths must exist when set.
- When `acme.enabled`, `acme.renew_days_before` must be `1..=90`.

## Schema version & migration (fail-closed)

- Current version: **`schema_version = 1`** (`CURRENT_SCHEMA_VERSION` in `src/config/mod.rs`).
- Load path requires an **exact** match; newer/unknown versions refuse to start.
- Helper: `config::migrate_toml` / CLI `sedat --migrate-config` applies the documented path when one exists (today: identity for v1; unknown versions error).
- Upgrade procedure: read [THREAT_MODEL.md](THREAT_MODEL.md) notes → run migrate → `--validate` → reload via admin socket or restart. Never skip `schema_version`.

## CLI

```text
sedat [--config PATH] [--listen ADDR] [--resetconfig] [--validate] [--migrate-config] [--version]
```

- `--validate`: load+validate and exit (non-zero on error).
- `--resetconfig`: write default config and activate.
- `--migrate-config`: rewrite user config through the fail-closed migrator, then exit.
- `--listen`: override `server.listen` for quick demos.

## Hot reload

SIGHUP (Unix) or admin `reload` command re-reads the user config. On failure, active config is unchanged and the error is logged/returned. On success, `security_diff` changes are logged under `sedat::audit` and summarized in the admin reply.

## Examples

See `examples/config/good.toml` and `examples/config/bad_line_12.toml`.
