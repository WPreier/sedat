//! Serde schema for SeDat TOML configuration.

use serde::{Deserialize, Serialize};

/// Root configuration document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SedatConfig {
    /// Schema version (must match [`super::CURRENT_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Server / process settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Static TLS files (when ACME disabled).
    #[serde(default)]
    pub tls: TlsConfig,
    /// ACME DNS-01 settings.
    #[serde(default)]
    pub acme: AcmeConfig,
    /// Virtual host routes.
    #[serde(default)]
    pub routes: RoutesConfig,
    /// PROXY protocol policy.
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolConfig,
    /// Edge limits.
    #[serde(default)]
    pub limits: LimitsConfig,
    /// Embedded documentation routes.
    #[serde(default)]
    pub embedded_docs: EmbeddedDocsConfig,
    /// Experimental flags.
    #[serde(default)]
    pub experimental: ExperimentalConfig,
    /// Logging.
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Linux sandbox (Landlock / seccomp) after privilege drop.
    #[serde(default)]
    pub hardening: HardeningConfig,
}

/// `[server]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Plain HTTP listen address.
    #[serde(default = "default_listen")]
    pub listen: String,
    /// HTTPS listen address.
    #[serde(default = "default_listen_tls")]
    pub listen_tls: String,
    /// Optional HTTP→HTTPS redirect listener.
    #[serde(default = "default_redirect")]
    pub http_redirect_listen: String,
    /// Unprivileged user after bind (Linux).
    #[serde(default)]
    pub user: Option<String>,
    /// Unprivileged group after bind (Linux).
    #[serde(default)]
    pub group: Option<String>,
    /// State directory (active config, ACME account, certs).
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    /// Admin Unix socket path.
    #[serde(default = "default_admin_socket")]
    pub admin_socket: String,
    /// Optional Unix group for admin socket ACL (`0660` when set; otherwise `0600`).
    #[serde(default)]
    pub admin_group: Option<String>,
    /// Optional admin capability token (empty = **no** token required; FS ACL only).
    ///
    /// When non-empty (or provided via `admin_token_file` / `SEDAT_ADMIN_TOKEN`),
    /// clients must send `AUTH <token>` before other admin commands.
    /// Prefer env/file over committing secrets into TOML.
    #[serde(default)]
    pub admin_token: String,
    /// Optional path to a file containing the admin token (trimmed). Overrides
    /// `admin_token` when the file is non-empty. Env `SEDAT_ADMIN_TOKEN` wins over both.
    #[serde(default)]
    pub admin_token_file: String,
    /// After admin `reload-token` (or config reload that changes the token), keep
    /// accepting the **previous** token for this many seconds (dual-token overlap).
    /// Default **300**. `0` = hard cut (only the new token).
    #[serde(default = "default_admin_token_overlap")]
    pub admin_token_overlap_secs: u64,
    /// Optional loopback-only Prometheus HTTP scrape address (e.g. `127.0.0.1:9090`).
    /// Empty / unset disables the sidecar. Non-loopback addresses fail validation.
    #[serde(default)]
    pub metrics_listen: Option<String>,
}

fn default_admin_token_overlap() -> u64 {
    300
}

fn default_listen() -> String {
    "127.0.0.1:8080".into()
}
fn default_listen_tls() -> String {
    "127.0.0.1:8443".into()
}
fn default_redirect() -> String {
    "127.0.0.1:8081".into()
}
fn default_state_dir() -> String {
    "./state".into()
}
fn default_admin_socket() -> String {
    "./state/admin.sock".into()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            listen_tls: default_listen_tls(),
            http_redirect_listen: default_redirect(),
            user: None,
            group: None,
            state_dir: default_state_dir(),
            admin_socket: default_admin_socket(),
            admin_group: None,
            admin_token: String::new(),
            admin_token_file: String::new(),
            admin_token_overlap_secs: default_admin_token_overlap(),
            metrics_listen: None,
        }
    }
}

/// `[tls]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS listener.
    #[serde(default)]
    pub enabled: bool,
    /// PEM certificate path (static mode).
    #[serde(default)]
    pub cert_path: Option<String>,
    /// PEM private key path (static mode).
    #[serde(default)]
    pub key_path: Option<String>,
}

/// `[acme]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable ACME.
    #[serde(default)]
    pub enabled: bool,
    /// `staging`, `production`, or directory URL.
    #[serde(default = "default_acme_dir")]
    pub directory: String,
    /// Account contact email.
    #[serde(default)]
    pub email: String,
    /// Domains to request.
    #[serde(default)]
    pub domains: Vec<String>,
    /// DNS provider id: `file` or `cloudflare`.
    #[serde(default = "default_dns_provider")]
    pub dns_provider: String,
    /// File path for file-based DNS challenge material.
    #[serde(default = "default_dns_file")]
    pub dns_file: String,
    /// Cloudflare API token (env preferred in production).
    #[serde(default)]
    pub cloudflare_api_token: Option<String>,
    /// Prefer ACME ARI (RFC 9773) when the CA directory exposes `renewalInfo`.
    ///
    /// Default **true** (safe): if ARI is unavailable, fall back to
    /// `renew_days_before` against certificate `notAfter`.
    #[serde(default = "default_acme_ari")]
    pub ari: bool,
    /// Days before cert `notAfter` to renew when ARI is off or unsupported (default 30).
    #[serde(default = "default_renew_days_before")]
    pub renew_days_before: u64,
}

fn default_acme_dir() -> String {
    "staging".into()
}
fn default_dns_provider() -> String {
    "file".into()
}
fn default_dns_file() -> String {
    "./state/acme-dns-challenge.txt".into()
}
fn default_acme_ari() -> bool {
    true
}
fn default_renew_days_before() -> u64 {
    30
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: default_acme_dir(),
            email: String::new(),
            domains: Vec::new(),
            dns_provider: default_dns_provider(),
            dns_file: default_dns_file(),
            cloudflare_api_token: None,
            ari: default_acme_ari(),
            renew_days_before: default_renew_days_before(),
        }
    }
}

/// `[routes]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutesConfig {
    /// Virtual hosts.
    #[serde(default)]
    pub hosts: Vec<HostRoute>,
}

/// One virtual host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRoute {
    /// Host header / SNI name (exact match).
    pub host: String,
    /// Path prefix routes (longest prefix wins).
    #[serde(default)]
    pub paths: Vec<PathRoute>,
}

/// Path prefix → upstream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRoute {
    /// Path prefix beginning with `/`.
    pub prefix: String,
    /// Upstream base URL (`http://host:port` or `https://host:port`).
    ///
    /// Default / recommended for Seda: plaintext `http://` on a private net.
    /// `https://` enables TLS to the upstream; pair with mTLS paths below when needed.
    pub upstream: String,
    /// Optional IP/CIDR allowlist for the resolved upstream peer (empty = no pin).
    ///
    /// When non-empty, DNS results / connected peer must match (fail-closed).
    /// Mitigates DNS rebinding and unexpected upstream IPs after config reload.
    #[serde(default)]
    pub upstream_allowlist: Vec<String>,
    /// Optional client certificate PEM for upstream mTLS (empty = off).
    /// Requires `upstream_mtls_key` and an `https://` upstream.
    #[serde(default)]
    pub upstream_mtls_cert: String,
    /// Optional client private key PEM for upstream mTLS.
    #[serde(default)]
    pub upstream_mtls_key: String,
    /// Optional CA PEM to verify the upstream server certificate.
    /// Empty with `https://` → public webpki roots (not for private CAs).
    #[serde(default)]
    pub upstream_mtls_ca: String,
}

impl Default for PathRoute {
    fn default() -> Self {
        Self {
            prefix: "/".into(),
            upstream: "http://127.0.0.1:1".into(),
            upstream_allowlist: vec![],
            upstream_mtls_cert: String::new(),
            upstream_mtls_key: String::new(),
            upstream_mtls_ca: String::new(),
        }
    }
}

/// `[proxy_protocol]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyProtocolConfig {
    /// Outbound mode: `off`, `v1`, `v2`.
    #[serde(default = "default_outbound_pp")]
    pub outbound: String,
    /// Accept inbound PROXY from clients.
    #[serde(default)]
    pub inbound_enabled: bool,
    /// CIDR allowlist when inbound enabled.
    #[serde(default)]
    pub inbound_allowlist: Vec<String>,
    /// Where to parse inbound PROXY: `before_tls` (default) or `after_tls` (PP2 over TLS).
    #[serde(default = "default_inbound_placement")]
    pub inbound_placement: String,
}

fn default_outbound_pp() -> String {
    "v2".into()
}

fn default_inbound_placement() -> String {
    "before_tls".into()
}

impl Default for ProxyProtocolConfig {
    fn default() -> Self {
        Self {
            outbound: default_outbound_pp(),
            inbound_enabled: false,
            inbound_allowlist: Vec::new(),
            inbound_placement: default_inbound_placement(),
        }
    }
}

/// `[hardening]` table — Linux sandbox after privilege drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningConfig {
    /// Landlock FS restriction: `auto` (default), `off`, `required`.
    #[serde(default = "default_sandbox_mode")]
    pub landlock: String,
    /// Seccomp-BPF allowlist (+ NO_NEW_PRIVS): `auto` (default), `off`, `required`.
    ///
    /// - `auto`: install built-in BPF profile; on failure fall back to NO_NEW_PRIVS.
    /// - `required`: fail closed if BPF cannot be installed (Linux little-endian).
    /// - `off`: no seccomp / NO_NEW_PRIVS from SeDat.
    #[serde(default = "default_sandbox_mode")]
    pub seccomp: String,
}

fn default_sandbox_mode() -> String {
    "auto".into()
}

impl Default for HardeningConfig {
    fn default() -> Self {
        Self {
            landlock: default_sandbox_mode(),
            seccomp: default_sandbox_mode(),
        }
    }
}

/// `[limits]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Max concurrent connections.
    #[serde(default = "default_max_conn")]
    pub max_connections: usize,
    /// Max total header bytes.
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Max header count.
    #[serde(default = "default_max_headers")]
    pub max_headers: usize,
    /// Max request body bytes.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    /// Overall request timeout.
    #[serde(default = "default_req_timeout")]
    pub request_timeout_secs: u64,
    /// Idle timeout.
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u64,
    /// Sustained rate per IP (requests/sec approx via token refill).
    #[serde(default = "default_rate")]
    pub rate_limit_per_ip: u32,
    /// Burst tokens per IP.
    #[serde(default = "default_burst")]
    pub rate_limit_burst: u32,
    /// After this many **consecutive** rate-limit denials, temporarily ban the IP.
    /// `0` disables temporary bans (default **20**).
    #[serde(default = "default_ban_strikes")]
    pub ban_after_rate_limit_strikes: u32,
    /// Ban TTL in seconds once triggered (fail-closed until expiry). Default **60**.
    /// Ignored when `ban_after_rate_limit_strikes = 0`.
    #[serde(default = "default_ban_duration")]
    pub ban_duration_secs: u64,
    /// When true (default), each request while banned refreshes TTL to
    /// `now + ban_duration_secs` (sliding window; does not grow beyond that).
    #[serde(default = "default_true")]
    pub ban_extend_while_banned: bool,
    /// Minimum seconds between `ip_ban_extend` audit events per IP (TTL still
    /// refreshes every hit when extend is on). Default **1**; `0` = audit every extend.
    #[serde(default = "default_ban_extend_min_interval")]
    pub ban_extend_min_interval_secs: u64,
    /// Separate max concurrent HTTP/3 connections (when enabled).
    #[serde(default = "default_h3_conn")]
    pub max_h3_connections: usize,
    /// Max concurrent h3 streams per connection.
    #[serde(default = "default_h3_streams")]
    pub max_h3_streams: usize,
}

fn default_max_conn() -> usize {
    1024
}
fn default_max_header_bytes() -> usize {
    16_384
}
fn default_max_headers() -> usize {
    100
}
fn default_max_body() -> usize {
    1_048_576
}
fn default_req_timeout() -> u64 {
    30
}
fn default_idle() -> u64 {
    60
}
fn default_rate() -> u32 {
    100
}
fn default_burst() -> u32 {
    20
}
fn default_ban_strikes() -> u32 {
    20
}
fn default_ban_duration() -> u64 {
    60
}
fn default_ban_extend_min_interval() -> u64 {
    1
}
fn default_h3_conn() -> usize {
    512
}
fn default_h3_streams() -> usize {
    100
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_conn(),
            max_header_bytes: default_max_header_bytes(),
            max_headers: default_max_headers(),
            max_body_bytes: default_max_body(),
            request_timeout_secs: default_req_timeout(),
            idle_timeout_secs: default_idle(),
            rate_limit_per_ip: default_rate(),
            rate_limit_burst: default_burst(),
            ban_after_rate_limit_strikes: default_ban_strikes(),
            ban_duration_secs: default_ban_duration(),
            ban_extend_while_banned: true,
            ban_extend_min_interval_secs: default_ban_extend_min_interval(),
            max_h3_connections: default_h3_conn(),
            max_h3_streams: default_h3_streams(),
        }
    }
}

/// `[embedded_docs]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedDocsConfig {
    /// Serve embedded docs.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path for SeDat docs.
    #[serde(default = "default_sedat_path")]
    pub sedat_path: String,
    /// Path for Seda docs.
    #[serde(default = "default_seda_path")]
    pub seda_path: String,
}

fn default_true() -> bool {
    true
}
fn default_sedat_path() -> String {
    "/sedat".into()
}
fn default_seda_path() -> String {
    "/seda".into()
}

impl Default for EmbeddedDocsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sedat_path: default_sedat_path(),
            seda_path: default_seda_path(),
        }
    }
}

/// `[experimental]` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExperimentalConfig {
    /// Enable HTTP/3 listener (requires `http3` feature).
    #[serde(default)]
    pub h3: bool,
}

/// `[logging]` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// tracing filter level (`error`, `warn`, `info`, `debug`, `trace`).
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Generate / propagate a correlation id per request (default **true**).
    ///
    /// When enabled, SeDat sets `request_id_header` on the upstream HTTP request
    /// **after** any outbound PROXY framing, echoes it on the client response, and
    /// includes it in request logs.
    #[serde(default = "default_true")]
    pub request_id: bool,
    /// HTTP header name for the correlation id (default `x-request-id`).
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
    /// Append-only JSONL audit file path. Empty / unset = **disabled** (default).
    ///
    /// Prefer a path under `server.state_dir` (e.g. `./state/audit.jsonl`).
    #[serde(default)]
    pub audit_jsonl: String,
    /// Rotate the audit file when size reaches this many bytes (`0` = never).
    /// Rotated file is renamed to `*.jsonl.1`.
    #[serde(default = "default_audit_max_bytes")]
    pub audit_jsonl_max_bytes: u64,
}

fn default_log_level() -> String {
    "info".into()
}

fn default_request_id_header() -> String {
    "x-request-id".into()
}

fn default_audit_max_bytes() -> u64 {
    10_485_760
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            request_id: true,
            request_id_header: default_request_id_header(),
            audit_jsonl: String::new(),
            audit_jsonl_max_bytes: default_audit_max_bytes(),
        }
    }
}
