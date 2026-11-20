# P10.4 – E4 Admin-Tokens

## Summary

Optional **capability token** for the admin Unix socket. When a token is
configured, clients must send `AUTH <token>` before other commands (except
`help` / `quit`). Comparison is constant-time (SHA-256 digests). Failed auth
is logged and written to JSONL (`admin_auth_fail`) when the audit sink is
enabled. The presented secret is **never** logged.

## Secure defaults

| Situation | Behavior |
|-----------|----------|
| `admin_token` / file / env all empty | Token auth **off** — rely on FS ACL (`0600` / `0660`). Documented as **dev-friendly**; production should set a token. |
| Token configured | Fail-closed: commands rejected until successful `AUTH` |

## Config / env precedence

1. `SEDAT_ADMIN_TOKEN` (non-empty env)
2. `server.admin_token_file` (file contents, trimmed)
3. `server.admin_token` (inline TOML — avoid in production)

```toml
[server]
admin_socket = "./state/admin.sock"
# admin_token = ""                    # empty = FS ACL only
# admin_token_file = "./state/admin.token"
```

## Protocol

```text
AUTH my-secret
OK auth
status
OK sedat ...
```

Wrong / missing token → `ERR auth failed` / `ERR auth required`.

## Out of scope (this step)

- Admin `unban` / ban-list commands (idea from P10.3) — deferred
- Metrics HTTP sidecar does **not** use the admin token (loopback + FS still apply)

## Tests

- `src/admin/auth.rs` unit tests
- `src/admin` `token_required_rejects_until_auth`, `no_token_allows_commands`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test admin
```
