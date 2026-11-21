# P12.6 – Shared ban state across replicas

## Design choice

**File-backed JSON map** on a shared filesystem path (Docker volume / NFS),
authenticated with **HMAC-SHA256**.

| Alternative | Why not for this MVP |
|-------------|----------------------|
| Redis / etcd | Extra service; heavier ops than SeDat’s single-binary model |
| UDP / Unix datagram gossip | Harder to test securely; NAT/firewall noise; still need auth |

Shared volume + HMAC is ops-friendly, fail-closed, and easy to test with a
bind-mount between containers.

## Config (disabled by default)

```toml
[limits]
ban_share_path = "./state/shared_bans.json"   # empty = off
# Prefer env in production:
# SEDAT_BAN_SHARE_SECRET=...
# ban_share_secret_file = "./state/ban_share.secret"
ban_share_secret = ""                         # inline (dev only)
ban_share_poll_secs = 2                       # pull interval; 0 → 1
```

**Fail-closed:** non-empty `ban_share_path` **requires** a secret
(`SEDAT_BAN_SHARE_SECRET` → `ban_share_secret_file` → `ban_share_secret`).
Bad / missing HMAC on read → pull error; local bans unchanged; file not
clobbered on failed auth.

## Conflict policy

| Event | Merge |
|-------|--------|
| Ban / extend | **max `until_ms` wins** |
| Unban | Tombstone (`until_ms = 0`); replicas clear on pull |

## Trust boundary

- Secret shared among replicas only (filesystem ACL on secret file + volume).
- Not a network protocol — do not expose the JSON path to untrusted hosts.

## Runtime

- Local `Applied` / `Extended` / admin `unban` publish immediately.
- Pulls run on the poll interval (also from `check_rate` when due).

## Tests

- `src/limits/ban_share` unit (max expiry, unban, bad MAC, path-without-secret)
- `src/limits` `shared_ban_propagates_between_limiters`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib ban_share && cargo test --lib shared_ban"
```
