# P12.3 – Token rotation without full reload

## Summary

Hot-swap the admin / metrics capability token **without** a full process
restart or a full config reload. Admin command `reload-token` re-reads
`SEDAT_ADMIN_TOKEN` → `admin_token_file` → `admin_token` into a live gate
shared by the Unix socket `AUTH` and the loopback metrics Bearer check.

## Secure defaults (fail-closed)

| Situation | Behavior |
|-----------|----------|
| Token currently required, new sources empty/unreadable | **Reject** reload; previous token kept |
| Token rotated to a new value | New token active immediately; previous accepted for overlap window |
| Overlap `0` | Hard cut — only the new token |
| Never had a token | Still off (FS ACL only) until sources provide one |

## Config

```toml
[server]
admin_token_file = "./state/admin.token"
admin_token_overlap_secs = 300   # default; dual-token window after rotate
```

## Ops flow

```bash
# 1) Write new secret (atomic replace recommended)
printf 'new-secret\n' > /run/sedat/admin.token.new
mv /run/sedat/admin.token.new /run/sedat/admin.token

# 2) Hot-reload token only (auth with current/previous token first)
printf 'AUTH %s\nreload-token\n' "$OLD_OR_NEW" | socat - UNIX-CONNECT:/run/sedat/admin.sock
# → OK reload-token rotated overlap_secs=300

# 3) Update scrapers / clients to the new Bearer / AUTH secret during the window
```

Aliases: `token-reload`, `reload_token`, `token_reload`.

Full config `reload` also refreshes the live token gate (same fail-closed /
overlap rules) and may append `token=rotated …` or `token=kept_fail_closed`
to the reply.

## Audit

JSONL `admin_token_reload` with `outcome`:
`rotated` | `unchanged` | `unchanged_empty` | `enabled` | `rejected_would_disable`
(and `overlap_secs` when rotated). Secrets are never logged.

## Tests

- `src/admin/auth` `live_tokens_rotate_with_overlap_and_fail_closed`,
  `live_tokens_hard_cut_when_overlap_zero`
- `src/admin` `reload_token_rotates_with_overlap`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib live_tokens && cargo test --lib reload_token"
```
