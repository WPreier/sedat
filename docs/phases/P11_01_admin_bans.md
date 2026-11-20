# P11.1 – Admin `bans` / `unban <ip>`

## Summary

Operators can list and clear **temporary IP bans** via the admin Unix socket
(same AUTH gate as other commands when a token is configured). Manual clears
emit JSONL `admin_unban` (distinct from TTL-driven `ip_unban`).

## Commands

| Command | Reply |
|---------|--------|
| `bans` | `OK bans n=N` plus one line per active ban: `<ip> remaining_secs=T` |
| `unban <ip>` | `OK unban <ip>` or `ERR unban: …` (usage / invalid / not banned) |
| `help` | Lists `bans` and `unban <ip>` |

Aliases: `ban-list` / `ban_list` → same as `bans`.

## Auth

When `SEDAT_ADMIN_TOKEN` / `admin_token_file` / `admin_token` is set, send
`AUTH <token>` first (unchanged P10.4 behavior). `bans` / `unban` require auth.

## Audit

| Event | When |
|-------|------|
| `admin_unban` | Successful admin `unban` (`peer`, `source=admin`) |

TTL expiry still uses `ip_unban` from the proxy path (P10.3).

## Tests

- Unit: `src/limits` `list_and_unban`
- Unit: `src/admin` `bans_and_unban_commands`, `help_lists_bans_unban`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test --lib limits::tests::list_and_unban
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test --lib admin::tests::bans_and_unban
```
