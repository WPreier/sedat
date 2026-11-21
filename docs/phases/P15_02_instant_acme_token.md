# P15.2 – instant-acme 0.8 (optional Challenge.token)

## Summary

P15.1 pinned Pebble to `2.7.0` because `:latest` returns authorization
challenges (e.g. `dns-persist-01`) **without** a `token` field.
`instant-acme` **0.7** required `token: String`, so deserialization failed with
`missing field token`.

**Fix:** Upgrade to **`instant-acme` 0.8** where `token` is `#[serde(default)]`.
Adapt call sites to the 0.8 builder / authorization-handle API. Unpin Compose
Pebble back to `:latest`.

| Change | Detail |
|--------|--------|
| `Cargo.toml` | `instant-acme` 0.8 (`hyper-rustls` + `ring`) |
| `src/acme/renew.rs` | `Account::builder*`, `NewOrder::new`, authz stream, `finalize_csr` |
| `src/acme/http_client.rs` | Hyper client with `BodyWrapper` for 0.8 `HttpClient` |
| `docker-compose.dev.yml` | `pebble:latest` again |

## Verify

```bash
docker compose -f docker-compose.dev.yml --profile acme up -d pebble
PEBBLE_DIRECTORY=https://localhost:14000/dir \
  SEDAT_PEBBLE_ISSUE_STATE=/tmp/sedat-pebble \
  cargo test --test pebble_issue -- --ignored --nocapture
```
