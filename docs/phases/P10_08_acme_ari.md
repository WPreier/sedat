# P10.8 – E2 ACME ARI (Renewal Information)

## Summary

Prefer the CA’s **ACME Renewal Information** window ([RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html))
when scheduling renewals. If the directory has no `renewalInfo`, the fetch fails,
or `acme.ari = false`, SeDat falls back to **`notAfter − renew_days_before`**
(default 30 days). Safe defaults: ARI on, no blind daily re-issue.

## Config

```toml
[acme]
enabled = true
directory = "staging"
# Prefer ARI when the CA exposes renewalInfo (default true).
ari = true
# Fallback lead time when ARI is unavailable (1..=90, default 30).
renew_days_before = 30
```

| Setting | Default | Meaning |
|---------|---------|---------|
| `ari` | `true` | Query directory `renewalInfo` + GET window |
| `renew_days_before` | `30` | Expiry-based fallback |

## Behavior

1. Ensure cert/key on disk (issue if missing).
2. If `ari`: GET ACME directory → optional `renewalInfo` URL → GET
   `{renewalInfo}/{aki}.{serial}` (plain HTTP, no JWS).
3. Pick a uniform random time inside `suggestedWindow` (or renew immediately if
   the window is overdue).
4. Else: renew at `notAfter − renew_days_before`.
5. Sleep until due (wake at least every 24h to re-evaluate / re-fetch ARI).
6. Order failure → exponential backoff; **previous cert retained** (fail-closed).

Implemented in-tree (`src/acme/ari.rs` + `ari_fetch.rs`) against **instant-acme 0.7**
issuance. A future upgrade to instant-acme ≥0.8 can switch to its built-in
`Account::renewal_info` without changing the schedule policy.

## Tests

- Unit: `src/acme/ari.rs` (parse, schedule, cert id)
- Integration: `tests/acme_ari.rs` (mock directory + renewalInfo)

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test ari
```
