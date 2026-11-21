# P13.2 – Multiple ACME DNS-01 providers

## Summary

Extend the existing `DnsProvider` trait with a working **Cloudflare** API
implementation and a generic **webhook** provider. Default remains
`dns_provider = "file"` (staging / Pebble safe).

| Provider | Config | Secrets |
|----------|--------|---------|
| `file` | `acme.dns_file` | none |
| `cloudflare` | optional `acme.cloudflare_zone_id` | `SEDAT_CLOUDFLARE_API_TOKEN` or `acme.cloudflare_api_token` |
| `webhook` | `acme.dns_webhook_url` (required) | optional `SEDAT_DNS_WEBHOOK_BEARER` / `acme.dns_webhook_bearer` |

## Design

- Shared `DnsHttpTransport` for API calls; Hyper in production, mocks in unit tests.
- Cloudflare: walk domain labels to resolve zone → replace TXT at
  `_acme-challenge.<domain>` → cleanup deletes matching TXT ids.
- Webhook: `POST` JSON `{action, domain, fqdn, token?}`; expect 2xx.
- Validation fail-closed: cloudflare needs a token; webhook needs a URL.
- ACME directory default stays **`staging`**.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib acme::dns -- --nocapture"
```
