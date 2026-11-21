# SeDat – Roadmap P13 (post-P12)

Follow-ups after **P12 complete** (v0.1.22). Source: [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P13.1 E8 HTTP/3 attack corpus   ← done (v0.1.23)
P13.2 Multiple DNS providers    ← Cloudflare API + webhook (v0.1.24)
→ continued in [ROADMAP_P14.md](ROADMAP_P14.md); fuller H3 proxy waits on h3-quinn
```

## Step breakdown

### P13.1 – E8 HTTP/3 attack corpus

| | |
|--|--|
| **Status** | **done** (v0.1.23) |
| **Behavior** | Programmatic QUIC connection/stream/UDP junk probes with strict caps; no multi-GB archive |
| **Phase note** | [phases/P13_01_e8_h3_corpus.md](phases/P13_01_e8_h3_corpus.md) |

### P13.2 – Multiple DNS providers

| | |
|--|--|
| **Status** | **done** (v0.1.24) |
| **Behavior** | Live Cloudflare DNS-01 + generic HTTP webhook; `file` remains default |
| **Phase note** | [phases/P13_02_dns_providers.md](phases/P13_02_dns_providers.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | E8 H3 attack corpus | **done** (v0.1.23) |
| 2 | Multiple DNS providers | **done** (v0.1.24) |
