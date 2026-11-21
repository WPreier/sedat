# SeDat – Roadmap P13 (post-P12)

Follow-ups after **P12 complete** (v0.1.22). Source: [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P13.1 E8 HTTP/3 attack corpus   ← programmatic QUIC/H3 flood (small disk)
P13.2 Multiple DNS providers    ← trait ready; Cloudflare first
… later: fuller H3 request proxy when h3-quinn tracks quinn …
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
| **Status** | pending |
| **Behavior** | Additional ACME DNS providers beyond Cloudflare / file |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | E8 H3 attack corpus | **done** (v0.1.23) |
| 2 | Multiple DNS providers | pending |
