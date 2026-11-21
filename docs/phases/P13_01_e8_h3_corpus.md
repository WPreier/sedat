# P13.1 – E8 HTTP/3 (QUIC) attack corpus

## Summary

Programmatic negative corpus mirroring [P09.4](P09_04_h2_corpus.md) for the
experimental QUIC listener — **not** a large on-disk archive.

| Cap | Value |
|-----|-------|
| Flood connections / test | 24 |
| Server `max_h3_connections` | 4 |
| UDP junk packets × size | 64 × 1200 B (~75 KiB) |
| Per-test wall clock | ≤ 8 s |

Success = accept/reject/close without harness **panic** or OOM.

## Feature / deps

`http3` feature is **Quinn-only**. hyperium `h3-quinn` 0.0.7 does not build
against quinn 0.11 (`StreamId` field private). The experimental listener already
used Quinn alone; broken optional crates were removed so

```bash
cargo test --features http3 --test h3_attack_corpus
```

works in Docker. Without the feature, the binary exposes a single skip test.

## Probes

| Test | Intent |
|------|--------|
| `connection_flood_stays_within_caps` | Many handshakes vs low `max_h3_connections` |
| `udp_junk_amplification_probe_no_panic` | Garbage UDP into the QUIC port |
| `stream_open_storm_on_accepted_conn` | Burst `open_bi` after handshake |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --features http3 --test h3_attack_corpus -- --nocapture"
```

Default `cargo test` (no feature) still green; skip test documents the gate.
