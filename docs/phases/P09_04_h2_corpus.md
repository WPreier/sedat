# P09.4 – HTTP/2 Continuations / HPACK-bomb corpus

See [ROADMAP_P09.md](../ROADMAP_P09.md).

**Code:** `tests/h2_attack_corpus.rs`.
**Exit:** Oversized CONTINUATION / header floods rejected or connection closed without harness panic.
