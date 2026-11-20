# P09.1 – Landlock / seccomp after privilege drop

See [ROADMAP_P09.md](../ROADMAP_P09.md).

**Code:** `src/hardening/mod.rs` (`apply_sandbox`), config `[hardening]`.
**Exit:** `auto` skips gracefully; `required` fails closed; docs note Linux-only.

**Follow-up (P10.9):** real seccomp-BPF allowlist beyond NO_NEW_PRIVS —
see [P10_09_seccomp_bpf.md](P10_09_seccomp_bpf.md).
