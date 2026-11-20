# P09.1 – Landlock / seccomp after privilege drop

See [ROADMAP_P09.md](../ROADMAP_P09.md).

**Code:** `src/hardening/mod.rs` (`apply_sandbox`), config `[hardening]`.
**Exit:** `auto` skips gracefully; `required` fails closed; docs note Linux-only.
