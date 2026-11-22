# P17.5 – Selftest Landlock/seccomp mode

## Summary

Threat model T10 relies on Landlock + seccomp after drop. Operators had no
selftest signal for the configured modes beyond reading TOML.

**Fix:** Selftest checks `hardening_landlock` and `hardening_seccomp`:

| Result | When |
|--------|------|
| PASS `mode=auto\|off\|required` | Valid enum (informational) |
| FAIL `invalid mode=…` | Anything else |

Does not probe kernel enforcement — only config clarity.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- selftest_fails_invalid_sandbox selftest_passes_defaults --nocapture"
```
