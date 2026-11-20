# P10.9 – E7 Seccomp-BPF profiles

## Summary

SeDat installs a **built-in seccomp-BPF allowlist** after privilege drop (Linux,
little-endian). This goes beyond `NO_NEW_PRIVS`: denied syscalls (e.g. `execve`,
`ptrace`, `mount`, `reboot`) return **EPERM**. Modes stay consistent with
`[hardening]`: `auto` | `off` | `required`.

## Config

```toml
[hardening]
landlock = "auto"    # unchanged
seccomp = "auto"     # auto | off | required
```

| Mode | Behaviour |
|------|-----------|
| `off` | No seccomp / NO_NEW_PRIVS from SeDat |
| `auto` | Install BPF allowlist; on failure fall back to `NO_NEW_PRIVS` only |
| `required` | Fail closed if BPF cannot be installed |

Non-Linux / big-endian: `auto` skips (or NO_NEW_PRIVS-only); `required` errors.

## Profile

- Runtime: `src/hardening/seccomp.rs` (`sedat-default-v1`), applied with
  `SECCOMP_FILTER_FLAG_TSYNC` (all Tokio threads).
- Ops mirror (Docker `--security-opt seccomp=...`): [`deploy/seccomp/sedat.json`](../../deploy/seccomp/sedat.json).

Allowlist covers network, epoll, futex/clone, file I/O for `state_dir`/certs.
Landlock still scopes filesystem paths when enabled.

## Tests

- Unit: compile filter; allowlist excludes `execve`/`mount`; forked child sees
  `mount` → `EPERM`.
- Verify under Linux Docker (see below).

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test hardening::
```
