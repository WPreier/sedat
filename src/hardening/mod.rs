//! Privilege drop and process hardening (Linux-primary).

#[cfg(all(target_os = "linux", target_endian = "little"))]
mod seccomp;

use std::path::Path;

use tracing::info;
#[cfg(not(unix))]
use tracing::warn;

use crate::config::{HardeningConfig, ServerConfig};

/// Result of privilege-drop attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropResult {
    /// Dropped to the requested identity.
    Dropped {
        /// Target user.
        user: String,
    },
    /// Skipped (no user configured).
    Skipped,
    /// Not supported on this platform.
    Unsupported,
}

/// Result of post-drop sandbox application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxResult {
    /// Landlock and/or seccomp applied.
    Applied {
        /// Landlock outcome message.
        landlock: String,
        /// Seccomp / NO_NEW_PRIVS outcome message.
        seccomp: String,
    },
    /// Sandbox disabled in config.
    Disabled,
    /// Unsupported platform / kernel; skipped because mode is `auto`.
    Skipped {
        /// Reason.
        reason: String,
    },
}

/// Drop privileges to `server.user` / `server.group` after sockets are bound.
///
/// On non-Unix platforms this is a no-op returning [`DropResult::Unsupported`].
pub fn drop_privileges(server: &ServerConfig) -> std::io::Result<DropResult> {
    let Some(ref user) = server.user else {
        return Ok(DropResult::Skipped);
    };

    #[cfg(unix)]
    {
        use nix::unistd::{setgid, setuid, Gid, Group, Uid, User};

        let u = User::from_name(user)
            .map_err(std::io::Error::other)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("user `{user}` not found"),
                )
            })?;

        let gid = if let Some(ref gname) = server.group {
            Group::from_name(gname)
                .map_err(std::io::Error::other)?
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("group `{gname}` not found"),
                    )
                })?
                .gid
        } else {
            u.gid
        };

        setgid(Gid::from_raw(gid.as_raw()))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        setuid(Uid::from_raw(u.uid.as_raw()))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        info!(user, "privileges dropped");
        Ok(DropResult::Dropped { user: user.clone() })
    }

    #[cfg(not(unix))]
    {
        let _ = user;
        warn!("privilege drop requested but not supported on this platform");
        Ok(DropResult::Unsupported)
    }
}

/// Apply Landlock + seccomp / NO_NEW_PRIVS after privilege drop (Linux).
///
/// Modes: `auto` (skip on unsupported), `off`, `required` (fail closed).
pub fn apply_sandbox(
    hardening: &HardeningConfig,
    state_dir: &Path,
    extra_ro: &[&Path],
) -> std::io::Result<SandboxResult> {
    if hardening.landlock == "off" && hardening.seccomp == "off" {
        return Ok(SandboxResult::Disabled);
    }

    #[cfg(target_os = "linux")]
    {
        let landlock = apply_landlock(&hardening.landlock, state_dir, extra_ro)?;
        let seccomp = apply_seccomp(&hardening.seccomp)?;
        info!(%landlock, %seccomp, "sandbox applied after privilege drop");
        Ok(SandboxResult::Applied { landlock, seccomp })
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_dir, extra_ro);
        let reason = "sandbox not supported on this platform".to_string();
        if hardening.landlock == "required" || hardening.seccomp == "required" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!("{reason} (mode=required)"),
            ));
        }
        info!(%reason, "sandbox skipped");
        Ok(SandboxResult::Skipped { reason })
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock(mode: &str, state_dir: &Path, extra_ro: &[&Path]) -> std::io::Result<String> {
    if mode == "off" {
        return Ok("off".into());
    }
    match try_landlock(state_dir, extra_ro) {
        Ok(msg) => Ok(msg),
        Err(e) if mode == "auto" => {
            info!(error = %e, "landlock unavailable; continuing (auto)");
            Ok(format!("skipped:{e}"))
        }
        Err(e) => Err(std::io::Error::other(format!(
            "landlock required but failed: {e}"
        ))),
    }
}

/// Best-effort Landlock ABI: restrict to state_dir (RW) and optional RO paths.
/// Uses raw syscalls so we degrade cleanly when the kernel lacks Landlock.
#[cfg(target_os = "linux")]
fn try_landlock(state_dir: &Path, extra_ro: &[&Path]) -> Result<String, String> {
    // Landlock syscall numbers (x86_64 / aarch64 share these since ABI introduction).
    // We probe via landlock_create_ruleset; ENOSYS / EOPNOTSUPP → unsupported.
    const LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const LANDLOCK_ADD_RULE: libc::c_long = 445;
    const LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

    const ACCESS_FS_ROUGHLY_READ: u64 =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const ACCESS_FS_ROUGHLY_WRITE: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    let attr = LandlockRulesetAttr {
        handled_access_fs: ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE,
    };

    let ruleset = unsafe {
        libc::syscall(
            LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset < 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!("create_ruleset: {err}"));
    }
    let ruleset = ruleset as i32;

    let add_path = |path: &Path, access: u64| -> Result<(), String> {
        let c =
            std::ffi::CString::new(path.to_string_lossy().as_bytes()).map_err(|e| e.to_string())?;
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(format!(
                "open {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let path_attr = LandlockPathBeneathAttr {
            allowed_access: access,
            parent_fd: fd,
        };
        const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
        let rc = unsafe {
            libc::syscall(
                LANDLOCK_ADD_RULE,
                ruleset,
                LANDLOCK_RULE_PATH_BENEATH,
                &path_attr as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        unsafe { libc::close(fd) };
        if rc < 0 {
            return Err(format!(
                "add_rule {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    };

    // Always allow reading system libs/certs and writing state_dir.
    let _ = add_path(Path::new("/usr"), ACCESS_FS_ROUGHLY_READ);
    let _ = add_path(Path::new("/lib"), ACCESS_FS_ROUGHLY_READ);
    let _ = add_path(Path::new("/lib64"), ACCESS_FS_ROUGHLY_READ);
    let _ = add_path(Path::new("/etc"), ACCESS_FS_ROUGHLY_READ);
    let _ = add_path(
        Path::new("/dev/null"),
        ACCESS_FS_ROUGHLY_READ | LANDLOCK_ACCESS_FS_WRITE_FILE,
    );
    let _ = std::fs::create_dir_all(state_dir);
    add_path(state_dir, ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE)?;
    for p in extra_ro {
        if p.exists() {
            let _ = add_path(p, ACCESS_FS_ROUGHLY_READ);
        }
    }

    // NO_NEW_PRIVS is required before restrict_self.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        unsafe { libc::close(ruleset) };
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }

    let rc = unsafe { libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset, 0u32) };
    unsafe { libc::close(ruleset) };
    if rc < 0 {
        return Err(format!(
            "restrict_self: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok("applied".into())
}

#[cfg(target_os = "linux")]
fn apply_seccomp(mode: &str) -> std::io::Result<String> {
    if mode == "off" {
        return Ok("off".into());
    }

    #[cfg(all(target_os = "linux", target_endian = "little"))]
    {
        match seccomp::apply_default_bpf() {
            Ok(()) => Ok(format!("bpf:{}", seccomp::PROFILE_NAME)),
            Err(e) if mode == "auto" => {
                // Soft fallback: NO_NEW_PRIVS only (pre-P10.9 behaviour).
                info!(error = %e, "seccomp BPF unavailable; falling back to NO_NEW_PRIVS (auto)");
                match try_no_new_privs() {
                    Ok(()) => Ok(format!("no_new_privs_fallback:{e}")),
                    Err(e2) => {
                        info!(error = %e2, "NO_NEW_PRIVS also failed; continuing (auto)");
                        Ok(format!("skipped:{e};{e2}"))
                    }
                }
            }
            Err(e) => Err(std::io::Error::other(format!(
                "seccomp BPF required but failed: {e}"
            ))),
        }
    }

    #[cfg(all(target_os = "linux", not(target_endian = "little")))]
    {
        // seccompiler is little-endian only.
        match try_no_new_privs() {
            Ok(()) if mode == "auto" => Ok("no_new_privs_be_unsupported".into()),
            Ok(()) => Err(std::io::Error::other(
                "seccomp BPF required but host endianness unsupported",
            )),
            Err(e) if mode == "auto" => Ok(format!("skipped:{e}")),
            Err(e) => Err(std::io::Error::other(format!(
                "seccomp required but failed: {e}"
            ))),
        }
    }
}

#[cfg(target_os = "linux")]
fn try_no_new_privs() -> Result<(), String> {
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!("{}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Best-effort systemd watchdog ping (no-op if `NOTIFY_SOCKET` unset).
pub fn sd_notify_ready() {
    #[cfg(unix)]
    {
        if std::env::var_os("NOTIFY_SOCKET").is_some() {
            info!("systemd notify: READY=1 (NOTIFY_SOCKET present)");
        }
    }
}

/// Watchdog kick placeholder for long-running loops.
pub fn sd_notify_watchdog() {
    #[cfg(unix)]
    {
        if std::env::var_os("NOTIFY_SOCKET").is_some() {
            tracing::trace!("systemd notify: WATCHDOG=1");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_when_no_user() {
        let cfg = ServerConfig::default();
        let r = drop_privileges(&cfg).unwrap();
        assert_eq!(r, DropResult::Skipped);
    }

    #[test]
    #[cfg(windows)]
    fn unsupported_on_windows_when_user_set() {
        let cfg = ServerConfig {
            user: Some("nobody".into()),
            ..Default::default()
        };
        let r = drop_privileges(&cfg).unwrap();
        assert_eq!(r, DropResult::Unsupported);
    }

    #[test]
    fn sandbox_off() {
        let h = HardeningConfig {
            landlock: "off".into(),
            seccomp: "off".into(),
        };
        let r = apply_sandbox(&h, Path::new("."), &[]).unwrap();
        assert_eq!(r, SandboxResult::Disabled);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn sandbox_auto_skips_non_linux() {
        let h = HardeningConfig::default();
        let r = apply_sandbox(&h, Path::new("."), &[]).unwrap();
        assert!(matches!(r, SandboxResult::Skipped { .. }));
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn sandbox_required_fails_non_linux() {
        let h = HardeningConfig {
            landlock: "required".into(),
            seccomp: "auto".into(),
        };
        assert!(apply_sandbox(&h, Path::new("."), &[]).is_err());
    }
}
