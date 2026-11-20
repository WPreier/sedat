//! Seccomp-BPF syscall allowlist (P10.9 / E7).
//!
//! Builds a known-good filter for SeDat's reverse-proxy workload and installs it
//! with `SECCOMP_FILTER_FLAG_TSYNC` so all threads (Tokio workers) inherit it.
//! Default action is `EPERM` (blocked, not SIGSYS kill) for safer ops/debug.

#![cfg(all(target_os = "linux", target_endian = "little"))]

use std::collections::BTreeMap;
use std::convert::TryInto;

use seccompiler::{
    apply_filter_all_threads, BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch,
};
use tracing::debug;

/// Human-readable profile id (also mirrored under `deploy/seccomp/`).
pub const PROFILE_NAME: &str = "sedat-default-v1";

/// Compile the built-in SeDat allowlist to a BPF program (does not install).
pub fn compile_default_filter() -> Result<BpfProgram, String> {
    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|e| format!("seccomp arch: {e}"))?;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in allowed_syscalls() {
        rules.insert(nr, Vec::new()); // empty rules ⇒ allow regardless of args
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;

    filter
        .try_into()
        .map_err(|e| format!("seccomp bpf compile: {e}"))
}

/// Set `NO_NEW_PRIVS` and install the default BPF allowlist on all threads.
pub fn apply_default_bpf() -> Result<(), String> {
    // Kernel requires NO_NEW_PRIVS before unprivileged SECCOMP_MODE_FILTER.
    let nnp = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if nnp != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }

    let bpf = compile_default_filter()?;
    debug!(profile = PROFILE_NAME, instrs = bpf.len(), "installing seccomp BPF");
    apply_filter_all_threads(&bpf).map_err(|e| format!("seccomp apply: {e}"))?;
    Ok(())
}

/// Syscalls SeDat needs for Tokio/hyper/rustls reverse-proxy operation.
///
/// Intentionally **denies** `execve`/`execveat`, `ptrace`, `mount`, `reboot`,
/// module load, and similar high-blast-radius calls (default → EPERM).
fn allowed_syscalls() -> Vec<i64> {
    let mut v = vec![
        // I/O
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_lseek,
        libc::SYS_fdatasync,
        libc::SYS_fsync,
        libc::SYS_ftruncate,
        // open family
        libc::SYS_openat,
        // sockets
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        // epoll / event
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_pipe2,
        // memory
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_mremap,
        // threads / sync
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_set_tid_address,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_rseq,
        // time
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_gettimeofday,
        // signals
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_sigaltstack,
        libc::SYS_tgkill,
        // fd control / stat
        libc::SYS_fcntl,
        libc::SYS_ioctl,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        // filesystem (state_dir / certs; Landlock further scopes paths)
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_mkdirat,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        // misc process
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getrandom,
        libc::SYS_uname,
        libc::SYS_getcwd,
        libc::SYS_prctl,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_memfd_create,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_restart_syscall,
    ];

    #[cfg(target_arch = "x86_64")]
    {
        v.extend_from_slice(&[
            libc::SYS_open,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_epoll_create,
            libc::SYS_epoll_wait,
            libc::SYS_pipe,
            libc::SYS_dup2,
            libc::SYS_arch_prctl,
            libc::SYS_fork, // some allocators / tooling; still no execve
            libc::SYS_vfork,
            libc::SYS_wait4,
            libc::SYS_access,
            libc::SYS_unlink,
            libc::SYS_rename,
            libc::SYS_mkdir,
            libc::SYS_readlink,
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_time,
        ]);
    }

    #[cfg(target_arch = "aarch64")]
    {
        v.extend_from_slice(&[
            libc::SYS_epoll_pwait2,
            libc::SYS_ppoll,
            libc::SYS_fstatfs,
        ]);
    }

    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_default_filter() {
        let bpf = compile_default_filter().expect("compile");
        assert!(!bpf.is_empty());
    }

    #[test]
    fn allowlist_includes_network_and_excludes_nothing_critical_from_list() {
        let set: std::collections::HashSet<_> = allowed_syscalls().into_iter().collect();
        assert!(set.contains(&libc::SYS_socket));
        assert!(set.contains(&libc::SYS_epoll_ctl));
        assert!(set.contains(&libc::SYS_clone));
        // High-blast-radius calls must NOT be in the allowlist.
        assert!(!set.contains(&libc::SYS_execve));
        assert!(!set.contains(&libc::SYS_execveat));
        assert!(!set.contains(&libc::SYS_ptrace));
        assert!(!set.contains(&libc::SYS_mount));
        assert!(!set.contains(&libc::SYS_reboot));
    }

    #[test]
    fn bpf_blocks_mount_in_child() {
        // Apply filter only in a forked child so the test process stays usable.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            if let Err(e) = apply_default_bpf() {
                eprintln!("apply failed: {e}");
                unsafe { libc::_exit(2) };
            }
            // Allowed:
            let _ = unsafe { libc::getpid() };
            // Forbidden:
            let none = std::ffi::CString::new("none").unwrap();
            let root = std::ffi::CString::new("/").unwrap();
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_mount,
                    none.as_ptr(),
                    root.as_ptr(),
                    none.as_ptr(),
                    0usize,
                    std::ptr::null::<libc::c_void>(),
                )
            };
            let err = std::io::Error::last_os_error().raw_os_error();
            if rc < 0 && err == Some(libc::EPERM) {
                unsafe { libc::_exit(0) };
            }
            eprintln!("mount rc={rc} err={err:?}");
            unsafe { libc::_exit(1) };
        }
        let mut status: libc::c_int = 0;
        let w = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(w, pid);
        let code = libc::WEXITSTATUS(status);
        assert_eq!(code, 0, "child exit status={status:#x}");
    }
}
