//! P10.9: seccomp-BPF allowlist smoke (Linux little-endian only).
//!
//! Applies the filter only in a forked child so the test harness stays usable.

#![cfg(all(target_os = "linux", target_endian = "little"))]

use std::path::Path;

use sedat::config::HardeningConfig;
use sedat::hardening::apply_sandbox;

#[test]
fn seccomp_required_blocks_mount_in_child() {
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let h = HardeningConfig {
            landlock: "off".into(),
            seccomp: "required".into(),
        };
        if let Err(e) = apply_sandbox(&h, Path::new("."), &[]) {
            eprintln!("apply_sandbox: {e}");
            unsafe { libc::_exit(2) };
        }
        let _ = unsafe { libc::getpid() };
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
    assert_eq!(libc::WEXITSTATUS(status), 0, "status={status:#x}");
}
