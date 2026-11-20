//! P10.10: validate deploy/sedat.service ships required cgroup / sandbox keys.

use std::fs;
use std::path::PathBuf;

fn unit_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/sedat.service")
}

#[test]
fn sedat_service_has_cgroup_and_sandbox_limits() {
    let text = fs::read_to_string(unit_path()).expect("read deploy/sedat.service");
    for key in [
        "MemoryHigh=",
        "MemoryMax=",
        "TasksMax=",
        "LimitNOFILE=",
        "CPUQuota=",
        "OOMScoreAdjust=",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "Type=notify",
        "WatchdogSec=",
    ] {
        assert!(
            text.contains(key),
            "deploy/sedat.service missing `{key}`"
        );
    }
    // Sensible hard ceiling present (value may be tuned later).
    assert!(
        text.lines().any(|l| l.starts_with("MemoryMax=") && l.contains('M')),
        "MemoryMax should set a megabyte-scale ceiling"
    );
}
