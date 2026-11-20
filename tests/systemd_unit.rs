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

#[test]
fn defaults_coherent_with_max_connections_budget() {
    // Mirror schema default_max_conn / assets/default_config.toml.
    const MAX_CONNECTIONS: usize = 1024;
    const FD_HEADROOM: usize = 256;
    // Memory rule-of-thumb used in P11.5 docs (KiB per conn, baseline MiB).
    const BASELINE_MIB: u64 = 128;
    const PER_CONN_KIB: u64 = 350;

    let text = fs::read_to_string(unit_path()).expect("read deploy/sedat.service");

    let nofile: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("LimitNOFILE=")?.parse().ok())
        .expect("LimitNOFILE=N");
    assert!(
        nofile >= 2 * MAX_CONNECTIONS + FD_HEADROOM,
        "LimitNOFILE={nofile} too small for max_connections={MAX_CONNECTIONS}"
    );

    let memory_max_m: u64 = text
        .lines()
        .find_map(|l| {
            let v = l.strip_prefix("MemoryMax=")?;
            let num = v.trim_end_matches(|c: char| c.is_ascii_alphabetic());
            num.parse().ok()
        })
        .expect("MemoryMax=NM");
    let need_m = BASELINE_MIB + (MAX_CONNECTIONS as u64 * PER_CONN_KIB) / 1024;
    assert!(
        memory_max_m >= need_m,
        "MemoryMax={memory_max_m}M < rule-of-thumb {need_m}M for C={MAX_CONNECTIONS}"
    );

    let tasks: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("TasksMax=")?.parse().ok())
        .expect("TasksMax=N");
    assert!(
        tasks >= MAX_CONNECTIONS + 64,
        "TasksMax={tasks} too small for max_connections={MAX_CONNECTIONS}"
    );
}
