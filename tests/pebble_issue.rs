//! Automated Pebble ACME issuance (ignored by default; CI enables with Pebble up).
//!
//! Run: `PEBBLE_DIRECTORY=https://localhost:14000/dir cargo test --test pebble_issue -- --ignored`

use std::path::PathBuf;
use std::time::Duration;

use sedat::acme::{self, AcmeManager, AcmePaths, FileDnsProvider};
use sedat::config::AcmeConfig;

#[tokio::test]
#[ignore = "requires local Pebble with PEBBLE_VA_ALWAYS_VALID=1"]
async fn pebble_dns01_issues_certificate() {
    let state = std::env::var("SEDAT_PEBBLE_ISSUE_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let d = tempfile::tempdir().expect("tempdir");
            // Keep tempdir alive for the test by leaking (CI uses explicit state dir).
            let p = d.path().to_path_buf();
            std::mem::forget(d);
            p
        });
    std::fs::create_dir_all(&state).unwrap();
    let dns_file = state.join("acme-dns-challenge.txt");
    let directory = std::env::var("PEBBLE_DIRECTORY")
        .unwrap_or_else(|_| "https://localhost:14000/dir".into());

    let cfg = AcmeConfig {
        enabled: true,
        directory,
        email: "ci@example.com".into(),
        domains: vec!["test.local".into()],
        dns_provider: "file".into(),
        dns_file: dns_file.to_string_lossy().into_owned(),
        cloudflare_api_token: None,
    };
    let paths = AcmePaths::new(&state);
    let dns = Box::new(FileDnsProvider::new(dns_file));
    let mgr = AcmeManager::new(cfg, paths.clone(), dns, None);

    // Pebble uses a private CA — instant-acme may need insecure TLS to the directory.
    // Retry a few times while compose comes up.
    let mut last = String::new();
    for attempt in 1..=10 {
        match mgr.order_once().await {
            Ok(()) => {
                assert!(paths.cert_path.exists(), "cert.pem missing");
                assert!(paths.key_path.exists(), "key.pem missing");
                let cert = std::fs::read(&paths.cert_path).unwrap();
                assert!(
                    String::from_utf8_lossy(&cert).contains("BEGIN CERTIFICATE"),
                    "cert pem missing"
                );
                return;
            }
            Err(e) => {
                last = e;
                eprintln!("pebble attempt {attempt}: {last}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    panic!("pebble issuance failed: {last}");
}

#[test]
fn pebble_directory_constant() {
    assert_eq!(acme::directory_url("pebble"), acme::PEBBLE_DIRECTORY);
}
