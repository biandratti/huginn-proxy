//! ACME end-to-end tests: DirCache persistence across proxy restarts.
//!
//! Requires `examples/docker-compose.acme.yml` to be running. Run with:
//!
//! ```bash
//! ./examples/acme/gen-pebble-ca.sh
//! docker compose -f examples/docker-compose.acme.yml up --build -d
//! cargo test -p tests-e2e --test acme_renewal
//! ```
//!
//! Kept as a separate test binary from `acme.rs` because these tests restart the proxy
//! container, which would interfere with tests running in parallel in the same binary.
//!
//! # Note on certificate renewal tests
//!
//! Hot-swap renewal tests (observing a serial change after the rustls-acme renewal timer fires)
//! require short-lived certificates. Pebble's `certificateValidityPeriod` config field is in
//! **days** (minimum: 1 day = 86 400 s; renewal trigger at ~57 600 s). That is far too long for
//! a CI timeout. A dedicated short-validity ACME server (e.g. step-ca with a provisioner TTL of
//! 60-90 s) would be needed to test this in CI; it is left for a future extension.

#[path = "acme_helpers.rs"]
mod acme_helpers;
use acme_helpers::{cert_serial, fetch_leaf_certificate, METRICS_URL};

use std::time::Duration;

use serial_test::serial;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Absolute path to the ACME compose file, resolved from the package manifest directory so
/// it works regardless of where `cargo test` sets the working directory (which is the package
/// root, not the workspace root).
fn compose_file() -> Result<std::path::PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .ok_or("CARGO_MANIFEST_DIR has no parent - cannot locate workspace root")?;
    Ok(workspace.join("examples/docker-compose.acme.yml"))
}

#[tokio::test]
#[serial]
async fn acme_cache_survives_restart() -> TestResult {
    let leaf_before = fetch_leaf_certificate().await?;
    let serial_before = cert_serial(&leaf_before)?;

    let compose = compose_file()?;
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new("docker")
            .args(["compose", "-f"])
            .arg(compose)
            .args(["restart", "proxy"])
            .status()
    })
    .await
    .map_err(|e| format!("spawn_blocking error: {e}"))??;
    if !status.success() {
        return Err(format!("docker compose restart exited with {status}").into());
    }

    // Wait for the proxy health endpoint (cert loaded from DirCache before /health returns 200).
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("failed to build health client: {e}"))?;
    let mut healthy = false;
    for _ in 0..60u32 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        if client
            .get(format!("{METRICS_URL}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            healthy = true;
            break;
        }
    }
    if !healthy {
        return Err("proxy did not become healthy within 30 s after restart".into());
    }

    let leaf_after = fetch_leaf_certificate().await?;
    let serial_after = cert_serial(&leaf_after)?;

    assert_eq!(
        serial_before, serial_after,
        "cert serial must be identical after restart: DirCache must be loaded \
         (a different serial means a new ACME order was issued instead of using the cache)"
    );
    Ok(())
}
