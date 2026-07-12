//! ACME end-to-end tests: certificate renewal and DirCache persistence.
//!
//! Requires `examples/docker-compose.acme.yml` with `"certificateValidityPeriod": 90` set in
//! `examples/acme/pebble-config.json`. With 90 s validity, `rustls-acme` triggers renewal at
//! ~60 s (at `not_after - validity/3`), giving a 30 s window for the ACME order cycle.
//!
//! Run with:
//!
//! ```bash
//! ./examples/acme/gen-pebble-ca.sh
//! docker compose -f examples/docker-compose.acme.yml up --build -d
//! cargo test -p tests-e2e --test acme_renewal
//! ```
//!
//! Tests run sequentially (`#[serial]`) because they share the same running proxy and all
//! observe the same renewal windows.

#[path = "acme_helpers.rs"]
mod acme_helpers;
use acme_helpers::{
    acme_metric_value, cert_serial, fetch_leaf_certificate, fetch_metrics, METRICS_URL, PROXY_ADDR,
    PROXY_HOST, PROXY_PORT,
};

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Pebble `certificateValidityPeriod` value (seconds). rustls-acme renews at 2/3 of this:
/// trigger at ~60 s, giving a 30 s window for the ACME order cycle before expiry.
const CERT_VALIDITY_SECS: u64 = 90;

/// Poll timeout for each renewal test. Two full cert lifetimes gives ample margin.
const RENEWAL_TIMEOUT_SECS: u64 = CERT_VALIDITY_SECS * 2;

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

/// Poll until the leaf certificate's serial differs from `known`, or until
/// `RENEWAL_TIMEOUT_SECS` elapses. Returns the new serial on success.
async fn wait_for_new_serial(
    known: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let poll = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if let Ok(leaf) = fetch_leaf_certificate().await {
                if let Ok(serial) = cert_serial(&leaf) {
                    if serial != known {
                        return serial;
                    }
                }
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(RENEWAL_TIMEOUT_SECS), poll)
        .await
        .map_err(|_| {
            format!(
                "cert serial unchanged after {RENEWAL_TIMEOUT_SECS}s - renewal did not fire \
                 (is \"certificateValidityPeriod\": {CERT_VALIDITY_SECS} set in pebble-config.json?)"
            )
            .into()
        })
}

// Tests run sequentially (#[serial]) because they share the same proxy state and
// all observe the same renewal windows.

/// Renewal issues a new leaf certificate with a different serial number.
///
/// Captures the serial after first issuance, then polls until the proxy serves a
/// different serial. Verifies the `rustls-acme` background renewal loop fires and
/// `CompositeResolver` hot-swaps to the new cert without a restart.
#[tokio::test]
#[serial]
async fn acme_renewal_issues_new_leaf() -> TestResult {
    let leaf1 = fetch_leaf_certificate().await?;
    let serial1 = cert_serial(&leaf1)?;

    let serial2 = wait_for_new_serial(&serial1).await?;
    assert_ne!(serial1, serial2, "renewed cert must have a different serial number");

    // The new cert must still be a valid Pebble cert for the correct domain.
    let leaf2 = fetch_leaf_certificate().await?;
    let (_, cert2) = x509_parser::parse_x509_certificate(leaf2.as_ref())
        .map_err(|e| format!("failed to parse renewed cert: {e}"))?;
    assert!(
        cert2.issuer().to_string().contains("Pebble"),
        "renewed cert must still be issued by Pebble, got: {}",
        cert2.issuer()
    );

    Ok(())
}

/// No traffic failures during a certificate hot-swap renewal.
///
/// Sends an HTTP request every 500 ms via a background task while waiting for
/// `rustls-acme` to renew the certificate. Asserts zero failures, proving the
/// in-memory cert swap is transparent to live connections.
#[tokio::test]
#[serial]
async fn acme_renewal_no_downtime() -> TestResult {
    let leaf1 = fetch_leaf_certificate().await?;
    let serial1 = cert_serial(&leaf1)?;

    let proxy_addr: SocketAddr = PROXY_ADDR
        .parse()
        .map_err(|e| format!("invalid PROXY_ADDR: {e}"))?;
    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(PROXY_HOST, proxy_addr)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let failure_count = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));
    let failures_task = failure_count.clone();
    let running_task = running.clone();
    let client_task = http_client;

    let background = tokio::spawn(async move {
        while running_task.load(Ordering::Relaxed) {
            let ok = client_task
                .get(format!("https://{PROXY_HOST}:{PROXY_PORT}/"))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if !ok {
                failures_task.fetch_add(1, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    let serial2 = wait_for_new_serial(&serial1).await?;
    running.store(false, Ordering::Relaxed);
    background
        .await
        .map_err(|e| format!("background task panicked: {e}"))?;

    let failures = failure_count.load(Ordering::Relaxed);
    assert_eq!(
        failures, 0,
        "cert hot-swap must not cause traffic failures; \
         got {failures} failures during renewal from {serial1} to {serial2}"
    );
    Ok(())
}

/// `huginn_acme_cert_renewals_total{result="success"}` increments after renewal.
///
/// Records the counter before the renewal window, waits for a new serial, then asserts the
/// counter increased by at least 1.
#[tokio::test]
#[serial]
async fn acme_renewal_metrics_increment() -> TestResult {
    let leaf1 = fetch_leaf_certificate().await?;
    let serial1 = cert_serial(&leaf1)?;

    let body_before = fetch_metrics().await?;
    let count_before = acme_metric_value(
        &body_before,
        "huginn_acme_cert_renewals_total",
        &[("domain", PROXY_HOST), ("result", "success")],
    )
    .unwrap_or(0.0);

    let _ = wait_for_new_serial(&serial1).await?;

    // Allow a moment for the event callback to flush the counter.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let body_after = fetch_metrics().await?;
    let count_after = acme_metric_value(
        &body_after,
        "huginn_acme_cert_renewals_total",
        &[("domain", PROXY_HOST), ("result", "success")],
    )
    .unwrap_or(0.0);

    assert!(
        count_after > count_before,
        "huginn_acme_cert_renewals_total{{result=\"success\"}} must increase after renewal \
         (was {count_before}, now {count_after})"
    );
    Ok(())
}

/// Proxy restart loads the certificate from DirCache without issuing a new ACME order.
///
/// Captures the serial before restart, restarts the proxy container (the `acme-cache` Docker
/// volume persists), waits for the proxy to become healthy again, then asserts the serial is
/// unchanged, proving `DirCache` is populated correctly and loaded on startup.
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
