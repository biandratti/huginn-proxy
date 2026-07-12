//! ACME end-to-end tests against a local Pebble ACME server.
//!
//! Requires `examples/docker-compose.acme.yml` to be running. Run with:
//!
//! ```bash
//! ./examples/acme/gen-pebble-ca.sh
//! docker compose -f examples/docker-compose.acme.yml up --build -d
//! cargo test -p tests-e2e --test acme
//! ```
//!
//! Covers issuance, readiness, metrics, and resolver stability.
//! Renewal and cache tests live in `acme_renewal.rs`.

#[path = "acme_helpers.rs"]
mod acme_helpers;
use acme_helpers::{
    acme_metric_value, cert_serial, fetch_leaf_certificate, fetch_leaf_once, fetch_metrics,
    METRICS_URL, PROXY_ADDR, PROXY_HOST, PROXY_PORT,
};

use std::net::SocketAddr;
use std::time::Duration;

use x509_parser::extensions::GeneralName;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn acme_cert_is_issued_by_pebble_for_the_domain() -> TestResult {
    let leaf = fetch_leaf_certificate().await?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|e| format!("failed to parse leaf certificate: {e}"))?;

    let issuer = cert.issuer().to_string();
    assert!(issuer.contains("Pebble"), "leaf issuer should be Pebble, got: {issuer}");

    let san = cert
        .subject_alternative_name()
        .map_err(|e| format!("failed to read SAN: {e}"))?
        .ok_or("leaf certificate has no SAN extension")?;
    let has_domain = san
        .value
        .general_names
        .iter()
        .any(|gn| matches!(gn, GeneralName::DNSName(dns) if *dns == PROXY_HOST));
    assert!(has_domain, "leaf SAN must include {PROXY_HOST}");

    Ok(())
}

#[tokio::test]
async fn acme_proxy_serves_traffic_with_issued_cert() -> TestResult {
    let _ = fetch_leaf_certificate().await?;

    let addr: SocketAddr = PROXY_ADDR.parse()?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve(PROXY_HOST, addr)
        .timeout(Duration::from_secs(5))
        .build()?;

    let resp = client
        .get(format!("https://{PROXY_HOST}:{PROXY_PORT}/"))
        .send()
        .await?;
    assert_eq!(resp.status(), 200, "proxy should return 200 over the ACME cert");

    let body = resp.text().await?;
    assert!(body.contains("Hostname:"), "expected whoami echo body, got: {body}");

    Ok(())
}

#[tokio::test]
async fn acme_readiness_endpoint_ok() -> TestResult {
    let _ = fetch_leaf_certificate().await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("failed to build client: {e}"))?;
    let resp = client
        .get(format!("{METRICS_URL}/ready"))
        .send()
        .await
        .map_err(|e| format!("GET /ready failed: {e}"))?;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "/ready must return 200 once the ACME cert is deployed"
    );
    Ok(())
}

#[tokio::test]
async fn acme_metrics_cert_ready_and_renewals() -> TestResult {
    let _ = fetch_leaf_certificate().await?;

    // Allow a short retry in case the scrape endpoint hasn't refreshed yet.
    let mut body = String::new();
    for _ in 0..10u32 {
        body = fetch_metrics().await?;
        if acme_metric_value(&body, "huginn_acme_cert_ready", &[("domain", PROXY_HOST)])
            == Some(1.0)
        {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let ready = acme_metric_value(&body, "huginn_acme_cert_ready", &[("domain", PROXY_HOST)]);
    assert_eq!(
        ready,
        Some(1.0),
        "huginn_acme_cert_ready{{domain=\"{PROXY_HOST}\"}} must be 1 after cert deploy"
    );

    let renewals = acme_metric_value(
        &body,
        "huginn_acme_cert_renewals_total",
        &[("domain", PROXY_HOST), ("result", "success")],
    );
    assert!(
        renewals.map(|v| v >= 1.0).unwrap_or(false),
        "huginn_acme_cert_renewals_total{{result=\"success\"}} must be >= 1, got: {renewals:?}"
    );
    Ok(())
}

#[tokio::test]
async fn acme_cert_served_on_consecutive_connections() -> TestResult {
    let _ = fetch_leaf_certificate().await?;

    for i in 1..=3u32 {
        let leaf = fetch_leaf_once()
            .await
            .map_err(|e| format!("connection {i} failed: {e}"))?;
        let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref())
            .map_err(|e| format!("connection {i}: failed to parse cert: {e}"))?;

        let issuer = cert.issuer().to_string();
        assert!(
            issuer.contains("Pebble"),
            "connection {i}: expected Pebble-issued cert, got issuer: {issuer}"
        );

        let san = cert
            .subject_alternative_name()
            .map_err(|e| format!("connection {i}: SAN error: {e}"))?
            .ok_or_else(|| format!("connection {i}: no SAN extension"))?;
        let has_domain = san
            .value
            .general_names
            .iter()
            .any(|gn| matches!(gn, GeneralName::DNSName(dns) if *dns == PROXY_HOST));
        assert!(has_domain, "connection {i}: SAN must include {PROXY_HOST}");
    }

    // Additionally verify the serial is stable across these rapid connections:
    // if all 3 return the same cert no silent cert flapping occurred.
    let s0 = cert_serial(&fetch_leaf_once().await?)?;
    let s1 = cert_serial(&fetch_leaf_once().await?)?;
    let s2 = cert_serial(&fetch_leaf_once().await?)?;
    assert!(
        s0 == s1 && s1 == s2,
        "serial flapped across rapid connections: {s0} / {s1} / {s2}"
    );

    Ok(())
}
