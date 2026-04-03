//! HTTP/2 Akamai fingerprint tests.
//!
//! Verifies that the Akamai fingerprint header is:
//! - **present** with the exact expected value on HTTP/2 connections.
//! - **absent** on HTTP/1.1 connections (no HTTP/2 frames to fingerprint).
//! - **absent** on the `/static` route regardless of HTTP version (per-route gating).
//! - **present** on the `/api` route when using HTTP/2 (per-route gating).

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

const EXPECTED_AKAMAI: &str = "2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p";

// ── impl ──────────────────────────────────────────────────────────────────────

/// Asserts that the Akamai fingerprint header is present with the exact expected value
/// and is stable across a keep-alive second request (HTTP/2 connection).
async fn test_akamai_present_impl(
    url: &str,
    is_ipv6: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP/2 request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers")?;

    assert!(
        headers.contains_key(names::HTTP2_AKAMAI),
        "Akamai fingerprint should be present for HTTP/2 connection"
    );
    let akamai_fp = headers
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai fingerprint should be a string")?;
    assert!(!akamai_fp.is_empty(), "Akamai fingerprint should not be empty");
    assert!(akamai_fp.contains('|'), "Akamai fingerprint should contain pipe separator");
    assert_eq!(akamai_fp, EXPECTED_AKAMAI, "Akamai fingerprint should match expected value");

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    println!("{ip_ver} HTTP/2 Akamai fingerprint ({}): {akamai_fp}", names::HTTP2_AKAMAI);

    // Must be stable across a keep-alive second request
    let response2 = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send second HTTP/2 request: {e}"))?;
    let body2: serde_json::Value = response2.json().await?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Second response should contain headers")?;
    let akamai_fp2 = headers2
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai fingerprint missing in second response")?;
    assert_eq!(akamai_fp, akamai_fp2, "Akamai fingerprint must be consistent across requests");
    assert_eq!(akamai_fp2, EXPECTED_AKAMAI, "Second request Akamai must match expected value");

    Ok(())
}

/// Asserts that the Akamai fingerprint header is **absent** for HTTP/1.1 connections —
/// there are no HTTP/2 frames to fingerprint.
async fn test_akamai_absent_impl(
    url: &str,
    is_ipv6: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP/1.1 client: {e}"))?;

    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP/1.1 request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers")?;

    assert!(
        !headers.contains_key(names::HTTP2_AKAMAI),
        "Akamai fingerprint should NOT be present for HTTP/1.1 connection"
    );

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    println!("{ip_ver} HTTP/1.1: Akamai fingerprint correctly absent");

    Ok(())
}

/// Asserts that the Akamai fingerprint header is absent on the `/static` route (disabled)
/// and present on the `/api` route (enabled), using HTTP/2.
async fn test_akamai_per_route_impl(
    url: &str,
    is_ipv6: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    // /static → fingerprinting disabled: Akamai must be absent
    let response = client
        .get(format!("{url}/static/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /static: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers")?;
    assert!(
        !headers.contains_key(names::HTTP2_AKAMAI),
        "Akamai should NOT be present on /static (fingerprinting disabled)"
    );

    // /api → fingerprinting enabled: Akamai must be present with exact value
    let response2 = client
        .get(format!("{url}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = response2.json().await?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("/api response should contain headers")?;
    assert!(
        headers2.contains_key(names::HTTP2_AKAMAI),
        "Akamai should be present on /api (fingerprinting enabled)"
    );
    let akamai_fp = headers2
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai fingerprint should be a string")?;
    assert_eq!(akamai_fp, EXPECTED_AKAMAI, "Akamai on /api must match expected value");

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    println!("{ip_ver} HTTP/2 Akamai per-route: absent on /static, {akamai_fp} on /api");

    Ok(())
}

// ── HTTP/2 present × IPv4 / IPv6 ─────────────────────────────────────────────

#[tokio::test]
async fn test_akamai_present_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_akamai_present_impl(PROXY_HTTPS_URL_IPV4, false).await
}

#[tokio::test]
async fn test_akamai_present_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_akamai_present_impl(PROXY_HTTPS_URL_IPV6, true).await
}

// ── HTTP/1.1 absent × IPv4 / IPv6 ────────────────────────────────────────────

#[tokio::test]
async fn test_akamai_absent_http1_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_akamai_absent_impl(PROXY_HTTPS_URL_IPV4, false).await
}

#[tokio::test]
async fn test_akamai_absent_http1_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_akamai_absent_impl(PROXY_HTTPS_URL_IPV6, true).await
}

// ── Per-route gating × IPv4 / IPv6 ───────────────────────────────────────────

#[tokio::test]
async fn test_akamai_per_route_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_akamai_per_route_impl(PROXY_HTTPS_URL_IPV4, false).await
}

#[tokio::test]
async fn test_akamai_per_route_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_akamai_per_route_impl(PROXY_HTTPS_URL_IPV6, true).await
}
