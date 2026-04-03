//! TLS JA4 fingerprint injection tests.
//!
//! Covers all four JA4 variants (`ja4`, `ja4_r`, `ja4_o`, `ja4_or`) across every combination
//! of HTTP version (HTTP/1.1 and HTTP/2) and IP version (IPv4 and IPv6).
//! Also verifies that JA4 headers respect per-route fingerprinting configuration.

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

// ── impl ──────────────────────────────────────────────────────────────────────

/// Asserts that all four JA4 TLS fingerprint headers are present with the expected exact values
/// for the given HTTP version, and that they are stable across a keep-alive second request.
///
/// `use_http2 = false` → client uses `http1_only()`, expected JA4 ends with `h1`.
/// `use_http2 = true`  → client uses `http2_prior_knowledge()`, expected JA4 ends with `h2`.
async fn test_ja4_impl(
    url: &str,
    is_ipv6: bool,
    use_http2: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(true);
    builder = if use_http2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    };
    let client = builder
        .build()
        .map_err(|e| format!("Failed to create client: {e}"))?;

    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers")?;

    // All four JA4 variants must be present
    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(headers.contains_key(key), "Header {key} should be present");
    }

    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 header should be a string")?;
    let tls_fp_r = headers
        .get(names::TLS_JA4_R)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_r header should be a string")?;
    let tls_fp_o = headers
        .get(names::TLS_JA4_O)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_o header should be a string")?;
    let tls_fp_or = headers
        .get(names::TLS_JA4_OR)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_or header should be a string")?;

    assert!(!tls_fp.is_empty(), "TLS JA4 fingerprint should not be empty");
    assert!(tls_fp.starts_with('t'), "TLS fingerprint should start with 't'");
    assert!(tls_fp.contains('_'), "TLS fingerprint should contain underscore separators");

    // Expected value differs only in the ALPN field (h1 vs h2)
    let expected = if use_http2 {
        "t13i1010h2_61a7ad8aa9b6_3a8073edd8ef"
    } else {
        "t13i1010h1_61a7ad8aa9b6_3a8073edd8ef"
    };
    assert_eq!(tls_fp, expected, "TLS JA4 fingerprint should match expected value");

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    let http_ver = if use_http2 { "HTTP/2" } else { "HTTP/1.1" };
    println!("{ip_ver} {http_ver} TLS fingerprint ({}): {tls_fp}", names::TLS_JA4);
    println!("{ip_ver} {http_ver} TLS fingerprint ({}): {tls_fp_r}", names::TLS_JA4_R);
    println!("{ip_ver} {http_ver} TLS fingerprint ({}): {tls_fp_o}", names::TLS_JA4_O);
    println!("{ip_ver} {http_ver} TLS fingerprint ({}): {tls_fp_or}", names::TLS_JA4_OR);

    // JA4 must be stable across a keep-alive second request
    let response2 = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send second request: {e}"))?;
    let body2: serde_json::Value = response2.json().await?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Second response should contain headers")?;
    let tls_fp2 = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 missing in second response")?;
    assert_eq!(tls_fp, tls_fp2, "TLS JA4 fingerprint must be consistent across requests");
    assert_eq!(tls_fp2, expected, "Second request TLS JA4 must match expected value");

    Ok(())
}

/// Asserts that JA4 headers are absent on the `/static` route (fingerprinting disabled)
/// and present with the correct value on the `/api` route (fingerprinting enabled).
async fn test_ja4_per_route_impl(
    url: &str,
    use_http2: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = reqwest::Client::builder().danger_accept_invalid_certs(true);
    builder = if use_http2 {
        builder.http2_prior_knowledge()
    } else {
        builder.http1_only()
    };
    let client = builder
        .build()
        .map_err(|e| format!("Failed to create client: {e}"))?;

    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    // /static → fingerprinting disabled: all JA4 headers must be absent
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
    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(
            !headers.contains_key(key),
            "{key} should NOT be present when fingerprinting is disabled"
        );
    }

    // /api → fingerprinting enabled: all JA4 headers must be present with exact value
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
    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(
            headers2.contains_key(key),
            "{key} should be present when fingerprinting is enabled"
        );
    }
    let tls_fp = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 should be a string")?;
    let expected = if use_http2 {
        "t13i1010h2_61a7ad8aa9b6_3a8073edd8ef"
    } else {
        "t13i1010h1_61a7ad8aa9b6_3a8073edd8ef"
    };
    assert_eq!(tls_fp, expected, "TLS JA4 on enabled route must match expected value");

    Ok(())
}

// ── HTTP/1.1 × IPv4 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ja4_http1_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_impl(PROXY_HTTPS_URL_IPV4, false, false).await
}

#[tokio::test]
async fn test_ja4_per_route_http1_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_per_route_impl(PROXY_HTTPS_URL_IPV4, false).await
}

// ── HTTP/2 × IPv4 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ja4_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_impl(PROXY_HTTPS_URL_IPV4, false, true).await
}

#[tokio::test]
async fn test_ja4_per_route_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_per_route_impl(PROXY_HTTPS_URL_IPV4, true).await
}

// ── HTTP/1.1 × IPv6 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ja4_http1_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_impl(PROXY_HTTPS_URL_IPV6, true, false).await
}

#[tokio::test]
async fn test_ja4_per_route_http1_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_per_route_impl(PROXY_HTTPS_URL_IPV6, false).await
}

// ── HTTP/2 × IPv6 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_ja4_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_impl(PROXY_HTTPS_URL_IPV6, true, true).await
}

#[tokio::test]
async fn test_ja4_per_route_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_ja4_per_route_impl(PROXY_HTTPS_URL_IPV6, true).await
}
