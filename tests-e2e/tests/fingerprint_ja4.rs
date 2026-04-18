//! TLS JA4 fingerprint injection tests.
//!
//! Covers all four JA4 variants (`ja4`, `ja4_r`, `ja4_o`, `ja4_or`) across every combination
//! of HTTP version (HTTP/1.1 and HTTP/2) and IP version (IPv4 and IPv6).
//! Also verifies that JA4 headers respect per-route fingerprinting configuration.

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

// ── impl ──────────────────────────────────────────────────────────────────────

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

    let echo = parse_backend_echo(response).await?;

    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(echo.has_header(key), "Header {key} should be present");
    }

    let tls_fp = echo
        .header(names::TLS_JA4)
        .ok_or("TLS JA4 header should be present")?;
    let tls_fp_r = echo
        .header(names::TLS_JA4_R)
        .ok_or("TLS JA4_r header should be present")?;
    let tls_fp_o = echo
        .header(names::TLS_JA4_O)
        .ok_or("TLS JA4_o header should be present")?;
    let tls_fp_or = echo
        .header(names::TLS_JA4_OR)
        .ok_or("TLS JA4_or header should be present")?;

    assert!(!tls_fp.is_empty(), "TLS JA4 fingerprint should not be empty");
    assert!(tls_fp.starts_with('t'), "TLS fingerprint should start with 't'");
    assert!(tls_fp.contains('_'), "TLS fingerprint should contain underscore separators");

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
    let echo2 = parse_backend_echo(response2).await?;
    let tls_fp2 = echo2
        .header(names::TLS_JA4)
        .ok_or("TLS JA4 missing in second response")?;
    assert_eq!(tls_fp, tls_fp2, "TLS JA4 fingerprint must be consistent across requests");
    assert_eq!(tls_fp2, expected, "Second request TLS JA4 must match expected value");

    Ok(())
}

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
    let echo = parse_backend_echo(response).await?;
    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(
            !echo.has_header(key),
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
    let echo2 = parse_backend_echo(response2).await?;
    for key in [names::TLS_JA4, names::TLS_JA4_R, names::TLS_JA4_O, names::TLS_JA4_OR] {
        assert!(echo2.has_header(key), "{key} should be present when fingerprinting is enabled");
    }
    let tls_fp = echo2
        .header(names::TLS_JA4)
        .ok_or("TLS JA4 should be present")?;
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
