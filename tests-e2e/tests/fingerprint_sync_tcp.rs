//! TCP SYN fingerprint (eBPF) tests.
//!
//! Verifies that the eBPF-captured TCP SYN fingerprint header is:
//! - **present** on the first request of a new TCP connection.
//! - **present** on subsequent keep-alive requests (same SYN data reused).
//! - **prefixed with `4:`** for IPv4 connections, **`6:`** for IPv6 connections.
//! - **8 colon-separated fields** (the p0f-style format).
//! - **absent** on routes where fingerprinting is disabled, regardless of HTTP version.

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

// ── impl ──────────────────────────────────────────────────────────────────────

async fn test_tcp_syn_impl(
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

    assert!(
        echo.has_header(names::TCP_SYN),
        "TCP SYN fingerprint should be present on first request (new TCP connection)"
    );
    let tcp_fp = echo
        .header(names::TCP_SYN)
        .ok_or("TCP SYN fingerprint should be present")?;
    assert!(!tcp_fp.is_empty(), "TCP SYN fingerprint should not be empty");

    // IP-version prefix
    if is_ipv6 {
        assert!(
            tcp_fp.starts_with("6:"),
            "TCP SYN must use '6:' prefix for IPv6 connections; got: {tcp_fp}"
        );
    } else {
        assert!(
            tcp_fp.starts_with("4:") || tcp_fp.starts_with("6:"),
            "TCP SYN must use '4:' or '6:' prefix for IPv4 connections; got: {tcp_fp}"
        );
    }

    // p0f-style format: exactly 8 colon-separated fields
    assert_eq!(
        tcp_fp.split(':').count(),
        8,
        "TCP SYN fingerprint must have 8 colon-separated fields; got: {tcp_fp}"
    );

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    let http_ver = if use_http2 { "HTTP/2" } else { "HTTP/1.1" };
    println!("{ip_ver} {http_ver} TCP SYN fingerprint ({}): {tcp_fp}", names::TCP_SYN);

    // Must also be injected on the keep-alive second request (same TCP connection, same SYN data)
    let response2 = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send second request: {e}"))?;
    let echo2 = parse_backend_echo(response2).await?;
    assert!(
        echo2.has_header(names::TCP_SYN),
        "TCP SYN fingerprint should be present on keep-alive request (same TCP connection)"
    );
    let tcp_fp2 = echo2
        .header(names::TCP_SYN)
        .ok_or("TCP SYN missing in second response")?;
    assert_eq!(
        tcp_fp, tcp_fp2,
        "TCP SYN fingerprint must be consistent within the same connection"
    );

    Ok(())
}

async fn test_tcp_syn_per_route_impl(
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

    // /static → fingerprinting disabled: TCP SYN must be absent
    let response = client
        .get(format!("{url}/static/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /static: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert!(
        !echo.has_header(names::TCP_SYN),
        "TCP SYN should NOT be present on /static (fingerprinting disabled)"
    );

    // /api → fingerprinting enabled: TCP SYN must be present with correct prefix
    let response2 = client
        .get(format!("{url}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let echo2 = parse_backend_echo(response2).await?;
    assert!(
        echo2.has_header(names::TCP_SYN),
        "TCP SYN should be present on /api (fingerprinting enabled)"
    );
    let tcp_fp = echo2
        .header(names::TCP_SYN)
        .ok_or("TCP SYN fingerprint should be present")?;
    if is_ipv6 {
        assert!(
            tcp_fp.starts_with("6:"),
            "TCP SYN must use '6:' prefix for IPv6 connections; got: {tcp_fp}"
        );
    } else {
        assert!(
            tcp_fp.starts_with("4:") || tcp_fp.starts_with("6:"),
            "TCP SYN must use '4:' or '6:' prefix; got: {tcp_fp}"
        );
    }

    let ip_ver = if is_ipv6 { "IPv6" } else { "IPv4" };
    let http_ver = if use_http2 { "HTTP/2" } else { "HTTP/1.1" };
    println!("{ip_ver} {http_ver} TCP SYN per-route: absent on /static, {tcp_fp} on /api");

    Ok(())
}

// ── HTTP/1.1 × IPv4 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tcp_syn_http1_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tcp_syn_impl(PROXY_HTTPS_URL_IPV4, false, false).await
}

#[tokio::test]
async fn test_tcp_syn_per_route_http1_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_tcp_syn_per_route_impl(PROXY_HTTPS_URL_IPV4, false, false).await
}

// ── HTTP/2 × IPv4 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tcp_syn_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tcp_syn_impl(PROXY_HTTPS_URL_IPV4, false, true).await
}

#[tokio::test]
async fn test_tcp_syn_per_route_http2_ipv4() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_tcp_syn_per_route_impl(PROXY_HTTPS_URL_IPV4, false, true).await
}

// ── HTTP/1.1 × IPv6 ───────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tcp_syn_http1_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tcp_syn_impl(PROXY_HTTPS_URL_IPV6, true, false).await
}

#[tokio::test]
async fn test_tcp_syn_per_route_http1_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_tcp_syn_per_route_impl(PROXY_HTTPS_URL_IPV6, true, false).await
}

// ── HTTP/2 × IPv6 ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_tcp_syn_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tcp_syn_impl(PROXY_HTTPS_URL_IPV6, true, true).await
}

#[tokio::test]
async fn test_tcp_syn_per_route_http2_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_tcp_syn_per_route_impl(PROXY_HTTPS_URL_IPV6, true, true).await
}
