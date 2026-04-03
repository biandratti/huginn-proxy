use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_tls_fingerprint_injection() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This test uses HTTP/1.1, so only TLS fingerprint should be present
    // Force HTTP/1.1 by disabling HTTP/2 support
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    // Check for TLS fingerprint headers (should be present for all TLS connections)
    assert!(headers.contains_key(names::TLS_JA4), "TLS JA4 header should be present");
    assert!(headers.contains_key(names::TLS_JA4_R), "TLS JA4_r header should be present");
    assert!(headers.contains_key(names::TLS_JA4_O), "TLS JA4_o header should be present");
    assert!(headers.contains_key(names::TLS_JA4_OR), "TLS JA4_or header should be present");

    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS JA4 fingerprint should not be empty");

    let tls_fp_r = headers
        .get(names::TLS_JA4_R)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_r header should be a string")?;
    assert!(!tls_fp_r.is_empty(), "TLS JA4_r fingerprint should not be empty");

    let tls_fp_o = headers
        .get(names::TLS_JA4_O)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_o header should be a string")?;
    assert!(!tls_fp_o.is_empty(), "TLS JA4_o fingerprint should not be empty");

    let tls_fp_or = headers
        .get(names::TLS_JA4_OR)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_or header should be a string")?;
    assert!(!tls_fp_or.is_empty(), "TLS JA4_or fingerprint should not be empty");

    println!("IPv4 TLS fingerprint ({}): {tls_fp}", names::TLS_JA4);
    println!("IPv4 TLS fingerprint ({}): {tls_fp_r}", names::TLS_JA4_R);
    println!("IPv4 TLS fingerprint ({}): {tls_fp_o}", names::TLS_JA4_O);
    println!("IPv4 TLS fingerprint ({}): {tls_fp_or}", names::TLS_JA4_OR);

    assert!(tls_fp.starts_with('t'), "TLS fingerprint should start with 't'");
    assert!(tls_fp.contains('_'), "TLS fingerprint should contain underscore separators");

    // Expected TLS fingerprint for reqwest client (HTTP/1.1)
    // Note: When HTTP/1.1 is forced, the fingerprint ends with 'h1' instead of 'h2'
    const EXPECTED_TLS_FINGERPRINT: &str = "t13i1010h1_61a7ad8aa9b6_3a8073edd8ef";
    assert_eq!(
        tls_fp, EXPECTED_TLS_FINGERPRINT,
        "TLS fingerprint should match expected value for reqwest HTTP/1.1 client"
    );

    // Verify consistency: same client should produce same fingerprint
    let response2 = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send second request: {e}"))?;
    let body2: serde_json::Value = response2
        .json()
        .await
        .map_err(|e| format!("Failed to parse second response as JSON: {e}"))?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Second response should contain headers object")?;
    let tls_fp2 = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string in second request")?;

    assert_eq!(
        tls_fp, tls_fp2,
        "TLS fingerprint should be consistent across multiple requests from the same client"
    );
    assert_eq!(
        tls_fp2, EXPECTED_TLS_FINGERPRINT,
        "Second request TLS fingerprint should also match expected value"
    );

    // HTTP/2 fingerprint should NOT be present for HTTP/1.1 connections
    assert!(
        !headers.contains_key(names::HTTP2_AKAMAI),
        "HTTP/2 fingerprint header should NOT be present in HTTP/1.1 connection"
    );

    // TCP SYN fingerprint should be present on the first request (new TCP connection)
    assert!(
        headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint header should be present on first request"
    );
    let tcp_fp = headers
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint header should be a string")?;
    assert!(!tcp_fp.is_empty(), "TCP SYN fingerprint should not be empty");
    assert!(
        tcp_fp.starts_with("4:") || tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint should start with '4:' (IPv4) or '6:' (IPv6)"
    );
    assert_eq!(
        tcp_fp.split(':').count(),
        8,
        "TCP SYN fingerprint should have 8 colon-separated fields: ver:ittl:olen:mss:wsize,wscale:olayout:quirks:pclass"
    );
    println!("IPv4 TCP SYN fingerprint ({}): {tcp_fp}", names::TCP_SYN);

    // TCP SYN fingerprint is injected on every request of the connection (same SYN, same fingerprint).
    assert!(
        headers2.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint should be present on keep-alive request (same TCP connection)"
    );

    Ok(())
}

#[tokio::test]
async fn test_http2_fingerprint_injection() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // HTTP/2 fingerprint only works for HTTP/2 connections
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP/2 request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    // Check for HTTP/2 fingerprint header
    assert!(
        headers.contains_key(names::HTTP2_AKAMAI),
        "HTTP/2 fingerprint header should be present"
    );

    let http2_fp = headers
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be a string")?;
    assert!(!http2_fp.is_empty(), "HTTP/2 fingerprint should not be empty");

    println!("IPv4 HTTP/2 fingerprint ({}): {http2_fp}", names::HTTP2_AKAMAI);

    assert!(http2_fp.contains('|'), "HTTP/2 fingerprint should contain pipe separator");

    // Expected HTTP/2 fingerprint for reqwest client with HTTP/2
    const EXPECTED_HTTP2_FINGERPRINT: &str = "2:0;4:2097152;5:16384;6:16384|5177345|0|m,s,a,p";
    assert_eq!(
        http2_fp, EXPECTED_HTTP2_FINGERPRINT,
        "HTTP/2 fingerprint should match expected value for reqwest HTTP/2 client"
    );

    // TCP SYN fingerprint should be present on the first request (new TCP connection)
    assert!(
        headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint header should be present on first HTTP/2 request"
    );
    let tcp_fp = headers
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint header should be a string")?;
    assert!(!tcp_fp.is_empty(), "TCP SYN fingerprint should not be empty");
    assert!(
        tcp_fp.starts_with("4:") || tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint should start with '4:' (IPv4) or '6:' (IPv6)"
    );
    println!("IPv4 TCP SYN fingerprint ({}): {tcp_fp}", names::TCP_SYN);

    // Also verify TLS fingerprint headers are present (all TLS connections should have them)
    assert!(
        headers.contains_key(names::TLS_JA4),
        "TLS JA4 header should be present in HTTP/2 connection"
    );
    assert!(
        headers.contains_key(names::TLS_JA4_R),
        "TLS JA4_r header should be present in HTTP/2 connection"
    );
    assert!(
        headers.contains_key(names::TLS_JA4_O),
        "TLS JA4_o header should be present in HTTP/2 connection"
    );
    assert!(
        headers.contains_key(names::TLS_JA4_OR),
        "TLS JA4_or header should be present in HTTP/2 connection"
    );

    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS JA4 fingerprint should not be empty");

    let tls_fp_r = headers
        .get(names::TLS_JA4_R)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4_r header should be a string")?;
    assert!(!tls_fp_r.is_empty(), "TLS JA4_r fingerprint should not be empty");

    println!("IPv4 TLS fingerprint ({}): {tls_fp}", names::TLS_JA4);
    println!("IPv4 TLS fingerprint ({}): {tls_fp_r}", names::TLS_JA4_R);

    // Expected TLS fingerprint for reqwest client (same for HTTP/1.1 and HTTP/2)
    const EXPECTED_TLS_FINGERPRINT_HTTP2: &str = "t13i1010h2_61a7ad8aa9b6_3a8073edd8ef";
    assert_eq!(
        tls_fp, EXPECTED_TLS_FINGERPRINT_HTTP2,
        "TLS fingerprint should match expected value for reqwest HTTP/2 client"
    );

    // Verify consistency: same client should produce same fingerprints
    let response2 = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send second HTTP/2 request: {e}"))?;
    let body2: serde_json::Value = response2
        .json()
        .await
        .map_err(|e| format!("Failed to parse second HTTP/2 response as JSON: {e}"))?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Second HTTP/2 response should contain headers object")?;
    let http2_fp2 = headers2
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be a string in second request")?;
    let tls_fp2 = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string in second request")?;

    assert_eq!(
        http2_fp, http2_fp2,
        "HTTP/2 fingerprint should be consistent across multiple requests from the same client"
    );
    assert_eq!(
        http2_fp2, EXPECTED_HTTP2_FINGERPRINT,
        "Second request HTTP/2 fingerprint should also match expected value"
    );
    assert_eq!(
        tls_fp, tls_fp2,
        "TLS fingerprint should be consistent across multiple requests from the same client"
    );
    assert_eq!(
        tls_fp2, EXPECTED_TLS_FINGERPRINT_HTTP2,
        "Second request TLS fingerprint should also match expected value"
    );

    Ok(())
}

#[tokio::test]
async fn test_fingerprinting_disabled_per_route(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    // Request to /static route (fingerprinting disabled)
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/static/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    // Fingerprint headers should NOT be present for /static route
    assert!(
        !headers.contains_key(names::TLS_JA4),
        "TLS JA4 header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key(names::TLS_JA4_R),
        "TLS JA4_r header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key(names::TLS_JA4_O),
        "TLS JA4_o header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key(names::TLS_JA4_OR),
        "TLS JA4_or header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key(names::HTTP2_AKAMAI),
        "HTTP/2 fingerprint header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint header should NOT be present when fingerprinting is disabled for route"
    );

    // Request to /api route (fingerprinting enabled)
    let response2 = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);

    let body2: serde_json::Value = response2
        .json()
        .await
        .map_err(|e| format!("Failed to parse /api response as JSON: {e}"))?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("/api response should contain headers object")?;

    // Fingerprint headers SHOULD be present for /api route
    assert!(
        headers2.contains_key(names::TLS_JA4),
        "TLS JA4 header should be present when fingerprinting is enabled for route"
    );
    assert!(
        headers2.contains_key(names::TLS_JA4_R),
        "TLS JA4_r header should be present when fingerprinting is enabled for route"
    );
    assert!(
        headers2.contains_key(names::TLS_JA4_O),
        "TLS JA4_o header should be present when fingerprinting is enabled for route"
    );
    assert!(
        headers2.contains_key(names::TLS_JA4_OR),
        "TLS JA4_or header should be present when fingerprinting is enabled for route"
    );
    // TCP SYN fingerprint is injected on every request of the connection (same SYN, same fingerprint).
    assert!(
        headers2.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint should be present on keep-alive request to /api (same TCP connection)"
    );

    Ok(())
}

// ── IPv6 variants ────────────────────────────────────────────────────────────

/// Verify that TLS + TCP SYN fingerprinting works identically over an IPv6 connection.
/// The TCP SYN fingerprint must carry the `6:` IP-version prefix.
#[tokio::test]
async fn test_tls_fingerprint_injection_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV6)
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    // TLS fingerprint must be present
    assert!(
        headers.contains_key(names::TLS_JA4),
        "TLS JA4 header should be present over IPv6"
    );
    assert!(
        headers.contains_key(names::TLS_JA4_R),
        "TLS JA4_r header should be present over IPv6"
    );
    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS JA4 header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS JA4 fingerprint should not be empty");
    assert!(tls_fp.starts_with('t'), "TLS fingerprint should start with 't'");
    println!("IPv6 TLS fingerprint ({}): {tls_fp}", names::TLS_JA4);

    // TCP SYN fingerprint must be present and use IPv6 prefix
    assert!(
        headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint header should be present on IPv6 connection"
    );
    let tcp_fp = headers
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint header should be a string")?;
    assert!(!tcp_fp.is_empty(), "TCP SYN fingerprint should not be empty");
    assert!(
        tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint must use '6:' prefix for IPv6 connections; got: {tcp_fp}"
    );
    assert_eq!(
        tcp_fp.split(':').count(),
        8,
        "TCP SYN fingerprint must have 8 colon-separated fields; got: {tcp_fp}"
    );
    println!("IPv6 TCP SYN fingerprint ({}): {tcp_fp}", names::TCP_SYN);

    // HTTP/2 fingerprint must NOT be present (HTTP/1.1 client)
    assert!(
        !headers.contains_key(names::HTTP2_AKAMAI),
        "HTTP/2 fingerprint should NOT be present for HTTP/1.1 connection"
    );

    Ok(())
}

/// HTTP/2 + TLS fingerprinting over IPv6: Akamai fingerprint present,
/// TCP SYN fingerprint carries the `6:` prefix.
#[tokio::test]
async fn test_http2_fingerprint_injection_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV6)
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP/2 request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    assert!(
        headers.contains_key(names::HTTP2_AKAMAI),
        "HTTP/2 Akamai fingerprint should be present over IPv6"
    );
    let http2_fp = headers
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be a string")?;
    assert!(!http2_fp.is_empty(), "HTTP/2 fingerprint should not be empty");
    assert!(http2_fp.contains('|'), "HTTP/2 fingerprint should contain pipe separator");
    println!("IPv6 HTTP/2 fingerprint ({}): {http2_fp}", names::HTTP2_AKAMAI);

    assert!(
        headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint should be present on IPv6 HTTP/2 connection"
    );
    let tcp_fp = headers
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint header should be a string")?;
    assert!(
        tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint must use '6:' prefix for IPv6 connections; got: {tcp_fp}"
    );
    println!("IPv6 TCP SYN fingerprint ({}): {tcp_fp}", names::TCP_SYN);

    Ok(())
}

/// Fingerprinting disabled / enabled per route works the same over IPv6.
#[tokio::test]
async fn test_fingerprinting_disabled_per_route_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    // /static route — fingerprinting disabled
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/static/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /static over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = response.json().await?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers")?;
    assert!(
        !headers.contains_key(names::TLS_JA4),
        "TLS JA4 should NOT be present when fingerprinting is disabled"
    );
    assert!(
        !headers.contains_key(names::TCP_SYN),
        "TCP SYN should NOT be present when fingerprinting is disabled"
    );

    // /api route — fingerprinting enabled
    let response2 = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api over IPv6: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let body2: serde_json::Value = response2.json().await?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("/api response should contain headers")?;
    assert!(
        headers2.contains_key(names::TLS_JA4),
        "TLS JA4 should be present when fingerprinting is enabled"
    );
    assert!(
        headers2.contains_key(names::TCP_SYN),
        "TCP SYN should be present when fingerprinting is enabled over IPv6"
    );
    let tcp_fp = headers2
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint should be a string")?;
    assert!(
        tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint must use '6:' prefix for IPv6 connections; got: {tcp_fp}"
    );

    Ok(())
}
