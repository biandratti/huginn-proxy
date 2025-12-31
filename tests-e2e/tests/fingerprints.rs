use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

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
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL)
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

    // Check for TLS fingerprint header (should be present for all TLS connections)
    assert!(
        headers.contains_key("x-huginn-net-tls"),
        "TLS fingerprint header should be present"
    );

    let tls_fp = headers
        .get("x-huginn-net-tls")
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint (x-huginn-net-tls): {tls_fp}");

    assert!(tls_fp.starts_with('t'), "TLS fingerprint should start with 't'");
    assert!(tls_fp.contains('_'), "TLS fingerprint should contain underscore separators");

    // Expected TLS fingerprint for reqwest client (HTTP/1.1)
    // Note: When HTTP/1.1 is forced, the fingerprint ends with 'h1' instead of 'h2'
    const EXPECTED_TLS_FINGERPRINT: &str = "t13d1011h1_61a7ad8aa9b6_3a8073edd8ef";
    assert_eq!(
        tls_fp, EXPECTED_TLS_FINGERPRINT,
        "TLS fingerprint should match expected value for reqwest HTTP/1.1 client"
    );

    // Verify consistency: same client should produce same fingerprint
    let response2 = client
        .get(PROXY_HTTPS_URL)
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
        .get("x-huginn-net-tls")
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
        !headers.contains_key("x-huginn-net-http"),
        "HTTP/2 fingerprint header should NOT be present in HTTP/1.1 connection"
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
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL)
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
        headers.contains_key("x-huginn-net-http"),
        "HTTP/2 fingerprint header should be present"
    );

    let http2_fp = headers
        .get("x-huginn-net-http")
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be a string")?;
    assert!(!http2_fp.is_empty(), "HTTP/2 fingerprint should not be empty");

    println!("HTTP/2 fingerprint (x-huginn-net-http): {http2_fp}");

    assert!(http2_fp.contains('|'), "HTTP/2 fingerprint should contain pipe separator");

    // Expected HTTP/2 fingerprint for reqwest client with HTTP/2
    const EXPECTED_HTTP2_FINGERPRINT: &str = "2:0;4:2097152;5:16384;6:16384|5177345|0|";
    assert_eq!(
        http2_fp, EXPECTED_HTTP2_FINGERPRINT,
        "HTTP/2 fingerprint should match expected value for reqwest HTTP/2 client"
    );

    // Also verify TLS fingerprint is present (all TLS connections should have it)
    assert!(
        headers.contains_key("x-huginn-net-tls"),
        "TLS fingerprint header should be present in HTTP/2 connection"
    );

    let tls_fp = headers
        .get("x-huginn-net-tls")
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint (x-huginn-net-tls): {tls_fp}");

    // Expected TLS fingerprint for reqwest client (same for HTTP/1.1 and HTTP/2)
    const EXPECTED_TLS_FINGERPRINT_HTTP2: &str = "t13d1011h2_61a7ad8aa9b6_3a8073edd8ef";
    assert_eq!(
        tls_fp, EXPECTED_TLS_FINGERPRINT_HTTP2,
        "TLS fingerprint should match expected value for reqwest HTTP/2 client"
    );

    // Verify consistency: same client should produce same fingerprints
    let response2 = client
        .get(PROXY_HTTPS_URL)
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
        .get("x-huginn-net-http")
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be a string in second request")?;
    let tls_fp2 = headers2
        .get("x-huginn-net-tls")
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
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    // Request to /static route (fingerprinting disabled)
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/static/test"))
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
        !headers.contains_key("x-huginn-net-tls"),
        "TLS fingerprint header should NOT be present when fingerprinting is disabled for route"
    );
    assert!(
        !headers.contains_key("x-huginn-net-http"),
        "HTTP/2 fingerprint header should NOT be present when fingerprinting is disabled for route"
    );

    // Request to /api route (fingerprinting enabled)
    let response2 = client
        .get(format!("{PROXY_HTTPS_URL}/api/test"))
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
        headers2.contains_key("x-huginn-net-tls"),
        "TLS fingerprint header should be present when fingerprinting is enabled for route"
    );

    Ok(())
}
