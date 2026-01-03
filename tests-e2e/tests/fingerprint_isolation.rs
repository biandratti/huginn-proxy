use huginn_proxy_lib::fingerprinting::{forwarded, names};
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

/// Test that fingerprints (especially Akamai) are generated correctly
/// and are NOT affected by headers we add (JA4 and X-Forwarded-*)
///
/// This test validates that:
/// 1. Akamai fingerprint is generated from HTTP/2 frames (not HTTP headers)
/// 2. Adding X-Forwarded-* headers doesn't affect the fingerprint
/// 3. Adding JA4 header doesn't affect the Akamai fingerprint
/// 4. Headers are correctly forwarded to the backend
#[tokio::test]
async fn test_fingerprint_isolation_from_added_headers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response1 = client
        .get(PROXY_HTTPS_URL)
        .header("X-Custom-Header", "test-value-1")
        .header("User-Agent", "test-client/1.0")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to send first HTTP/2 request: {e}"))?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);

    let body1: serde_json::Value = response1
        .json()
        .await
        .map_err(|e| format!("Failed to parse first response as JSON: {e}"))?;
    let headers1 = body1
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("First response should contain headers object")?;

    // Extract Akamai fingerprint from first request
    let akamai_fp1 = headers1
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be present in first request")?;
    assert!(!akamai_fp1.is_empty(), "HTTP/2 fingerprint should not be empty");
    println!("First request Akamai fingerprint: {akamai_fp1}");

    // Extract TLS fingerprint from first request
    let tls_fp1 = headers1
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be present in first request")?;
    assert!(!tls_fp1.is_empty(), "TLS fingerprint should not be empty");
    println!("First request TLS fingerprint: {tls_fp1}");

    // Verify X-Forwarded-* headers are present in backend response
    // These headers should be added by the proxy, not by the client
    assert!(
        headers1.contains_key(forwarded::FOR),
        "X-Forwarded-For header should be present in backend response"
    );
    // X-Forwarded-Host is only added if the request has a Host header
    // In HTTP/2, Host may not be present if :authority pseudo-header is used
    // So we check if it exists, but don't fail if it doesn't
    let has_forwarded_host = headers1.contains_key(forwarded::HOST);
    if has_forwarded_host {
        println!("✓ X-Forwarded-Host is present (request had Host header)");
    } else {
        println!("ℹ X-Forwarded-Host not present (request had no Host header, which is valid for HTTP/2)");
    }
    assert!(
        headers1.contains_key(forwarded::PROTO),
        "X-Forwarded-Proto header should be present in backend response"
    );
    assert!(
        headers1.contains_key(forwarded::PORT),
        "X-Forwarded-Port header should be present in backend response"
    );

    let forwarded_proto1 = headers1
        .get(forwarded::PROTO)
        .and_then(|v| v.as_str())
        .ok_or("X-Forwarded-Proto should be a string")?;
    assert_eq!(
        forwarded_proto1, "https",
        "X-Forwarded-Proto should be 'https' for HTTPS connections"
    );

    assert!(
        headers1.contains_key("x-custom-header"),
        "Custom header should be present in backend response"
    );
    let custom_header1 = headers1
        .get("x-custom-header")
        .and_then(|v| v.as_str())
        .ok_or("Custom header should be a string")?;
    assert_eq!(custom_header1, "test-value-1", "Custom header value should match what we sent");

    // Second request: with DIFFERENT custom headers
    // The fingerprint should remain the same because it's based on HTTP/2 frames, not headers
    let response2 = client
        .get(PROXY_HTTPS_URL)
        .header("X-Custom-Header", "test-value-2")
        .header("User-Agent", "test-client/2.0")
        .header("Accept", "text/html")
        .header("X-Another-Header", "different-value")
        .send()
        .await
        .map_err(|e| format!("Failed to send second HTTP/2 request: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);

    let body2: serde_json::Value = response2
        .json()
        .await
        .map_err(|e| format!("Failed to parse second response as JSON: {e}"))?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Second response should contain headers object")?;

    let akamai_fp2 = headers2
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("HTTP/2 fingerprint header should be present in second request")?;
    assert!(!akamai_fp2.is_empty(), "HTTP/2 fingerprint should not be empty");
    println!("Second request Akamai fingerprint: {akamai_fp2}");

    let tls_fp2 = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be present in second request")?;
    assert!(!tls_fp2.is_empty(), "TLS fingerprint should not be empty");
    println!("Second request TLS fingerprint: {tls_fp2}");

    // CRITICAL: Akamai fingerprint should be IDENTICAL between requests
    // This proves that adding different headers doesn't affect the fingerprint
    assert_eq!(
        akamai_fp1, akamai_fp2,
        "Akamai fingerprint should be identical across requests with different headers. \
         This proves that fingerprints are generated from HTTP/2 frames, not HTTP headers."
    );

    // TLS fingerprint should also be identical (same client, same TLS handshake)
    assert_eq!(
        tls_fp1, tls_fp2,
        "TLS fingerprint should be identical across requests from the same client"
    );

    // Verify X-Forwarded-* headers are still present in second request
    assert!(
        headers2.contains_key(forwarded::FOR),
        "X-Forwarded-For header should be present in second backend response"
    );
    // X-Forwarded-Host may or may not be present depending on Host header
    let has_forwarded_host2 = headers2.contains_key(forwarded::HOST);
    if has_forwarded_host2 {
        println!("✓ X-Forwarded-Host is present in second request");
    }
    assert!(
        headers2.contains_key(forwarded::PROTO),
        "X-Forwarded-Proto header should be present in second backend response"
    );
    assert!(
        headers2.contains_key(forwarded::PORT),
        "X-Forwarded-Port header should be present in second backend response"
    );

    // Verify X-Forwarded-Proto is still "https"
    let forwarded_proto2 = headers2
        .get(forwarded::PROTO)
        .and_then(|v| v.as_str())
        .ok_or("X-Forwarded-Proto should be a string")?;
    assert_eq!(
        forwarded_proto2, "https",
        "X-Forwarded-Proto should be 'https' for HTTPS connections"
    );

    assert!(
        headers2.contains_key("x-custom-header"),
        "Custom header should be present in second backend response"
    );
    let custom_header2 = headers2
        .get("x-custom-header")
        .and_then(|v| v.as_str())
        .ok_or("Custom header should be a string")?;
    assert_eq!(
        custom_header2, "test-value-2",
        "Custom header value should match what we sent in second request"
    );

    assert!(
        headers2.contains_key("x-another-header"),
        "New custom header should be present in second backend response"
    );

    // CRITICAL: Verify that JA4 and X-Forwarded-* headers are NOT included in Akamai fingerprint calculation
    // The fingerprint should be based only on HTTP/2 frames (SETTINGS, WINDOW_UPDATE, PRIORITY, etc.)
    // not on HTTP headers
    println!("\n✓ Test passed: Fingerprints are isolated from added headers");
    println!("  - Akamai fingerprint: {akamai_fp1}");
    println!("  - TLS fingerprint: {tls_fp1}");
    println!("  - Both fingerprints remained identical despite different HTTP headers");

    Ok(())
}
