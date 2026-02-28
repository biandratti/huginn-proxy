use huginn_proxy_lib::fingerprinting::{forwarded, names};
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

/// Test that injected headers always override client-provided headers with the same names
/// This prevents clients from manipulating fingerprints or X-Forwarded-* headers
///
/// This test validates that:
/// 1. JA4 fingerprint header always overrides any client-provided value
/// 2. Akamai fingerprint header always overrides any client-provided value
/// 3. X-Forwarded-* headers always override any client-provided values (or append correctly for X-Forwarded-For)
/// 4. Clients cannot manipulate or spoof these security-critical headers
#[tokio::test]
async fn test_injected_headers_override_client_headers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create HTTP/2 client
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    // Send request with malicious/spoofed headers that match our injected header names.
    // Host: evil.example.com and X-Forwarded-Host: spoofed-... are both ignored by the proxy.
    // X-Forwarded-Host is derived exclusively from the TLS SNI, which is not client-controllable.
    let response = client
        .get(PROXY_HTTPS_URL)
        .header(names::TLS_JA4, "t13d9999h2_fake_fingerprint_12345")
        .header(names::HTTP2_AKAMAI, "999:999;999:999|9999999|999|fake")
        .header("Host", "evil.example.com")
        .header(forwarded::FOR, "192.168.1.100")
        .header(forwarded::HOST, "spoofed-x-forwarded-host.example.com")
        .header(forwarded::PORT, "9999")
        .header(forwarded::PROTO, "http")
        .send()
        .await
        .map_err(|e| format!("Failed to send request with spoofed headers: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    // CRITICAL: Verify JA4 fingerprint is our real value, not the spoofed one
    assert!(headers.contains_key(names::TLS_JA4), "JA4 fingerprint header should be present");
    let ja4_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("JA4 fingerprint header should be a string")?;
    assert!(!ja4_fp.is_empty(), "JA4 fingerprint should not be empty");
    assert_ne!(
        ja4_fp, "t13d9999h2_fake_fingerprint_12345",
        "JA4 fingerprint should NOT be the spoofed value from client. \
         Our injected value must always override client-provided values."
    );
    assert!(
        ja4_fp.starts_with("t13"),
        "JA4 fingerprint should be a valid fingerprint starting with 't13'"
    );
    println!("✓ JA4 fingerprint correctly overridden: {ja4_fp}");

    // CRITICAL: Verify Akamai fingerprint is our real value, not the spoofed one
    assert!(
        headers.contains_key(names::HTTP2_AKAMAI),
        "Akamai fingerprint header should be present"
    );
    let akamai_fp = headers
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai fingerprint header should be a string")?;
    assert!(!akamai_fp.is_empty(), "Akamai fingerprint should not be empty");
    assert_ne!(
        akamai_fp, "999:999;999:999|9999999|999|fake",
        "Akamai fingerprint should NOT be the spoofed value from client. \
         Our injected value must always override client-provided values."
    );
    assert!(
        akamai_fp.contains('|'),
        "Akamai fingerprint should be a valid fingerprint containing pipe separator"
    );
    println!("✓ Akamai fingerprint correctly overridden: {akamai_fp}");

    // CRITICAL: Verify X-Forwarded-For is correctly handled
    // Note: X-Forwarded-For appends the client IP (standard proxy behavior), so it should contain both the spoofed value and the real IP
    assert!(headers.contains_key(forwarded::FOR), "X-Forwarded-For header should be present");
    let forwarded_for = headers
        .get(forwarded::FOR)
        .and_then(|v| v.as_str())
        .ok_or("X-Forwarded-For should be a string")?;
    // X-Forwarded-For should contain the real client IP (from peer SocketAddr)
    // Standard proxy behavior: append real IP to existing header (comma-separated)
    // Format should be: "spoofed-value, real-ip" or just "real-ip" if no spoofed value
    // In Docker, the real IP will be the container IP (e.g., 172.20.0.1), not localhost
    // So we check that it contains the spoofed value AND a different IP (the real one)
    assert!(
        forwarded_for.contains("192.168.1.100"),
        "X-Forwarded-For should contain the spoofed value from client. Current value: {forwarded_for}"
    );
    // The real IP will be appended after the spoofed one
    let parts: Vec<&str> = forwarded_for.split(',').map(|s| s.trim()).collect();
    assert!(
        parts.len() >= 2,
        "X-Forwarded-For should contain at least 2 IPs (spoofed + real). Current value: {forwarded_for}"
    );
    // The last part should be the real IP (most recent proxy in chain)
    // Safe to unwrap because we asserted parts.len() >= 2 above
    let real_ip = match parts.last() {
        Some(ip) => ip,
        None => {
            return Err("X-Forwarded-For should contain at least 2 IPs (asserted above but parts.last() returned None)".into());
        }
    };
    assert_ne!(
        *real_ip, "192.168.1.100",
        "X-Forwarded-For should end with the real client IP (not the spoofed one). \
         Current value: {forwarded_for}, Real IP: {real_ip}"
    );
    // Verify the real IP is a valid IP format (contains dots or colons)
    assert!(
        real_ip.contains('.') || real_ip.contains(':'),
        "Real IP should be a valid IP address format. Current value: {forwarded_for}, Real IP: {real_ip}"
    );
    println!("✓ X-Forwarded-For correctly handled (spoofed value: 192.168.1.100, real IP appended: {real_ip}): {forwarded_for}");

    // CRITICAL: Verify X-Forwarded-Host is set from the TLS SNI, not from any client-controlled header.
    // The client sent Host: evil.example.com and X-Forwarded-Host: spoofed-x-forwarded-host.example.com,
    // but the proxy must ignore both and use the SNI from the TLS ClientHello instead.
    // SNI ("localhost" for this test connection) cannot be overridden by HTTP headers.
    let forwarded_host = if headers.contains_key(forwarded::HOST) {
        let host = headers
            .get(forwarded::HOST)
            .and_then(|v| v.as_str())
            .ok_or("X-Forwarded-Host should be a string")?;
        assert_ne!(
            host, "spoofed-x-forwarded-host.example.com",
            "X-Forwarded-Host must NOT be the spoofed X-Forwarded-Host value from the client."
        );
        assert_ne!(
            host, "evil.example.com",
            "X-Forwarded-Host must NOT be taken from the spoofed Host header."
        );
        assert_eq!(
            host, "localhost",
            "X-Forwarded-Host should be the TLS SNI value (localhost), not any client-supplied header. Current value: {host}"
        );
        println!("✓ X-Forwarded-Host correctly uses TLS SNI (overrides spoofed Host and X-Forwarded-Host headers): {host}");
        Some(host)
    } else {
        println!("i X-Forwarded-Host not present (only set when TLS SNI is available)");
        None
    };

    // CRITICAL: Verify X-Forwarded-Port is our value (from peer SocketAddr), not the spoofed one
    assert!(
        headers.contains_key(forwarded::PORT),
        "X-Forwarded-Port header should be present"
    );
    let forwarded_port = headers
        .get(forwarded::PORT)
        .and_then(|v| v.as_str())
        .ok_or("X-Forwarded-Port should be a string")?;
    assert_ne!(
        forwarded_port, "9999",
        "X-Forwarded-Port should NOT be the spoofed value from client. \
         Our injected value (from peer SocketAddr) must always override client-provided values."
    );
    // X-Forwarded-Port should be a valid port number (not 9999)
    assert!(
        forwarded_port != "9999" && !forwarded_port.is_empty(),
        "X-Forwarded-Port should be the real port value"
    );
    println!("✓ X-Forwarded-Port correctly overridden: {forwarded_port}");

    // CRITICAL: Verify X-Forwarded-Proto is our value (based on is_https), not the spoofed one
    assert!(
        headers.contains_key(forwarded::PROTO),
        "X-Forwarded-Proto header should be present"
    );
    let forwarded_proto = headers
        .get(forwarded::PROTO)
        .and_then(|v| v.as_str())
        .ok_or("X-Forwarded-Proto should be a string")?;
    assert_eq!(
        forwarded_proto, "https",
        "X-Forwarded-Proto should be 'https' (our injected value), NOT the spoofed 'http' value from client. \
         Our injected value must always override client-provided values."
    );
    println!("✓ X-Forwarded-Proto correctly overridden: {forwarded_proto}");

    println!("\n✓ Test passed: All injected headers correctly override client-provided values");
    println!("  - JA4 fingerprint: {ja4_fp}");
    println!("  - Akamai fingerprint: {akamai_fp}");
    println!("  - X-Forwarded-For: {forwarded_for}");
    if let Some(host) = forwarded_host {
        println!("  - X-Forwarded-Host: {host}");
    } else {
        println!("  - X-Forwarded-Host: (not present - valid for HTTP/2)");
    }
    println!("  - X-Forwarded-Port: {forwarded_port}");
    println!("  - X-Forwarded-Proto: {forwarded_proto}");
    println!("\n✓ Security: Clients cannot manipulate or spoof security-critical headers");

    Ok(())
}

/// Test that multiple requests with different spoofed headers always result in the same fingerprints
/// This further validates that fingerprints are not affected by client-provided headers
#[tokio::test]
async fn test_fingerprints_consistent_despite_spoofed_headers(
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

    // First request with spoofed headers
    let response1 = client
        .get(PROXY_HTTPS_URL)
        .header(names::TLS_JA4, "spoofed-ja4-1")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-1")
        .send()
        .await
        .map_err(|e| format!("Failed to send first request: {e}"))?;

    let body1: serde_json::Value = response1.json().await?;
    let headers1 = body1
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Headers missing")?;
    let ja4_1 = headers1
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("JA4 missing")?;
    let akamai_1 = headers1
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai missing")?;

    // Second request with DIFFERENT spoofed headers
    let response2 = client
        .get(PROXY_HTTPS_URL)
        .header(names::TLS_JA4, "spoofed-ja4-2")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-2")
        .send()
        .await
        .map_err(|e| format!("Failed to send second request: {e}"))?;

    let body2: serde_json::Value = response2.json().await?;
    let headers2 = body2
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Headers missing")?;
    let ja4_2 = headers2
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("JA4 missing")?;
    let akamai_2 = headers2
        .get(names::HTTP2_AKAMAI)
        .and_then(|v| v.as_str())
        .ok_or("Akamai missing")?;

    assert_eq!(
        ja4_1, ja4_2,
        "JA4 fingerprint should be identical despite different spoofed headers"
    );
    assert_eq!(
        akamai_1, akamai_2,
        "Akamai fingerprint should be identical despite different spoofed headers"
    );

    // Verify they are NOT the spoofed values
    assert_ne!(ja4_1, "spoofed-ja4-1", "JA4 should not be spoofed value 1");
    assert_ne!(ja4_1, "spoofed-ja4-2", "JA4 should not be spoofed value 2");
    assert_ne!(akamai_1, "spoofed-akamai-1", "Akamai should not be spoofed value 1");
    assert_ne!(akamai_1, "spoofed-akamai-2", "Akamai should not be spoofed value 2");

    println!("\n✓ Test passed: Fingerprints remain consistent despite different spoofed headers");
    println!("  - JA4: {ja4_1}");
    println!("  - Akamai: {akamai_1}");

    Ok(())
}
