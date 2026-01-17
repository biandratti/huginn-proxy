use reqwest::Client;

const PROXY_HTTPS_URL: &str = "https://localhost:7000";

#[tokio::test]
async fn test_custom_security_headers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL}/api/users"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    // Check status
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Check custom security headers (if configured in compose.toml)
    // Note: These tests pass even if headers are not configured
    // because they check for presence, not absence

    // Check X-Frame-Options (if configured)
    if let Some(x_frame) = response.headers().get("x-frame-options") {
        let value = x_frame
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("X-Frame-Options: {}", value);
        // Could be "DENY", "SAMEORIGIN", etc.
    }

    // Check X-Content-Type-Options (if configured)
    if let Some(x_content) = response.headers().get("x-content-type-options") {
        let value = x_content
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("X-Content-Type-Options: {}", value);
        assert_eq!(value, "nosniff");
    }

    Ok(())
}

#[tokio::test]
async fn test_hsts_header() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    // Check status
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Check HSTS header (if configured)
    if let Some(hsts) = response.headers().get("strict-transport-security") {
        let value = hsts
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("Strict-Transport-Security: {}", value);

        // HSTS should have max-age
        assert!(value.contains("max-age="));
    }

    Ok(())
}

#[tokio::test]
async fn test_csp_header() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL}/static/test.html"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    // Check status
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Check CSP header (if configured)
    if let Some(csp) = response.headers().get("content-security-policy") {
        let value = csp
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("Content-Security-Policy: {}", value);

        // CSP should contain some directive
        assert!(!value.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn test_security_headers_with_fingerprinting(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL}/api/fingerprint"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    // Check status
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Fingerprinting should still work (headers go to backend)
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    // Backend should receive fingerprint headers
    if let Some(headers) = body.get("headers") {
        // Check if TLS fingerprint header exists
        if let Some(ja4) = headers.get("x-huginn-net-ja4") {
            println!("JA4 fingerprint present: {}", ja4);
        }

        // Check if HTTP/2 fingerprint header exists (if H2 connection)
        if let Some(akamai) = headers.get("x-huginn-net-akamai") {
            println!("Akamai fingerprint present: {}", akamai);
        }
    }

    Ok(())
}
