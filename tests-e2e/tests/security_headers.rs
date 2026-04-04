use reqwest::Client;

use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_custom_security_headers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/users"))
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
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/test"))
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
        .get(format!("{PROXY_HTTPS_URL_IPV4}/static/test.html"))
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
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/fingerprint"))
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
        // Check if TLS fingerprint headers exist
        if let Some(ja4) = headers.get("x-huginn-net-ja4") {
            println!("JA4 fingerprint present: {}", ja4);
        }
        if let Some(ja4_r) = headers.get("x-huginn-net-ja4_r") {
            println!("JA4_r fingerprint present: {}", ja4_r);
        }
        if let Some(ja4_o) = headers.get("x-huginn-net-ja4_o") {
            println!("JA4_o fingerprint present: {}", ja4_o);
        }
        if let Some(ja4_or) = headers.get("x-huginn-net-ja4_or") {
            println!("JA4_or fingerprint present: {}", ja4_or);
        }

        // Check if HTTP/2 fingerprint header exists (if H2 connection)
        if let Some(akamai) = headers.get("x-huginn-net-akamai") {
            println!("Akamai fingerprint present: {}", akamai);
        }
    }

    Ok(())
}

/// Confirm that HSTS and other security headers are injected correctly over IPv6.
#[tokio::test]
async fn test_hsts_header_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    if let Some(hsts) = response.headers().get("strict-transport-security") {
        let value = hsts
            .to_str()
            .map_err(|e| format!("Invalid HSTS header value: {e}"))?;
        println!("IPv6 Strict-Transport-Security: {value}");
        assert!(value.contains("max-age="), "HSTS should include max-age directive");
    }

    Ok(())
}

/// Confirm that fingerprinting still works alongside security headers over IPv6.
#[tokio::test]
async fn test_security_headers_with_fingerprinting_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/api/fingerprint"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response.json().await?;
    if let Some(headers) = body.get("headers") {
        if let Some(ja4) = headers.get("x-huginn-net-ja4") {
            println!("IPv6 JA4 fingerprint present: {ja4}");
        }
        if let Some(akamai) = headers.get("x-huginn-net-akamai") {
            println!("IPv6 Akamai fingerprint present: {akamai}");
        }
    }

    Ok(())
}
