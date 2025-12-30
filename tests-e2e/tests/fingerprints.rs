use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_tls_fingerprint_injection() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
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

    // Check for TLS fingerprint header
    assert!(
        headers.contains_key("x-huginn-net-tls"),
        "TLS fingerprint header should be present"
    );

    let tls_fp = headers
        .get("x-huginn-net-tls")
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");
    Ok(())
}

#[tokio::test]
async fn test_http2_fingerprint_injection() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    // HTTP/2 fingerprint only works for HTTP/2 connections
    // This test would need an HTTP/2 client
    // For now, we just verify the proxy accepts HTTP/2 connections
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
    Ok(())
}
