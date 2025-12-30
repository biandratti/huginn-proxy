
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_tls_termination() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?, "HTTPS proxy should be ready");

    let response = client
        .get(PROXY_HTTPS_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_tls_hot_reload() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This test would:
    // 1. Make a request to verify TLS works
    // 2. Replace the certificate files
    // 3. Wait for hot reload delay
    // 4. Make another request to verify new cert is used
    //
    // For now, this is a placeholder - full implementation would require
    // file manipulation in the Docker container
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?, "HTTPS proxy should be ready");

    let response = client
        .get(PROXY_HTTPS_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}
