use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_proxy_forwarding() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
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
    assert!(body.get("path").is_some());
    assert!(body.get("headers").is_some());
    Ok(())
}

#[tokio::test]
async fn test_path_routing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test /api route (should go to backend-a)
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api/test: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    // Test default route (should go to backend-b)
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/other"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /other: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_https_proxy() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(wait_for_service(PROXY_HTTPS_URL, 60).await?, "HTTPS proxy should be ready");

    let response = client
        .get(PROXY_HTTPS_URL)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}
