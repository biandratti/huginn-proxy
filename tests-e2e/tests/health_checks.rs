use tests_e2e::common::{wait_for_service, DEFAULT_HEALTH_CHECK_TIMEOUT_SECS, METRICS_URL};

#[tokio::test]
async fn test_health_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/health"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Health endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/health"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /health: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_ready_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/ready"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Ready endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/ready"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /ready: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_live_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/live"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS).await?,
        "Live endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/live"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /live: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_metrics_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Metrics endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /metrics: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    assert!(
        body.contains("huginn_") || body.contains("# TYPE"),
        "Should contain metrics format"
    );
    Ok(())
}
