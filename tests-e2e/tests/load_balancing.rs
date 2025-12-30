//! E2E tests for load balancing

use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_round_robin_load_balancing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Make multiple requests and verify they're distributed
    // Note: This is a basic test - a more thorough test would track which backend
    // received each request (requires backend identification)
    for _ in 0..10 {
        let response = client
            .get(PROXY_HTTPS_URL)
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {e}"))?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
    Ok(())
}
