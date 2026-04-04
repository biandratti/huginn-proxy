//! E2E tests for load balancing

use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

async fn test_round_robin_load_balancing_impl(
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
    for _ in 0..10 {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {e}"))?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }
    Ok(())
}

#[tokio::test]
async fn test_round_robin_load_balancing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_round_robin_load_balancing_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
async fn test_round_robin_load_balancing_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_round_robin_load_balancing_impl(PROXY_HTTPS_URL_IPV6).await
}
