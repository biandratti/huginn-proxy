use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

async fn test_proxy_forwarding_impl(
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
    let response = client
        .get(url)
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
async fn test_proxy_forwarding() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_proxy_forwarding_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
async fn test_proxy_forwarding_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_proxy_forwarding_impl(PROXY_HTTPS_URL_IPV6).await
}

async fn test_path_routing_impl(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
    let response = client
        .get(format!("{url}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /api/test: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let response = client
        .get(format!("{url}/other"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /other: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_path_routing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_path_routing_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
async fn test_path_routing_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_path_routing_impl(PROXY_HTTPS_URL_IPV6).await
}

async fn test_https_proxy_impl(url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_https_proxy() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_https_proxy_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
async fn test_https_proxy_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_https_proxy_impl(PROXY_HTTPS_URL_IPV6).await
}
