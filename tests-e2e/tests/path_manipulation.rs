use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_path_stripping() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping: /strip/users/123 → /users/123
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/strip/users/123"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    // The backend echo server returns the path it received
    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the prefix was stripped
    assert_eq!(path, "/users/123", "Path prefix should be stripped");

    Ok(())
}

#[tokio::test]
async fn test_path_stripping_with_query_params(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping with query parameters
    // /strip/api/data?id=123&name=test → /api/data?id=123&name=test
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/strip/api/data?id=123&name=test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the prefix was stripped and query params are preserved
    assert_eq!(path, "/api/data", "Path prefix should be stripped");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path rewriting: /old/data/file.txt → /new/data/file.txt
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/old/data/file.txt"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the prefix was replaced
    assert_eq!(path, "/new/data/file.txt", "Path should be rewritten");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting_with_query_params(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path rewriting with query parameters
    // /old/endpoint?param=value → /new/endpoint?param=value
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/old/endpoint?param=value&foo=bar"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the prefix was replaced and query params are preserved
    assert_eq!(path, "/new/endpoint", "Path should be rewritten");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting_to_versioned_api(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path rewriting to versioned API
    // /v1/users → /api/v1/users
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/v1/users"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the path was rewritten to versioned API format
    assert_eq!(path, "/api/v1/users", "Path should be rewritten to versioned API");

    Ok(())
}

#[tokio::test]
async fn test_path_manipulation_preserves_headers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test that path manipulation preserves custom headers
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/strip/test"))
        .header("X-Custom-Header", "test-value")
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

    // Verify custom header was preserved
    assert!(
        headers.contains_key("x-custom-header"),
        "Custom headers should be preserved during path manipulation"
    );

    let custom_header = headers
        .get("x-custom-header")
        .and_then(|v| v.as_str())
        .ok_or("Custom header should be present")?;

    assert_eq!(custom_header, "test-value", "Custom header value should match");

    Ok(())
}

#[tokio::test]
async fn test_no_path_manipulation_route() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test route without path manipulation (should preserve original path)
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // Verify the path was NOT modified
    assert_eq!(
        path, "/api/test",
        "Path should not be modified for routes without path manipulation"
    );

    Ok(())
}

#[tokio::test]
async fn test_path_stripping_exact_prefix() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping when request path exactly matches prefix
    // /strip → / (empty path becomes root)
    let response = client
        .get(format!("{PROXY_HTTPS_URL}/strip"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;

    let path = body
        .get("path")
        .and_then(|p| p.as_str())
        .ok_or("Response should contain path")?;

    // When prefix is stripped and nothing remains, should be root path
    assert_eq!(path, "/", "Empty path after stripping should become root");

    Ok(())
}
