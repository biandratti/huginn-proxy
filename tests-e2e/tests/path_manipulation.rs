use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_path_stripping() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping: /strip/users/123 → /users/123
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/strip/users/123"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/users/123", "Path prefix should be stripped");

    Ok(())
}

#[tokio::test]
async fn test_path_stripping_with_query_params(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping with query parameters
    // /strip/api/data?id=123&name=test → /api/data?id=123&name=test
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/strip/api/data?id=123&name=test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/api/data", "Path prefix should be stripped");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path rewriting: /old/data/file.txt → /new/data/file.txt
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/old/data/file.txt"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/new/data/file.txt", "Path should be rewritten");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting_with_query_params(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // /old/endpoint?param=value → /new/endpoint?param=value
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/old/endpoint?param=value&foo=bar"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/new/endpoint", "Path should be rewritten");

    Ok(())
}

#[tokio::test]
async fn test_path_rewriting_to_versioned_api(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path rewriting to versioned API: /v1/users → /api/v1/users
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/v1/users"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/api/v1/users", "Path should be rewritten to versioned API");

    Ok(())
}

#[tokio::test]
async fn test_path_manipulation_preserves_headers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/strip/test"))
        .header("X-Custom-Header", "test-value")
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        echo.has_header("x-custom-header"),
        "Custom headers should be preserved during path manipulation"
    );
    let custom_header = echo
        .header("x-custom-header")
        .ok_or("Custom header should be present")?;
    assert_eq!(custom_header, "test-value", "Custom header value should match");

    Ok(())
}

#[tokio::test]
async fn test_no_path_manipulation_route() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(
        echo.path, "/api/test",
        "Path should not be modified for routes without path manipulation"
    );

    Ok(())
}

#[tokio::test]
async fn test_path_stripping_exact_prefix() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Test path stripping when request path exactly matches prefix
    // /strip → / (empty path becomes root)
    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/strip"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/", "Empty path after stripping should become root");

    Ok(())
}

async fn test_path_stripping_impl(
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
        .get(format!("{url}/strip/users/123"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/users/123", "Path prefix should be stripped");
    Ok(())
}

#[tokio::test]
async fn test_path_stripping_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_path_stripping_impl(PROXY_HTTPS_URL_IPV6).await
}

async fn test_path_rewriting_impl(
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
        .get(format!("{url}/old/data/file.txt"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/new/data/file.txt", "Path should be rewritten");
    Ok(())
}

#[tokio::test]
async fn test_path_rewriting_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_path_rewriting_impl(PROXY_HTTPS_URL_IPV6).await
}

async fn test_path_manipulation_preserves_headers_impl(
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
        .get(format!("{url}/strip/test"))
        .header("X-Custom-Header", "test-value")
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert!(
        echo.has_header("x-custom-header"),
        "Custom headers should be preserved during path manipulation"
    );
    let custom_header = echo
        .header("x-custom-header")
        .ok_or("Custom header should be present")?;
    assert_eq!(custom_header, "test-value", "Custom header value should match");
    Ok(())
}

#[tokio::test]
async fn test_path_manipulation_preserves_headers_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_path_manipulation_preserves_headers_impl(PROXY_HTTPS_URL_IPV6).await
}
