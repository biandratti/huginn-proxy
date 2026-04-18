use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
};

#[tokio::test]
async fn test_global_header_manipulation() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        echo.has_header("x-proxy-name"),
        "X-Proxy-Name header should be present (added by global config)"
    );
    let proxy_name = echo
        .header("x-proxy-name")
        .ok_or("X-Proxy-Name should be present")?;
    assert_eq!(proxy_name, "huginn-proxy", "X-Proxy-Name should be 'huginn-proxy'");

    assert!(
        echo.has_header("x-proxy-version"),
        "X-Proxy-Version header should be present (added by global config)"
    );
    let proxy_version = echo
        .header("x-proxy-version")
        .ok_or("X-Proxy-Version should be present")?;
    assert_eq!(proxy_version, "0.0.1", "X-Proxy-Version should be '0.0.1'");

    println!("\n✓ Test passed: Global request header manipulation works correctly");
    println!("  - X-Proxy-Name: {proxy_name}");
    println!("  - X-Proxy-Version: {proxy_version}");

    Ok(())
}

#[tokio::test]
async fn test_response_header_manipulation() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let response_headers = response.headers();

    assert!(
        !response_headers.contains_key("x-powered-by"),
        "X-Powered-By header should be removed (global config removes it)"
    );
    assert!(
        !response_headers.contains_key("x-aspnet-version"),
        "X-AspNet-Version header should be removed (global config removes it)"
    );

    assert!(
        response_headers.contains_key("x-proxy"),
        "X-Proxy header should be present (added by global config)"
    );
    let x_proxy = response_headers
        .get("x-proxy")
        .and_then(|v| v.to_str().ok())
        .ok_or("X-Proxy should be a string")?;
    assert_eq!(x_proxy, "huginn-proxy", "X-Proxy should be 'huginn-proxy'");

    println!("\n✓ Test passed: Global response header manipulation works correctly");
    println!("  - X-Proxy: {x_proxy}");
    println!("  - Backend info headers (Server, X-Powered-By, X-AspNet-Version) removed");

    Ok(())
}

#[tokio::test]
async fn test_request_header_removal() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header("X-Forwarded-Server", "should-be-removed.example.com")
        .send()
        .await
        .map_err(|e| format!("Failed to send request with X-Forwarded-Server: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        !echo.has_header("x-forwarded-server"),
        "X-Forwarded-Server should be removed by global config. Headers: {:?}",
        echo.headers
    );

    println!("\n✓ Test passed: Request header removal works correctly");
    println!("  - X-Forwarded-Server header successfully removed");

    Ok(())
}

#[tokio::test]
async fn test_header_override_behavior() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header("X-Proxy-Name", "fake-proxy")
        .header("X-Proxy-Version", "999.999.999")
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    let proxy_name = echo
        .header("x-proxy-name")
        .ok_or("X-Proxy-Name should be present")?;
    assert_eq!(
        proxy_name, "huginn-proxy",
        "X-Proxy-Name should be overridden to 'huginn-proxy', not 'fake-proxy'"
    );

    let proxy_version = echo
        .header("x-proxy-version")
        .ok_or("X-Proxy-Version should be present")?;
    assert_eq!(
        proxy_version, "0.0.1",
        "X-Proxy-Version should be overridden to '0.0.1', not '999.999.999'"
    );

    println!("\n✓ Test passed: Header override behavior works correctly");
    println!("  - X-Proxy-Name correctly overridden: {proxy_name}");
    println!("  - X-Proxy-Version correctly overridden: {proxy_version}");

    Ok(())
}

#[tokio::test]
async fn test_case_insensitive_header_removal(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let test_cases = vec![
        "X-Forwarded-Server",
        "x-forwarded-server",
        "X-FORWARDED-SERVER",
        "x-FoRwArDeD-sErVeR",
    ];

    for header_name in test_cases {
        let response = client
            .get(PROXY_HTTPS_URL_IPV4)
            .header(header_name, "test-value")
            .send()
            .await
            .map_err(|e| format!("Failed to send request with header '{header_name}': {e}"))?;

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let echo = parse_backend_echo(response).await?;

        assert!(
            !echo.has_header("x-forwarded-server"),
            "Header '{header_name}' should be removed (case-insensitive). Headers: {:?}",
            echo.headers
        );

        println!("✓ Header '{header_name}' correctly removed");
    }

    println!("\n✓ Test passed: Case-insensitive header removal works correctly");

    Ok(())
}
