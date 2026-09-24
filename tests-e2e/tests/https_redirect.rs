use tests_e2e::common::{
    DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTP_URL_IPV4, PROXY_HTTP_URL_IPV6, PROXY_HTTPS_URL_IPV4,
    wait_for_service,
};

async fn http_redirects_to_https_impl(
    http_url: &str,
    expected_location: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
    let response = client
        .get(format!("{http_url}/api/test?x=1"))
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::MOVED_PERMANENTLY);
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .ok_or("301 without Location")?
        .to_str()
        .map_err(|e| format!("invalid Location: {e}"))?;
    assert_eq!(location, expected_location);
    Ok(())
}

#[tokio::test]
async fn http_redirects_to_https() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    http_redirects_to_https_impl(PROXY_HTTP_URL_IPV4, "https://127.0.0.1/api/test?x=1").await
}

#[tokio::test]
async fn http_redirects_to_https_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    http_redirects_to_https_impl(PROXY_HTTP_URL_IPV6, "https://[::1]/api/test?x=1").await
}
