//! Domain-level header manipulation.
//!
//! The compose config sets a domain-level response header (`X-Proxy: huginn-proxy`)
//! on the catch-all domain. This header comes *only* from the domain scope, not from
//! the global `headers` block or `security.headers`, so it proves domain-level headers
//! are actually applied. (They used to be parsed and silently ignored.)

use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4};

#[tokio::test]
async fn domain_level_response_header_is_applied(
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
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-proxy")
            .and_then(|v| v.to_str().ok()),
        Some("huginn-proxy"),
        "domain-level response header must be injected by the proxy"
    );
    Ok(())
}
