//! Catch-all (host-less) domain routing.
//!
//! The compose config declares a single host-less domain, so any host must be
//! served by it. Before the catch-all existed, an unconfigured host returned
//! 421; this guards against a regression to that behavior.

use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
};

/// A request carrying an arbitrary, unconfigured `Host` is routed through the
/// catch-all domain (HTTP 200) instead of being rejected with 421.
///
/// HTTP/1.1 is forced so the `Host` header is authoritative for host matching:
/// the connection is over IP (no SNI) and origin-form has no URI authority, so
/// the proxy resolves the host from the `Host` header.
#[tokio::test]
async fn catch_all_serves_arbitrary_host() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(reqwest::header::HOST, "totally-unconfigured.example")
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "an unconfigured host must be served by the catch-all domain, not rejected with 421"
    );

    // "/" routes to backend-b (traefik/whoami) — confirm we actually reached it.
    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, "/");
    Ok(())
}
