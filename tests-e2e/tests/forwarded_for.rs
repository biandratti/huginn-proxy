//! `X-Forwarded-For` forwarding E2E tests.
//!
//! The compose config sets no `security.trusted_proxies`, so the test client is a direct,
//! untrusted client: whatever `X-Forwarded-For` it sends, in one field line or several,
//! must be discarded and the backend must see the peer alone. The trusted-proxy side is
//! covered in-process by `huginn-proxy-lib/tests/proxy/forwarded_for_trust.rs`.

use huginn_proxy_lib::fingerprinting::forwarded;
use tests_e2e::common::{
    DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, parse_backend_echo, wait_for_service,
};

#[tokio::test]
async fn test_untrusted_client_xff_is_not_forwarded()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    // Two `.header()` calls with the same name are sent as two field lines.
    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(forwarded::FOR, "203.0.113.5")
        .header(forwarded::FOR, "198.51.100.7")
        .header("forwarded", "for=203.0.113.5")
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    let forwarded_for = echo
        .header(forwarded::FOR)
        .ok_or("X-Forwarded-For should be present")?;

    assert!(
        forwarded_for.parse::<std::net::IpAddr>().is_ok(),
        "only the peer IP must be forwarded, got: {forwarded_for}"
    );
    assert!(
        !echo.has_header("forwarded"),
        "a client-supplied Forwarded header must not reach the backend"
    );

    Ok(())
}
