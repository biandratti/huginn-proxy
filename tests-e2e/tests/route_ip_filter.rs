//! Per-route IP ACL (whole-block) E2E test.
//!
//! The `/acl-denied` route sets its own `ip_filter` allowlist to a TEST-NET-1 range
//! (`192.0.2.0/24`, RFC 5737) that no real client ever has, while the global `ip_filter` is
//! disabled. So a request to `/acl-denied` must be rejected with 403, while a sibling route
//! served from the same client succeeds, proving the ACL is resolved and enforced per route
//! (whole-block override), not globally.

use reqwest::StatusCode;
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4};

#[tokio::test]
async fn test_route_ip_filter_blocks_only_its_route(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let denied = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/acl-denied"))
        .send()
        .await
        .map_err(|e| format!("Request to /acl-denied failed: {e}"))?;
    assert_eq!(
        denied.status(),
        StatusCode::FORBIDDEN,
        "per-route ip_filter allowlist must reject this client with 403"
    );

    let allowed = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Request to /api/test failed: {e}"))?;
    assert_eq!(
        allowed.status(),
        StatusCode::OK,
        "a route without an ip_filter override must still serve this client"
    );

    Ok(())
}
