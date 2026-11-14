//! `X-Forwarded-For` forwarding E2E tests.
//!
//! A client may send `X-Forwarded-For` as several field lines, which are one list. The
//! proxy must forward every hop, in order, and append the peer as the rightmost one.

use huginn_proxy_lib::fingerprinting::forwarded;
use tests_e2e::common::{
    DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, parse_backend_echo, wait_for_service,
};

#[tokio::test]
async fn test_repeated_xff_field_lines_all_reach_backend()
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
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    let forwarded_for = echo
        .header(forwarded::FOR)
        .ok_or("X-Forwarded-For should be present")?;
    let hops: Vec<&str> = forwarded_for.split(',').map(str::trim).collect();

    assert_eq!(
        hops.len(),
        3,
        "both client hops plus the peer must be forwarded, got: {forwarded_for}"
    );
    assert_eq!(hops.first(), Some(&"203.0.113.5"), "first hop lost, got: {forwarded_for}");
    assert_eq!(hops.get(1), Some(&"198.51.100.7"), "second hop lost, got: {forwarded_for}");
    assert!(
        hops.get(2)
            .is_some_and(|peer| peer.parse::<std::net::IpAddr>().is_ok()),
        "rightmost hop must be the peer IP, got: {forwarded_for}"
    );

    Ok(())
}
