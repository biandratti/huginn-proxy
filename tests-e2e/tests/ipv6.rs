//! E2E tests that exercise the **IPv6 listener** (`[::]:7000` with `IPV6_V6ONLY`).
//!
//! Requires:
//! - `docker compose -f examples/docker-compose.yml up` (ports include `[::]:7000:7000`)
//! - Host IPv6 stack with `::1` reaching the published port (Linux/macOS Docker usually OK)

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_proxy_forwarding_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should accept connections on IPv6 loopback [::1]:7000"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(PROXY_HTTPS_URL_IPV6)
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;

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
async fn test_tls_and_tcp_syn_fingerprints_over_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );
    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "IPv6 HTTPS listener should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV6)
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response as JSON: {e}"))?;
    let headers = body
        .get("headers")
        .and_then(|h| h.as_object())
        .ok_or("Response should contain headers object")?;

    assert!(
        headers.contains_key(names::TLS_JA4),
        "TLS JA4 should be present on IPv6 connection"
    );
    assert!(
        headers.contains_key(names::TCP_SYN),
        "TCP SYN fingerprint (eBPF) should be present when fingerprinting is enabled"
    );

    let tcp_fp = headers
        .get(names::TCP_SYN)
        .and_then(|v| v.as_str())
        .ok_or("TCP SYN fingerprint should be a string")?;
    assert!(
        tcp_fp.starts_with("6:"),
        "TCP SYN fingerprint should use IPv6 prefix when client connects via IPv6; got: {tcp_fp}"
    );
    Ok(())
}
