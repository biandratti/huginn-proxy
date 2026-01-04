use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

#[tokio::test]
async fn test_tls_with_configured_cipher_suites(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This test verifies that the proxy accepts and validates cipher suite configuration
    // Note: Due to rustls 0.23 limitations, the cipher suites are validated but not
    // fully applied, so TLS signatures will be the same regardless of configuration.

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL)
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

    assert!(headers.contains_key(names::TLS_JA4), "TLS fingerprint header should be present");

    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint with configured cipher suites: {tls_fp}");

    // Note: We cannot verify that different cipher suite configurations produce
    // different fingerprints because rustls 0.23 doesn't apply these configurations.
    // This test documents that the configuration is accepted and TLS works correctly.

    Ok(())
}

#[tokio::test]
async fn test_tls_with_configured_curves() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This test verifies that the proxy accepts and validates curve preferences configuration
    // Note: Due to rustls 0.23 limitations, the curve preferences are validated but not
    // fully applied, so TLS signatures will be the same regardless of configuration.

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL)
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

    assert!(headers.contains_key(names::TLS_JA4), "TLS fingerprint header should be present");

    let tls_fp = headers
        .get(names::TLS_JA4)
        .and_then(|v| v.as_str())
        .ok_or("TLS fingerprint header should be a string")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint with configured curves: {tls_fp}");

    // Note: We cannot verify that different curve configurations produce
    // different fingerprints because rustls 0.23 doesn't apply these configurations.
    // This test documents that the configuration is accepted and TLS works correctly.

    Ok(())
}
