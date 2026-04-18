use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_tls_with_configured_cipher_suites(
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

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert!(echo.has_header(names::TLS_JA4), "TLS fingerprint header should be present");
    let tls_fp = echo
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint should be present")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint with configured cipher suites: {tls_fp}");

    Ok(())
}

#[tokio::test]
async fn test_tls_with_configured_curves() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

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
    assert!(echo.has_header(names::TLS_JA4), "TLS fingerprint header should be present");
    let tls_fp = echo
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint should be present")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");

    println!("TLS fingerprint with configured curves: {tls_fp}");

    Ok(())
}

async fn test_tls_with_cipher_suites_impl(
    url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;
    assert!(
        wait_for_service(url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert!(echo.has_header(names::TLS_JA4), "TLS fingerprint header should be present");
    let tls_fp = echo
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint should be present")?;
    assert!(!tls_fp.is_empty(), "TLS fingerprint should not be empty");
    println!("TLS fingerprint ({url}): {tls_fp}");
    Ok(())
}

#[tokio::test]
async fn test_tls_with_configured_cipher_suites_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tls_with_cipher_suites_impl(PROXY_HTTPS_URL_IPV6).await
}

#[tokio::test]
async fn test_tls_with_configured_curves_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_tls_with_cipher_suites_impl(PROXY_HTTPS_URL_IPV6).await
}
