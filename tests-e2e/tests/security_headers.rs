use huginn_proxy_lib::names;
use reqwest::Client;

use tests_e2e::common::{
    parse_backend_echo, wait_for_service, BackendEcho, DEFAULT_SERVICE_TIMEOUT_SECS,
    PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

fn assert_injected_fingerprint_headers(echo: &BackendEcho, ipv6: bool) {
    let prefix = if ipv6 { "IPv6 " } else { "" };

    let tls: &[(&str, &str)] = &[
        ("JA4", names::TLS_JA4),
        ("JA4_r", names::TLS_JA4_R),
        ("JA4_o", names::TLS_JA4_O),
        ("JA4_or", names::TLS_JA4_OR),
        ("JA4_s1", names::TLS_JA4_S1),
        ("JA4_s1r", names::TLS_JA4_S1R),
    ];

    for (label, name) in tls {
        let v = echo.header(name).unwrap_or_else(|| {
            panic!("{prefix}expected injected header {name} ({label})");
        });
        assert!(!v.is_empty(), "{prefix}{name} ({label}) must be non-empty");
        println!("{prefix}{label} fingerprint present: {v}");
    }

    let akamai = echo.header(names::HTTP2_AKAMAI).unwrap_or_else(|| {
        panic!("{prefix}expected injected header {}", names::HTTP2_AKAMAI);
    });
    assert!(!akamai.is_empty(), "{prefix}HTTP/2 Akamai fingerprint must be non-empty");
    println!("{prefix}Akamai fingerprint present: {akamai}");
}

#[tokio::test]
async fn test_custom_security_headers() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/users"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    if let Some(x_frame) = response.headers().get("x-frame-options") {
        let value = x_frame
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("X-Frame-Options: {}", value);
    }

    if let Some(x_content) = response.headers().get("x-content-type-options") {
        let value = x_content
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("X-Content-Type-Options: {}", value);
        assert_eq!(value, "nosniff");
    }

    Ok(())
}

#[tokio::test]
async fn test_hsts_header() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    if let Some(hsts) = response.headers().get("strict-transport-security") {
        let value = hsts
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("Strict-Transport-Security: {}", value);
        assert!(value.contains("max-age="));
    }

    Ok(())
}

#[tokio::test]
async fn test_csp_header() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/static/test.html"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    if let Some(csp) = response.headers().get("content-security-policy") {
        let value = csp
            .to_str()
            .map_err(|e| format!("Invalid header value: {e}"))?;
        println!("Content-Security-Policy: {}", value);
        assert!(!value.is_empty());
    }

    Ok(())
}

#[tokio::test]
async fn test_security_headers_with_fingerprinting(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV4}/api/fingerprint"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request: {e}"))?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_injected_fingerprint_headers(&echo, false);

    Ok(())
}

#[tokio::test]
async fn test_hsts_header_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/api/test"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    if let Some(hsts) = response.headers().get("strict-transport-security") {
        let value = hsts
            .to_str()
            .map_err(|e| format!("Invalid HSTS header value: {e}"))?;
        println!("IPv6 Strict-Transport-Security: {value}");
        assert!(value.contains("max-age="), "HSTS should include max-age directive");
    }

    Ok(())
}

#[tokio::test]
async fn test_security_headers_with_fingerprinting_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response = client
        .get(format!("{PROXY_HTTPS_URL_IPV6}/api/fingerprint"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;
    assert_injected_fingerprint_headers(&echo, true);

    Ok(())
}
