use huginn_proxy_lib::fingerprinting::{forwarded, names};
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_fingerprint_isolation_from_added_headers(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready"
    );

    let response1 = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header("X-Custom-Header", "test-value-1")
        .header("User-Agent", "test-client/1.0")
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("Failed to send first HTTP/2 request: {e}"))?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);

    let echo1 = parse_backend_echo(response1).await?;

    let akamai_fp1 = echo1
        .header(names::HTTP2_AKAMAI)
        .ok_or("HTTP/2 fingerprint header should be present in first request")?;
    assert!(!akamai_fp1.is_empty(), "HTTP/2 fingerprint should not be empty");
    println!("First request Akamai fingerprint: {akamai_fp1}");

    let tls_fp1 = echo1
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint header should be present in first request")?;
    assert!(!tls_fp1.is_empty(), "TLS fingerprint should not be empty");
    println!("First request TLS fingerprint: {tls_fp1}");

    assert!(
        echo1.has_header(forwarded::FOR),
        "X-Forwarded-For header should be present in backend response"
    );
    let has_forwarded_host = echo1.has_header(forwarded::HOST);
    if has_forwarded_host {
        println!("✓ X-Forwarded-Host is present (request had Host header)");
    } else {
        println!(
            "ℹ X-Forwarded-Host not present (request had no Host header, which is valid for HTTP/2)"
        );
    }
    assert!(
        echo1.has_header(forwarded::PROTO),
        "X-Forwarded-Proto header should be present in backend response"
    );
    assert!(
        echo1.has_header(forwarded::PORT),
        "X-Forwarded-Port header should be present in backend response"
    );

    let forwarded_proto1 = echo1
        .header(forwarded::PROTO)
        .ok_or("X-Forwarded-Proto should be present")?;
    assert_eq!(
        forwarded_proto1, "https",
        "X-Forwarded-Proto should be 'https' for HTTPS connections"
    );

    assert!(
        echo1.has_header("x-custom-header"),
        "Custom header should be present in backend response"
    );
    let custom_header1 = echo1
        .header("x-custom-header")
        .ok_or("Custom header should be present")?;
    assert_eq!(custom_header1, "test-value-1", "Custom header value should match what we sent");

    // Second request: with DIFFERENT custom headers — fingerprints must be identical
    let response2 = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header("X-Custom-Header", "test-value-2")
        .header("User-Agent", "test-client/2.0")
        .header("Accept", "text/html")
        .header("X-Another-Header", "different-value")
        .send()
        .await
        .map_err(|e| format!("Failed to send second HTTP/2 request: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);

    let echo2 = parse_backend_echo(response2).await?;

    let akamai_fp2 = echo2
        .header(names::HTTP2_AKAMAI)
        .ok_or("HTTP/2 fingerprint header should be present in second request")?;
    assert!(!akamai_fp2.is_empty(), "HTTP/2 fingerprint should not be empty");
    println!("Second request Akamai fingerprint: {akamai_fp2}");

    let tls_fp2 = echo2
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint header should be present in second request")?;
    assert!(!tls_fp2.is_empty(), "TLS fingerprint should not be empty");
    println!("Second request TLS fingerprint: {tls_fp2}");

    assert_eq!(
        akamai_fp1, akamai_fp2,
        "Akamai fingerprint should be identical across requests with different headers. \
         This proves that fingerprints are generated from HTTP/2 frames, not HTTP headers."
    );

    assert_eq!(
        tls_fp1, tls_fp2,
        "TLS fingerprint should be identical across requests from the same client"
    );

    assert!(
        echo2.has_header(forwarded::FOR),
        "X-Forwarded-For header should be present in second backend response"
    );
    let has_forwarded_host2 = echo2.has_header(forwarded::HOST);
    if has_forwarded_host2 {
        println!("✓ X-Forwarded-Host is present in second request");
    }
    assert!(
        echo2.has_header(forwarded::PROTO),
        "X-Forwarded-Proto header should be present in second backend response"
    );
    assert!(
        echo2.has_header(forwarded::PORT),
        "X-Forwarded-Port header should be present in second backend response"
    );

    let forwarded_proto2 = echo2
        .header(forwarded::PROTO)
        .ok_or("X-Forwarded-Proto should be present")?;
    assert_eq!(
        forwarded_proto2, "https",
        "X-Forwarded-Proto should be 'https' for HTTPS connections"
    );

    assert!(
        echo2.has_header("x-custom-header"),
        "Custom header should be present in second backend response"
    );
    let custom_header2 = echo2
        .header("x-custom-header")
        .ok_or("Custom header should be present")?;
    assert_eq!(
        custom_header2, "test-value-2",
        "Custom header value should match what we sent in second request"
    );

    assert!(
        echo2.has_header("x-another-header"),
        "New custom header should be present in second backend response"
    );

    println!("\n✓ Test passed: Fingerprints are isolated from added headers");
    println!("  - Akamai fingerprint: {akamai_fp1}");
    println!("  - TLS fingerprint: {tls_fp1}");
    println!("  - Both fingerprints remained identical despite different HTTP headers");

    Ok(())
}

// ── IPv6 variant ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_fingerprint_isolation_from_added_headers_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to create HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV6, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "HTTPS proxy should be ready on IPv6"
    );

    let response1 = client
        .get(PROXY_HTTPS_URL_IPV6)
        .header("X-Custom-Header", "value-1")
        .send()
        .await
        .map_err(|e| format!("Failed to send first IPv6 request: {e}"))?;
    assert_eq!(response1.status(), reqwest::StatusCode::OK);
    let echo1 = parse_backend_echo(response1).await?;
    let akamai1 = echo1
        .header(names::HTTP2_AKAMAI)
        .ok_or("Akamai fingerprint should be present on IPv6")?;
    let tls1 = echo1
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint should be present on IPv6")?;
    assert!(echo1.has_header(forwarded::FOR), "X-Forwarded-For should be present over IPv6");

    let response2 = client
        .get(PROXY_HTTPS_URL_IPV6)
        .header("X-Custom-Header", "value-2")
        .header("X-Another-Header", "extra")
        .send()
        .await
        .map_err(|e| format!("Failed to send second IPv6 request: {e}"))?;
    assert_eq!(response2.status(), reqwest::StatusCode::OK);
    let echo2 = parse_backend_echo(response2).await?;
    let akamai2 = echo2
        .header(names::HTTP2_AKAMAI)
        .ok_or("Akamai fingerprint should be present on second IPv6 request")?;
    let tls2 = echo2
        .header(names::TLS_JA4)
        .ok_or("TLS fingerprint should be present on second IPv6 request")?;

    assert_eq!(
        akamai1, akamai2,
        "Akamai fingerprint must be identical over IPv6 despite different headers"
    );
    assert_eq!(
        tls1, tls2,
        "TLS fingerprint must be identical over IPv6 despite different headers"
    );

    println!("\n✓ IPv6 fingerprint isolation confirmed");
    println!("  - Akamai: {akamai1}");
    println!("  - TLS:    {tls1}");

    Ok(())
}
