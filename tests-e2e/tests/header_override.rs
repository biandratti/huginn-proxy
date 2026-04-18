use huginn_proxy_lib::fingerprinting::{forwarded, names};
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

#[tokio::test]
async fn test_injected_headers_override_client_headers(
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

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::TLS_JA4, "t13d9999h2_fake_fingerprint_12345")
        .header(names::HTTP2_AKAMAI, "999:999;999:999|9999999|999|fake")
        .header("Host", "evil.example.com")
        .header(forwarded::FOR, "192.168.1.100")
        .header(forwarded::HOST, "spoofed-x-forwarded-host.example.com")
        .header(forwarded::PORT, "9999")
        .header(forwarded::PROTO, "http")
        .send()
        .await
        .map_err(|e| format!("Failed to send request with spoofed headers: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(echo.has_header(names::TLS_JA4), "JA4 fingerprint header should be present");
    let ja4_fp = echo
        .header(names::TLS_JA4)
        .ok_or("JA4 fingerprint header should be present")?;
    assert!(!ja4_fp.is_empty(), "JA4 fingerprint should not be empty");
    assert_ne!(
        ja4_fp, "t13d9999h2_fake_fingerprint_12345",
        "JA4 fingerprint should NOT be the spoofed value from client."
    );
    assert!(
        ja4_fp.starts_with("t13"),
        "JA4 fingerprint should be a valid fingerprint starting with 't13'"
    );
    println!("✓ JA4 fingerprint correctly overridden: {ja4_fp}");

    assert!(
        echo.has_header(names::HTTP2_AKAMAI),
        "Akamai fingerprint header should be present"
    );
    let akamai_fp = echo
        .header(names::HTTP2_AKAMAI)
        .ok_or("Akamai fingerprint header should be present")?;
    assert!(!akamai_fp.is_empty(), "Akamai fingerprint should not be empty");
    assert_ne!(
        akamai_fp, "999:999;999:999|9999999|999|fake",
        "Akamai fingerprint should NOT be the spoofed value from client."
    );
    assert!(akamai_fp.contains('|'), "Akamai fingerprint should be a valid fingerprint");
    println!("✓ Akamai fingerprint correctly overridden: {akamai_fp}");

    assert!(echo.has_header(forwarded::FOR), "X-Forwarded-For header should be present");
    let forwarded_for = echo
        .header(forwarded::FOR)
        .ok_or("X-Forwarded-For should be present")?;
    assert!(
        forwarded_for.contains("192.168.1.100"),
        "X-Forwarded-For should contain the spoofed value from client. Current value: {forwarded_for}"
    );
    let parts: Vec<&str> = forwarded_for.split(',').map(|s| s.trim()).collect();
    assert!(
        parts.len() >= 2,
        "X-Forwarded-For should contain at least 2 IPs (spoofed + real). Current value: {forwarded_for}"
    );
    let real_ip = match parts.last() {
        Some(ip) => ip,
        None => {
            return Err("X-Forwarded-For should contain at least 2 IPs".into());
        }
    };
    assert_ne!(
        *real_ip, "192.168.1.100",
        "X-Forwarded-For should end with the real client IP. Current value: {forwarded_for}"
    );
    assert!(
        real_ip.contains('.') || real_ip.contains(':'),
        "Real IP should be a valid IP address format. Current value: {real_ip}"
    );
    println!("✓ X-Forwarded-For correctly handled (spoofed: 192.168.1.100, real IP: {real_ip}): {forwarded_for}");

    let forwarded_host = if echo.has_header(forwarded::HOST) {
        let host = echo
            .header(forwarded::HOST)
            .ok_or("X-Forwarded-Host should be present")?;
        assert_ne!(
            host, "spoofed-x-forwarded-host.example.com",
            "X-Forwarded-Host must NOT be the spoofed value."
        );
        assert_ne!(
            host, "evil.example.com",
            "X-Forwarded-Host must NOT be taken from Host header."
        );
        assert_eq!(
            host, "127.0.0.1",
            "X-Forwarded-Host should be the TLS SNI value (127.0.0.1). Current value: {host}"
        );
        println!("✓ X-Forwarded-Host correctly uses TLS SNI: {host}");
        Some(host)
    } else {
        println!("i X-Forwarded-Host not present (only set when TLS SNI is available)");
        None
    };

    assert!(echo.has_header(forwarded::PORT), "X-Forwarded-Port header should be present");
    let forwarded_port = echo
        .header(forwarded::PORT)
        .ok_or("X-Forwarded-Port should be present")?;
    assert_ne!(
        forwarded_port, "9999",
        "X-Forwarded-Port should NOT be the spoofed value from client."
    );
    assert!(
        forwarded_port != "9999" && !forwarded_port.is_empty(),
        "X-Forwarded-Port should be the real port value"
    );
    println!("✓ X-Forwarded-Port correctly overridden: {forwarded_port}");

    assert!(echo.has_header(forwarded::PROTO), "X-Forwarded-Proto header should be present");
    let forwarded_proto = echo
        .header(forwarded::PROTO)
        .ok_or("X-Forwarded-Proto should be present")?;
    assert_eq!(forwarded_proto, "https", "X-Forwarded-Proto should be 'https'.");
    println!("✓ X-Forwarded-Proto correctly overridden: {forwarded_proto}");

    println!("\n✓ Test passed: All injected headers correctly override client-provided values");
    println!("  - JA4 fingerprint: {ja4_fp}");
    println!("  - Akamai fingerprint: {akamai_fp}");
    println!("  - X-Forwarded-For: {forwarded_for}");
    if let Some(host) = forwarded_host {
        println!("  - X-Forwarded-Host: {host}");
    } else {
        println!("  - X-Forwarded-Host: (not present - valid for HTTP/2)");
    }
    println!("  - X-Forwarded-Port: {forwarded_port}");
    println!("  - X-Forwarded-Proto: {forwarded_proto}");

    Ok(())
}

#[tokio::test]
async fn test_fingerprints_consistent_despite_spoofed_headers(
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
        .header(names::TLS_JA4, "spoofed-ja4-1")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-1")
        .send()
        .await
        .map_err(|e| format!("Failed to send first request: {e}"))?;

    let echo1 = parse_backend_echo(response1).await?;
    let ja4_1 = echo1.header(names::TLS_JA4).ok_or("JA4 missing")?;
    let akamai_1 = echo1.header(names::HTTP2_AKAMAI).ok_or("Akamai missing")?;

    let response2 = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::TLS_JA4, "spoofed-ja4-2")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-2")
        .send()
        .await
        .map_err(|e| format!("Failed to send second request: {e}"))?;

    let echo2 = parse_backend_echo(response2).await?;
    let ja4_2 = echo2.header(names::TLS_JA4).ok_or("JA4 missing")?;
    let akamai_2 = echo2.header(names::HTTP2_AKAMAI).ok_or("Akamai missing")?;

    assert_eq!(
        ja4_1, ja4_2,
        "JA4 fingerprint should be identical despite different spoofed headers"
    );
    assert_eq!(
        akamai_1, akamai_2,
        "Akamai fingerprint should be identical despite different spoofed headers"
    );

    assert_ne!(ja4_1, "spoofed-ja4-1", "JA4 should not be spoofed value 1");
    assert_ne!(ja4_1, "spoofed-ja4-2", "JA4 should not be spoofed value 2");
    assert_ne!(akamai_1, "spoofed-akamai-1", "Akamai should not be spoofed value 1");
    assert_ne!(akamai_1, "spoofed-akamai-2", "Akamai should not be spoofed value 2");

    println!("\n✓ Test passed: Fingerprints remain consistent despite different spoofed headers");
    println!("  - JA4: {ja4_1}");
    println!("  - Akamai: {akamai_1}");

    Ok(())
}

#[tokio::test]
async fn test_injected_headers_override_client_headers_ipv6(
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

    let response = client
        .get(PROXY_HTTPS_URL_IPV6)
        .header(names::TLS_JA4, "t13d9999h2_fake_fingerprint_12345")
        .header(names::HTTP2_AKAMAI, "999:999;999:999|9999999|999|fake")
        .header(forwarded::FOR, "192.168.1.100")
        .header(forwarded::PORT, "9999")
        .header(forwarded::PROTO, "http")
        .send()
        .await
        .map_err(|e| format!("Failed to send request with spoofed headers over IPv6: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    let ja4_fp = echo
        .header(names::TLS_JA4)
        .ok_or("JA4 fingerprint header should be present")?;
    assert_ne!(
        ja4_fp, "t13d9999h2_fake_fingerprint_12345",
        "JA4 must NOT be the spoofed value over IPv6"
    );
    assert!(ja4_fp.starts_with("t13"), "JA4 should be a real value starting with 't13'");
    println!("✓ IPv6 JA4 overridden: {ja4_fp}");

    let akamai_fp = echo
        .header(names::HTTP2_AKAMAI)
        .ok_or("Akamai fingerprint header should be present")?;
    assert_ne!(
        akamai_fp, "999:999;999:999|9999999|999|fake",
        "Akamai must NOT be the spoofed value over IPv6"
    );
    assert!(akamai_fp.contains('|'), "Akamai fingerprint should be a valid value");
    println!("✓ IPv6 Akamai overridden: {akamai_fp}");

    let forwarded_for = echo
        .header(forwarded::FOR)
        .ok_or("X-Forwarded-For should be present")?;
    assert!(
        forwarded_for.contains("192.168.1.100"),
        "X-Forwarded-For should contain spoofed value; got: {forwarded_for}"
    );
    let parts: Vec<&str> = forwarded_for.split(',').map(|s| s.trim()).collect();
    assert!(
        parts.len() >= 2,
        "X-Forwarded-For should have at least 2 entries; got: {forwarded_for}"
    );
    println!("✓ IPv6 X-Forwarded-For: {forwarded_for}");

    let forwarded_proto = echo
        .header(forwarded::PROTO)
        .ok_or("X-Forwarded-Proto should be present")?;
    assert_eq!(forwarded_proto, "https", "X-Forwarded-Proto must be 'https' over IPv6");
    println!("✓ IPv6 X-Forwarded-Proto: {forwarded_proto}");

    let forwarded_port = echo
        .header(forwarded::PORT)
        .ok_or("X-Forwarded-Port should be present")?;
    assert_ne!(
        forwarded_port, "9999",
        "X-Forwarded-Port must NOT be the spoofed value over IPv6"
    );
    println!("✓ IPv6 X-Forwarded-Port: {forwarded_port}");

    if let Some(host) = echo.header(forwarded::HOST) {
        assert_ne!(host, "evil.example.com", "X-Forwarded-Host must not be spoofed");
        println!("✓ IPv6 X-Forwarded-Host: {host}");
    } else {
        println!("i X-Forwarded-Host not present (valid for IPv6 IP-literal with no SNI)");
    }

    println!("\n✓ IPv6 header-override test passed");

    Ok(())
}

#[tokio::test]
async fn test_fingerprints_consistent_despite_spoofed_headers_ipv6(
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
        .header(names::TLS_JA4, "spoofed-ja4-1")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-1")
        .send()
        .await
        .map_err(|e| format!("Failed to send first IPv6 request: {e}"))?;
    let echo1 = parse_backend_echo(response1).await?;
    let ja4_1 = echo1.header(names::TLS_JA4).ok_or("JA4 missing")?;
    let akamai_1 = echo1.header(names::HTTP2_AKAMAI).ok_or("Akamai missing")?;

    let response2 = client
        .get(PROXY_HTTPS_URL_IPV6)
        .header(names::TLS_JA4, "spoofed-ja4-2")
        .header(names::HTTP2_AKAMAI, "spoofed-akamai-2")
        .send()
        .await
        .map_err(|e| format!("Failed to send second IPv6 request: {e}"))?;
    let echo2 = parse_backend_echo(response2).await?;
    let ja4_2 = echo2.header(names::TLS_JA4).ok_or("JA4 missing")?;
    let akamai_2 = echo2.header(names::HTTP2_AKAMAI).ok_or("Akamai missing")?;

    assert_eq!(
        ja4_1, ja4_2,
        "IPv6 JA4 fingerprint must be identical despite different spoofed headers"
    );
    assert_eq!(
        akamai_1, akamai_2,
        "IPv6 Akamai fingerprint must be identical despite different spoofed headers"
    );
    assert_ne!(ja4_1, "spoofed-ja4-1");
    assert_ne!(akamai_1, "spoofed-akamai-1");

    println!("\n✓ IPv6 fingerprint consistency test passed");
    println!("  - JA4:    {ja4_1}");
    println!("  - Akamai: {akamai_1}");

    Ok(())
}
