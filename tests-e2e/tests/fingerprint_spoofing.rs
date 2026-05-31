//! Fingerprint header spoofing protection tests.
//!
//! Verifies that the proxy unconditionally strips all proxy-authoritative fingerprint
//! headers supplied by the client and, when any were present, injects
//! [`names::SPOOFING_DETECTED`] listing the spoofed header names so the backend
//! can act on the detection signal.

use huginn_proxy_lib::fingerprinting::names;
use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
};

/// Parse [`names::SPOOFING_DETECTED`] value into a sorted vec of header names.
fn detected_list(value: &str) -> Vec<&str> {
    let mut v: Vec<&str> = value.split(',').collect();
    v.sort_unstable();
    v
}

#[tokio::test]
async fn test_spoof_akamai_and_p0f_over_http1(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .map_err(|e| format!("Failed to build HTTP/1.1 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::HTTP2_AKAMAI, "999:999;999:999|9999999|999|FORGED")
        .header(names::TCP_SYN, "4:64+0:0:1460:FORGED:df,id+:0")
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        !echo.has_header(names::HTTP2_AKAMAI),
        "forged {} must not reach the backend",
        names::HTTP2_AKAMAI
    );
    assert!(
        !echo.has_header(names::TCP_SYN),
        "forged {} must not reach the backend",
        names::TCP_SYN
    );

    let detected = echo
        .header(names::SPOOFING_DETECTED)
        .ok_or_else(|| format!("{} must be present", names::SPOOFING_DETECTED))?;
    let list = detected_list(detected);
    assert!(
        list.contains(&names::HTTP2_AKAMAI),
        "detection must list {}; got: {detected}",
        names::HTTP2_AKAMAI
    );
    assert!(
        list.contains(&names::TCP_SYN),
        "detection must list {}; got: {detected}",
        names::TCP_SYN
    );
    assert_eq!(list.len(), 2, "detection must list exactly 2 headers; got: {detected}");

    Ok(())
}

#[tokio::test]
async fn test_spoof_p0f_over_http2() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to build HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::TCP_SYN, "4:64+0:0:1460:FORGED:df,id+:0")
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        !echo.has_header(names::TCP_SYN),
        "forged {} must not reach the backend",
        names::TCP_SYN
    );
    assert!(
        echo.has_header(names::HTTP2_AKAMAI),
        "real Akamai fingerprint must still be present"
    );
    assert!(echo.has_header(names::TLS_JA4), "real JA4 fingerprint must still be present");

    let detected = echo
        .header(names::SPOOFING_DETECTED)
        .ok_or_else(|| format!("{} must be present", names::SPOOFING_DETECTED))?;
    let list = detected_list(detected);
    assert_eq!(
        list,
        vec![names::TCP_SYN],
        "detection must list only {}; got: {detected}",
        names::TCP_SYN
    );

    Ok(())
}

#[tokio::test]
async fn test_spoof_on_no_fingerprinting_route(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let static_url = format!("{PROXY_HTTPS_URL_IPV4}/static");

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let response = client
        .get(&static_url)
        .header(names::TLS_JA4, "FORGED-JA4")
        .header(names::HTTP2_AKAMAI, "FORGED-AKAMAI")
        .header(names::TCP_SYN, "FORGED-TCP")
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    for &fp_header in names::FINGERPRINTS {
        assert!(
            !echo.has_header(fp_header),
            "fingerprint header {fp_header} must not reach backend on fingerprinting=false route"
        );
    }

    let detected = echo.header(names::SPOOFING_DETECTED).ok_or_else(|| {
        format!(
            "{} must be present even on fingerprinting=false route",
            names::SPOOFING_DETECTED
        )
    })?;
    let list = detected_list(detected);
    assert!(
        list.contains(&names::TLS_JA4),
        "detection must list {}; got: {detected}",
        names::TLS_JA4
    );
    assert!(
        list.contains(&names::HTTP2_AKAMAI),
        "detection must list {}; got: {detected}",
        names::HTTP2_AKAMAI
    );
    assert!(
        list.contains(&names::TCP_SYN),
        "detection must list {}; got: {detected}",
        names::TCP_SYN
    );

    Ok(())
}

#[tokio::test]
async fn test_no_spoofing_detection_on_clean_request(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to build HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        !echo.has_header(names::SPOOFING_DETECTED),
        "{} must be absent when no spoofing occurred",
        names::SPOOFING_DETECTED
    );
    assert!(echo.has_header(names::HTTP2_AKAMAI), "real Akamai fingerprint must be present");
    assert!(echo.has_header(names::TLS_JA4), "real JA4 fingerprint must be present");

    Ok(())
}

#[tokio::test]
async fn test_forged_ja4_replaced_by_real_value(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const FORGED_JA4: &str = "t00000000000000000000000000000000_FORGED";

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to build HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::TLS_JA4, FORGED_JA4)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    let ja4 = echo
        .header(names::TLS_JA4)
        .ok_or_else(|| format!("{} must be present (real value)", names::TLS_JA4))?;
    assert_ne!(
        ja4, FORGED_JA4,
        "backend must see the real proxy-computed JA4, not the forged client value"
    );

    let detected = echo
        .header(names::SPOOFING_DETECTED)
        .ok_or_else(|| format!("{} must be present", names::SPOOFING_DETECTED))?;
    let list = detected_list(detected);
    assert_eq!(
        list,
        vec![names::TLS_JA4],
        "detection must list only {}; got: {detected}",
        names::TLS_JA4
    );

    Ok(())
}

#[tokio::test]
async fn test_forged_detection_header_stripped(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .http2_prior_knowledge()
        .build()
        .map_err(|e| format!("Failed to build HTTP/2 client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let forged_detection = format!("{},{}", names::TLS_JA4, names::HTTP2_AKAMAI);
    let response = client
        .get(PROXY_HTTPS_URL_IPV4)
        .header(names::SPOOFING_DETECTED, forged_detection)
        .send()
        .await
        .map_err(|e| format!("Request failed: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);

    let echo = parse_backend_echo(response).await?;

    assert!(
        !echo.has_header(names::SPOOFING_DETECTED),
        "client-forged {} must not reach the backend",
        names::SPOOFING_DETECTED
    );

    Ok(())
}
