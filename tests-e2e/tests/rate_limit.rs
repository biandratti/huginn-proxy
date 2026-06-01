//! Rate-limit E2E tests.
//!
//! The `/rl` route in compose.yaml has burst=3, so the 4th request in a window
//! must always return 429 regardless of what `X-Forwarded-For` says.
//!
//! The key assertion: we rotate `X-Forwarded-For` on every request (simulating
//! client-side IP rotation). If the proxy used the leftmost XFF value as the
//! rate-limit key (the old vulnerable behaviour), each request would be a new
//! key and the limit would never fire. With the fix, the TCP peer IP is always
//! used as the key (same for every request from this test process), so the
//! bucket fills normally and the 4th request gets 429.

use reqwest::StatusCode;
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4};

const BURST: usize = 3;

#[tokio::test]
async fn test_rate_limit_xff_rotation_does_not_bypass(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let url = format!("{PROXY_HTTPS_URL_IPV4}/rl");
    let mut statuses = Vec::new();

    // Send BURST+1 requests, each with a distinct XFF value to simulate IP rotation.
    for i in 0..=BURST {
        let resp = client
            .get(&url)
            .header("x-forwarded-for", format!("10.0.0.{}", i + 1))
            .send()
            .await
            .map_err(|e| format!("Request {i} failed: {e}"))?;
        statuses.push(resp.status());
    }

    let allowed = statuses.iter().filter(|s| s.is_success()).count();
    let limited = statuses
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();

    assert_eq!(allowed, BURST, "first {BURST} requests should be allowed (got {allowed})");
    assert_eq!(
        limited,
        1,
        "request {} must be rate-limited — XFF rotation must not bypass the limit (got {limited})",
        BURST + 1
    );

    Ok(())
}

#[tokio::test]
async fn test_xff_bypass_attempt_is_blocked() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    // Use the dedicated /rl-bypass route so this test has its own fresh bucket.
    let url = format!("{PROXY_HTTPS_URL_IPV4}/rl-bypass");

    for i in 0..BURST {
        let resp = client
            .get(&url)
            .header("x-forwarded-for", "10.10.10.1")
            .send()
            .await
            .map_err(|e| format!("Phase-1 request {i} failed: {e}"))?;
        assert!(
            resp.status().is_success(),
            "phase-1 request {i} should be allowed, got {}",
            resp.status()
        );
    }

    let bypass = client
        .get(&url)
        .header("x-forwarded-for", "99.99.99.99")
        .send()
        .await
        .map_err(|e| format!("Bypass attempt failed: {e}"))?;

    assert_eq!(
        bypass.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "switching X-Forwarded-For must not reset the rate-limit bucket"
    );

    Ok(())
}
