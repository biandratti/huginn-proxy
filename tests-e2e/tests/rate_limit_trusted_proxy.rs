//! Rate-limit E2E tests with the test client acting as a **trusted proxy**.
//!
//! These need `security.trusted_proxies` to cover the address the proxy sees the test
//! client from, which the default compose config deliberately does not set (the tests in
//! `rate_limit.rs` assert the untrusted behaviour on the same proxy). They are therefore
//! `#[ignore]`d and run by `tests-e2e/run-xff-validation.sh`, which restarts the proxy
//! with a trusted-proxy config first.
//!
//! The `/rl` route has burst=3. Each test resolves to its own client IP, so each has its
//! own bucket.

use reqwest::StatusCode;
use tests_e2e::common::{DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4, wait_for_service};

const BURST: usize = 3;

/// Send `BURST + 1` requests to `/rl`, each with the `X-Forwarded-For` field lines built
/// by `xff_lines(i)`, and return `(allowed, limited)`.
async fn burst_plus_one(
    xff_lines: impl Fn(usize) -> Vec<String>,
) -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to build client: {e}"))?;

    assert!(
        wait_for_service(PROXY_HTTPS_URL_IPV4, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "proxy should be ready"
    );

    let url = format!("{PROXY_HTTPS_URL_IPV4}/rl");
    let mut allowed = 0usize;
    let mut limited = 0usize;
    for i in 0..=BURST {
        let mut req = client.get(&url);
        for line in xff_lines(i) {
            req = req.header("x-forwarded-for", line);
        }
        let status = req
            .send()
            .await
            .map_err(|e| format!("Request {i} failed: {e}"))?
            .status();
        if status.is_success() {
            allowed = allowed.saturating_add(1);
        } else if status == StatusCode::TOO_MANY_REQUESTS {
            limited = limited.saturating_add(1);
        }
    }
    Ok((allowed, limited))
}

fn assert_limited(allowed: usize, limited: usize, what: &str) {
    assert_eq!(allowed, BURST, "{what}: first {BURST} requests should be allowed");
    assert_eq!(limited, 1, "{what}: request {} must be rate-limited", BURST.saturating_add(1));
}

/// The real client hop is in the second field line; the first line rotates. Reading only
/// the first line would give every request its own bucket.
#[tokio::test]
#[ignore = "needs trusted_proxies; run tests-e2e/run-xff-validation.sh"]
async fn test_trusted_proxy_repeated_xff_lines_do_not_bypass()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (allowed, limited) = burst_plus_one(|i| {
        vec![format!("192.0.2.{}", i.saturating_add(1)), "198.51.100.21".into()]
    })
    .await?;
    assert_limited(allowed, limited, "repeated field lines");
    Ok(())
}

/// The trusted hop carries a port. It must resolve to that IP, not be skipped in favour
/// of the rotating entry to its left.
#[tokio::test]
#[ignore = "needs trusted_proxies; run tests-e2e/run-xff-validation.sh"]
async fn test_trusted_proxy_hop_with_port_does_not_bypass()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (allowed, limited) =
        burst_plus_one(|i| vec![format!("192.0.2.{}, 198.51.100.22:51234", i.saturating_add(101))])
            .await?;
    assert_limited(allowed, limited, "hop with port");
    Ok(())
}

/// The rightmost hop is not an IP. The walk fails closed to the peer IP instead of
/// stepping left onto the rotating entry.
#[tokio::test]
#[ignore = "needs trusted_proxies; run tests-e2e/run-xff-validation.sh"]
async fn test_trusted_proxy_unparseable_hop_fails_closed()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (allowed, limited) =
        burst_plus_one(|i| vec![format!("192.0.2.{}, unknown", i.saturating_add(201))]).await?;
    assert_limited(allowed, limited, "unparseable hop");
    Ok(())
}
