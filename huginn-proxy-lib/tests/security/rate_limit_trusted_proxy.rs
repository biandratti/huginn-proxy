//! Rate limiting behind a trusted proxy, through the full accept loop.
//!
//! Each test runs an in-process proxy (plain HTTP) with the loopback test client listed in
//! `security.trusted_proxies`, so the client plays the trusted proxy and its
//! `X-Forwarded-For` is honored. Every test spawns its own proxy, so buckets are not shared.

use std::net::SocketAddr;
use std::time::Duration;

use huginn_proxy_lib::fingerprinting::forwarded;

use crate::hot_reload::helpers::{free_port, spawn_mock_backend, spawn_proxy, write_toml};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const BURST: usize = 3;
/// Requests sent per test: the burst plus as many again that must all be limited.
const REQUESTS: usize = 6;

fn trusted_proxy_rate_limit_toml(listen_port: u16, backend: SocketAddr) -> String {
    // A long window so the bucket cannot refill mid-test on a slow machine.
    format!(
        r#"listen = {{ port = {listen_port}, address_v4 = ["127.0.0.1"] }}
backends = [{{ address = "{backend}" }}]

[[domains]]
host = "127.0.0.1"
routes = [{{ prefix = "/", backend = "{backend}" }}]

[security.trusted_proxies]
cidrs = ["127.0.0.1/32"]

[security.rate_limit]
enabled = true
requests_per_second = 1
burst = {BURST}
window_seconds = 60
limit_by = "ip"
"#
    )
}

/// Send `REQUESTS` requests, each with the `X-Forwarded-For` field lines from `xff_lines(i)`,
/// and return `(allowed, limited)`.
async fn send_requests(
    xff_lines: impl Fn(usize) -> Vec<String>,
) -> Result<(usize, usize), Box<dyn std::error::Error + Send + Sync>> {
    let (backend, _backend_handle) = spawn_mock_backend("a").await?;
    let tmp = tempfile::Builder::new().suffix(".toml").tempfile()?;
    write_toml(tmp.path(), &trusted_proxy_rate_limit_toml(free_port()?, backend))?;
    let (proxy, _proxy_handle) = spawn_proxy(tmp.path(), false, 0).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut allowed = 0usize;
    let mut limited = 0usize;
    for i in 0..REQUESTS {
        let mut req = client.get(format!("http://{proxy}/"));
        // Repeated `.header()` calls with one name are sent as separate field lines.
        for line in xff_lines(i) {
            req = req.header(forwarded::FOR, line);
        }
        match req.send().await?.status().as_u16() {
            200 => allowed = allowed.saturating_add(1),
            429 => limited = limited.saturating_add(1),
            other => return Err(format!("unexpected status {other} on request {i}").into()),
        }
    }
    Ok((allowed, limited))
}

fn assert_limited(allowed: usize, limited: usize) {
    assert_eq!(allowed, BURST, "only the burst should be allowed");
    assert_eq!(limited, REQUESTS.saturating_sub(BURST), "the rest must be rate-limited");
}

/// Control: the trusted proxy reports a different client on every request, so each has its
/// own bucket. Proves the key really comes from `X-Forwarded-For` in this setup.
#[tokio::test]
async fn distinct_clients_behind_trusted_proxy_are_not_limited() -> TestResult {
    let (allowed, limited) =
        send_requests(|i| vec![format!("198.51.100.{}", i.saturating_add(1))]).await?;
    assert_eq!((allowed, limited), (REQUESTS, 0));
    Ok(())
}

/// The real client hop is in the second field line; the first line rotates. Reading only
/// the first line would give every request its own bucket.
#[tokio::test]
async fn repeated_xff_lines_do_not_bypass() -> TestResult {
    let (allowed, limited) =
        send_requests(|i| vec![format!("192.0.2.{}", i.saturating_add(1)), "198.51.100.21".into()])
            .await?;
    assert_limited(allowed, limited);
    Ok(())
}

/// The trusted hop carries a port. It must resolve to that IP, not be skipped in favour of
/// the rotating entry to its left.
#[tokio::test]
async fn hop_with_port_does_not_bypass() -> TestResult {
    let (allowed, limited) =
        send_requests(|i| vec![format!("192.0.2.{}, 198.51.100.22:51234", i.saturating_add(1))])
            .await?;
    assert_limited(allowed, limited);
    Ok(())
}

/// The rightmost hop is not an IP. The walk fails closed to the peer IP instead of stepping
/// left onto the rotating entry.
#[tokio::test]
async fn unparseable_hop_fails_closed() -> TestResult {
    let (allowed, limited) =
        send_requests(|i| vec![format!("192.0.2.{}, unknown", i.saturating_add(1))]).await?;
    assert_limited(allowed, limited);
    Ok(())
}
