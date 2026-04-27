//! E2E tests for load balancing

use tests_e2e::common::{
    parse_backend_echo, wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL_IPV4,
    PROXY_HTTPS_URL_IPV6,
};

async fn test_round_robin_load_balance_impl(
    base_url: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(base_url, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let mut backend_a_hits = 0usize;
    let mut backend_b_hits = 0usize;
    let requests = 20usize;
    let mut observed_hosts = Vec::with_capacity(requests);

    for _ in 0..requests {
        let response = client
            .get(format!("{base_url}/lb/e2e-round-robin"))
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {e}"))?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let echo = parse_backend_echo(response).await?;
        let host = echo
            .header("host")
            .ok_or("missing Host header in backend echo response")?;
        observed_hosts.push(host.to_string());

        match host {
            "backend-a:9000" => backend_a_hits += 1,
            "backend-b:9000" => backend_b_hits += 1,
            other => return Err(format!("unexpected backend host observed: {other}").into()),
        }
    }

    assert!(
        backend_a_hits > 0 && backend_b_hits > 0,
        "expected requests to hit both backends; got backend-a={backend_a_hits}, backend-b={backend_b_hits}"
    );

    let diff = backend_a_hits.abs_diff(backend_b_hits);
    // With a deterministic round-robin policy and an even request count,
    // distribution should be near 50/50. Keep a small tolerance to avoid
    // flakiness from occasional environmental noise.
    let max_allowed_skew = 2usize;
    assert!(
        diff <= max_allowed_skew,
        "expected near-even round-robin distribution across {requests} requests; got backend-a={backend_a_hits}, backend-b={backend_b_hits}, diff={diff}, allowed={max_allowed_skew}, observed={observed_hosts:?}"
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_round_robin_load_balance() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_round_robin_load_balance_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
#[serial_test::serial]
async fn test_round_robin_load_balance_ipv6() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    test_round_robin_load_balance_impl(PROXY_HTTPS_URL_IPV6).await
}
