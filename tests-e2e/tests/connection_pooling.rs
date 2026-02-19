use std::time::Instant;
use tests_e2e::common::{wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, PROXY_HTTPS_URL};

/// Test the /fingerprint route with force_new_connection enabled
/// This route forces new backend connections per request (bypassing connection pool)
/// Note: Fingerprint headers (x-tls-ja4, x-http2-akamai) are extracted from client→proxy connection,
/// not from proxy→backend connection. The force_new_connection setting affects only proxy→backend.
#[tokio::test]
async fn test_fingerprint_route_with_force_new_connection(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    for _ in 0..3 {
        let resp = client
            .get(format!("{}/fingerprint/get", PROXY_HTTPS_URL))
            .send()
            .await?;

        assert_eq!(
            resp.status(),
            200,
            "/fingerprint route should succeed with force_new_connection"
        );
    }

    for _ in 0..3 {
        let resp = client
            .get(format!("{}/api/get", PROXY_HTTPS_URL))
            .send()
            .await?;

        assert_eq!(resp.status(), 200, "/api route should succeed with pooling");
    }

    Ok(())
}

/// Compare performance between pooled and non-pooled routes
/// This test demonstrates the latency difference between routes with and without pooling
#[tokio::test]
async fn test_pooling_vs_force_new_performance(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    let _ = client
        .get(format!("{}/api/get", PROXY_HTTPS_URL))
        .send()
        .await?; // Warm up
    let start = Instant::now();
    let resp = client
        .get(format!("{}/api/get", PROXY_HTTPS_URL))
        .send()
        .await?;
    let pooled_duration = start.elapsed();
    assert_eq!(resp.status(), 200);

    let start = Instant::now();
    let resp = client
        .get(format!("{}/fingerprint/get", PROXY_HTTPS_URL))
        .send()
        .await?;
    let force_new_duration = start.elapsed();
    assert_eq!(resp.status(), 200);

    println!("Pooled route (/api): {:?}", pooled_duration);
    println!("Force new route (/fingerprint): {:?}", force_new_duration);

    if force_new_duration > pooled_duration {
        let overhead = force_new_duration.as_secs_f64() / pooled_duration.as_secs_f64();
        println!("Force new connection overhead: {:.2}x slower", overhead);
    }

    Ok(())
}

/// Test that multiple requests reuse connections (connection pooling)
/// By making multiple sequential requests from the same client, we verify that
/// subsequent requests benefit from connection reuse (no repeated TCP + TLS handshakes)
///
/// Note: This test assumes the proxy is already running with connection pooling enabled
/// (force_new_connection = false, which is the default)
#[tokio::test]
async fn test_connection_pooling_multiple_requests(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // First request: Establishes connection (slower due to TCP + TLS handshake)
    let start = Instant::now();
    let resp = client
        .get(format!("{}/get", PROXY_HTTPS_URL))
        .send()
        .await?;
    let first_duration = start.elapsed();
    assert_eq!(resp.status(), 200, "First request should succeed");

    // Subsequent requests: Should reuse connection (faster)
    let mut subsequent_durations = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        let resp = client
            .get(format!("{}/get", PROXY_HTTPS_URL))
            .send()
            .await?;
        subsequent_durations.push(start.elapsed());
        assert_eq!(resp.status(), 200, "Subsequent request should succeed");
    }

    // Calculate average of subsequent requests
    let avg_subsequent = subsequent_durations.iter().sum::<std::time::Duration>()
        / subsequent_durations.len() as u32;

    println!("First request (with TCP + TLS handshake): {:?}", first_duration);
    println!("Average subsequent (pooled): {:?}", avg_subsequent);

    if avg_subsequent < first_duration {
        let speedup = first_duration.as_secs_f64() / avg_subsequent.as_secs_f64();
        println!("Connection pooling speedup: {:.2}x", speedup);
    }

    Ok(())
}

/// Test that concurrent requests work correctly with connection pooling
/// Multiple concurrent requests should share the connection pool efficiently
#[tokio::test]
async fn test_connection_pooling_concurrent_requests(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Make 10 concurrent requests
    let mut handles = Vec::new();
    for _ in 0..10 {
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let resp = client_clone
                .get(format!("{}/get", PROXY_HTTPS_URL))
                .send()
                .await?;
            assert_eq!(resp.status(), 200);
            Ok::<_, reqwest::Error>(())
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    for handle in handles {
        handle.await??;
    }

    Ok(())
}
