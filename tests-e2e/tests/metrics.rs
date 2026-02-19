use tests_e2e::common::{
    wait_for_service, DEFAULT_SERVICE_TIMEOUT_SECS, METRICS_URL, PROXY_HTTPS_URL,
};

async fn fetch_metrics() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let response = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .map_err(|e| format!("Failed to fetch metrics: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("Metrics endpoint returned {}", response.status()).into());
    }

    response
        .text()
        .await
        .map_err(|e| format!("Failed to read metrics response: {e}").into())
}

fn metric_exists(metrics: &str, metric_prefix: &str) -> bool {
    metrics
        .lines()
        .any(|line| !line.starts_with('#') && line.starts_with(metric_prefix))
}

#[tokio::test]
async fn test_metrics_endpoint_available() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Metrics endpoint should be available"
    );

    let metrics = fetch_metrics().await?;
    assert!(!metrics.is_empty(), "Metrics should not be empty");

    Ok(())
}

#[tokio::test]
async fn test_build_info_metric() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Metrics endpoint should be available"
    );

    let metrics = fetch_metrics().await?;

    assert!(
        metric_exists(&metrics, "huginn_build_info"),
        "huginn_build_info metric should exist"
    );

    let found_build_info = metrics.lines().any(|line| {
        !line.starts_with('#')
            && line.starts_with("huginn_build_info")
            && line.contains("version=")
            && line.contains("rust_version=")
    });

    assert!(
        found_build_info,
        "huginn_build_info should have version and rust_version labels"
    );

    Ok(())
}

#[tokio::test]
async fn test_request_metrics_increment() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for _ in 0..5 {
        let _response = client.get(PROXY_HTTPS_URL).send().await?;
    }

    let metrics = fetch_metrics().await?;

    assert!(
        metric_exists(&metrics, "huginn_requests_total"),
        "huginn_requests_total should exist"
    );

    assert!(
        metric_exists(&metrics, "huginn_connections_total"),
        "huginn_connections_total should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_backend_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for _ in 0..3 {
        let _response = client.get(PROXY_HTTPS_URL).send().await?;
    }

    let metrics = fetch_metrics().await?;

    assert!(
        metric_exists(&metrics, "huginn_backend_requests_total"),
        "huginn_backend_requests_total should exist"
    );

    assert!(
        metric_exists(&metrics, "huginn_backend_duration_seconds"),
        "huginn_backend_duration_seconds should exist"
    );

    assert!(
        metric_exists(&metrics, "huginn_backend_selections_total"),
        "huginn_backend_selections_total should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_tls_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for _ in 0..3 {
        let _response = client.get(PROXY_HTTPS_URL).send().await?;
    }

    let metrics = fetch_metrics().await?;

    assert!(
        metric_exists(&metrics, "huginn_tls_handshakes_total"),
        "huginn_tls_handshakes_total should exist"
    );

    assert!(
        metric_exists(&metrics, "huginn_tls_handshake_duration_seconds"),
        "huginn_tls_handshake_duration_seconds should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_throughput_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for _ in 0..3 {
        let _response = client.get(PROXY_HTTPS_URL).send().await?;
    }

    let metrics = fetch_metrics().await?;

    assert!(
        metric_exists(&metrics, "huginn_bytes_sent_total"),
        "huginn_bytes_sent_total should exist (will be exported as *_total_total)"
    );

    assert!(
        metric_exists(&metrics, "huginn_backend_bytes_received_total"),
        "huginn_backend_bytes_received_total should exist"
    );

    Ok(())
}

#[tokio::test]
async fn test_per_route_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(PROXY_HTTPS_URL, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    let _response = client
        .get(format!("{PROXY_HTTPS_URL}/api/test"))
        .send()
        .await?;
    let _response = client
        .get(format!("{PROXY_HTTPS_URL}/other"))
        .send()
        .await?;

    let metrics = fetch_metrics().await?;

    let has_route_label = metrics.lines().any(|line| {
        !line.starts_with('#')
            && (line.starts_with("huginn_requests_total") || line.starts_with("huginn_backend"))
            && line.contains("route=")
    });

    assert!(has_route_label, "Metrics should include route label for per-route tracking");

    Ok(())
}

#[tokio::test]
async fn test_rate_limit_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Metrics endpoint should be available"
    );

    let metrics = fetch_metrics().await?;

    let has_rate_limit_definitions = metrics.lines().any(|line| {
        line.starts_with("# HELP huginn_rate_limit") || line.starts_with("# TYPE huginn_rate_limit")
    });

    if has_rate_limit_definitions {
        assert!(
            metrics.contains("huginn_rate_limit_requests_total")
                || metrics.contains("huginn_rate_limit_allowed_total")
                || metrics.contains("huginn_rate_limit_rejected_total"),
            "Rate limit metrics should be present if rate limiting is configured"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_ip_filter_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Note: This test assumes IP filtering is configured
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Metrics endpoint should be available"
    );

    let metrics = fetch_metrics().await?;

    let has_ip_filter_definitions = metrics.lines().any(|line| {
        line.starts_with("# HELP huginn_ip_filter") || line.starts_with("# TYPE huginn_ip_filter")
    });

    if has_ip_filter_definitions {
        assert!(
            metrics.contains("huginn_ip_filter_requests_total")
                || metrics.contains("huginn_ip_filter_allowed_total")
                || metrics.contains("huginn_ip_filter_denied_total"),
            "IP filter metrics should be present if IP filtering is configured"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_header_manipulation_metrics() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Metrics endpoint should be available"
    );

    let metrics = fetch_metrics().await?;

    let has_header_metrics_definitions = metrics.lines().any(|line| {
        line.starts_with("# HELP huginn_headers") || line.starts_with("# TYPE huginn_headers")
    });

    if has_header_metrics_definitions {
        assert!(
            metrics.contains("huginn_headers_added_total")
                || metrics.contains("huginn_headers_removed_total"),
            "Header manipulation metrics should be present if configured"
        );
    }

    Ok(())
}
