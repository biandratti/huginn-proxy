use std::time::Duration;

use tests_e2e::common::{
    metrics_contain_health_probe_ok, parse_backend_echo, wait_for_service,
    DEFAULT_HEALTH_CHECK_TIMEOUT_SECS, DEFAULT_SERVICE_TIMEOUT_SECS, METRICS_URL,
    PROXY_HTTPS_URL_IPV4, PROXY_HTTPS_URL_IPV6,
};

const HTTP_HEALTH_BACKEND: &str = "backend-a:9000";
/// `compose.yaml` maps `/api/...` to `backend-a:9000`, which has an HTTP `GET /` health probe.
const ROUTE_TO_HTTP_HEALTH_BACKEND: &str = "/api/e2e-active-http-health";

/// Request through the proxy to a route whose backend has **HTTP** health checks enabled → 200 and whoami body.
#[tokio::test]
async fn test_proxy_200_when_backend_has_http_health_check(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_proxy_200_http_health_impl(PROXY_HTTPS_URL_IPV4).await
}

#[tokio::test]
async fn test_proxy_200_when_backend_has_http_health_check_ipv6(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    test_proxy_200_http_health_impl(PROXY_HTTPS_URL_IPV6).await
}

async fn test_proxy_200_http_health_impl(
    base: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(base, DEFAULT_SERVICE_TIMEOUT_SECS).await?,
        "Proxy should be ready"
    );
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("build client: {e}"))?;
    let url = format!("{base}{ROUTE_TO_HTTP_HEALTH_BACKEND}");
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let echo = parse_backend_echo(response).await?;
    assert_eq!(echo.path, ROUTE_TO_HTTP_HEALTH_BACKEND);
    Ok(())
}

/// Compose enables HTTP health checks for `backend-a:9000`; `/metrics` must show successful probes
/// (`result="ok"`) for that backend.
#[tokio::test]
async fn test_active_http_health_probes_appear_in_metrics(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Metrics endpoint should be ready"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .map_err(|e| format!("GET /metrics: {e}"))?;
    let body = response
        .text()
        .await
        .map_err(|e| format!("read body: {e}"))?;
    assert!(
        metrics_contain_health_probe_ok(&body, HTTP_HEALTH_BACKEND),
        "expected huginn_health_check_probes_total with backend {HTTP_HEALTH_BACKEND} and result=ok; got snippet (truncated): {:?}",
        body.chars().take(500).collect::<String>()
    );
    Ok(())
}

#[tokio::test]
async fn test_health_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/health"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Health endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/health"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /health: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_ready_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/ready"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Ready endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/ready"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /ready: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_live_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/live"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS).await?,
        "Live endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/live"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /live: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn test_metrics_endpoint() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    assert!(
        wait_for_service(&format!("{METRICS_URL}/metrics"), DEFAULT_HEALTH_CHECK_TIMEOUT_SECS)
            .await?,
        "Metrics endpoint should be ready"
    );

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{METRICS_URL}/metrics"))
        .send()
        .await
        .map_err(|e| format!("Failed to send request to /metrics: {e}"))?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    assert!(
        body.contains("huginn_") || body.contains("# TYPE"),
        "Should contain metrics format"
    );
    Ok(())
}
