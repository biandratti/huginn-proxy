//! E2E test helpers and common utilities

use reqwest::Client;

/// Default proxy HTTPS URL
pub const PROXY_HTTPS_URL: &str = "https://localhost:7000";

/// Default metrics/health check server URL
pub const METRICS_URL: &str = "http://localhost:9090";

/// Default timeout for waiting for services to be ready (in seconds)
pub const DEFAULT_SERVICE_TIMEOUT_SECS: u32 = 60;

/// Default timeout for health check endpoints (in seconds)
pub const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u32 = 30;

/// Helper to wait for a service to be ready
///
/// Returns `Ok(true)` if the service becomes ready within the specified number of attempts,
/// `Ok(false)` if it doesn't become ready, or `Err` if there's an error creating the HTTP client.
pub async fn wait_for_service(
    url: &str,
    max_attempts: u32,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    for _ in 0..max_attempts {
        if client.get(url).send().await.is_ok() {
            return Ok(true);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Ok(false)
}
