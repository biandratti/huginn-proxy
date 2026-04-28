//! E2E test helpers and common utilities

use reqwest::Client;
use std::collections::HashMap;

pub const PROXY_HTTPS_URL_IPV4: &str = "https://127.0.0.1:7000";

pub const PROXY_HTTPS_URL_IPV6: &str = "https://[::1]:7000";

/// Default metrics/health check server URL
pub const METRICS_URL: &str = "http://127.0.0.1:9090";

/// Default timeout for waiting for services to be ready (in seconds)
pub const DEFAULT_SERVICE_TIMEOUT_SECS: u32 = 60;

/// Default timeout for health check endpoints (in seconds)
pub const DEFAULT_HEALTH_CHECK_TIMEOUT_SECS: u32 = 30;

/// Parsed backend echo response from traefik/whoami.
///
/// Whoami returns a plain-text echo of the incoming request:
/// ```text
/// Hostname: <hostname>
/// IP: 127.0.0.1
/// RemoteAddr: <addr>
/// GET /path HTTP/1.1
/// Host: <backend-host>
/// X-Some-Header: value
/// ```
///
/// `BackendEcho` extracts the request path and all headers (keys normalised to lowercase).
#[derive(Debug, Default)]
pub struct BackendEcho {
    pub path: String,
    pub headers: HashMap<String, String>,
}

impl BackendEcho {
    /// Parse the plain-text body returned by traefik/whoami.
    pub fn parse(text: &str) -> Option<Self> {
        let mut path = None;
        let mut headers = HashMap::new();
        let mut in_headers = false;

        for line in text.lines() {
            if !in_headers {
                // HTTP request line: METHOD /path HTTP/x.x
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() == 3
                    && matches!(
                        parts[0],
                        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
                    )
                    && parts[2].starts_with("HTTP/")
                {
                    // Strip query string — whoami includes it in the request line
                    // but the proxy path tests only care about the path component.
                    let raw = parts[1];
                    path = Some(
                        raw.split_once('?')
                            .map(|(p, _)| p)
                            .unwrap_or(raw)
                            .to_string(),
                    );
                    in_headers = true;
                }
            } else if let Some((name, value)) = line.split_once(": ") {
                headers.insert(name.to_lowercase(), value.to_string());
            }
        }

        path.map(|p| BackendEcho { path: p, headers })
    }

    /// Case-insensitive header lookup. Returns `None` if the header is absent.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Case-insensitive header presence check.
    pub fn has_header(&self, name: &str) -> bool {
        self.headers.contains_key(&name.to_lowercase())
    }
}

/// Reads a response body as text and parses it as a [`BackendEcho`].
pub async fn parse_backend_echo(
    response: reqwest::Response,
) -> Result<BackendEcho, Box<dyn std::error::Error + Send + Sync>> {
    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response body: {e}"))?;
    BackendEcho::parse(&text).ok_or_else(|| "Failed to parse backend echo response".into())
}

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

pub fn metrics_contain_gate_reject(body: &str, backend: &str) -> bool {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.contains("huginn_health_check_gate_rejects_total") && line.contains(backend) {
            return true;
        }
    }
    false
}

pub fn metrics_contain_health_probe_ok(body: &str, backend: &str) -> bool {
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.contains("huginn_health_check_probes_total") {
            continue;
        }
        if line.contains(backend) && line.contains("result=\"ok\"") {
            return true;
        }
    }
    false
}
