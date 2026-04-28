use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;
use tokio::time;
use tracing::trace;

use crate::config::BackendPoolConfig;

pub type HttpHealthClient = Client<HttpConnector, Full<Bytes>>;

pub struct HealthCheckHttpClient {
    inner: HttpHealthClient,
}

impl HealthCheckHttpClient {
    /// Creates a client with the given connect timeout (seconds) and a short idle pool.
    pub fn new(connect_timeout_secs: u64) -> Self {
        let mut connector = HttpConnector::new();
        connector
            .set_connect_timeout(Some(Duration::from_secs(connect_timeout_secs.clamp(1, 300))));

        let pool = BackendPoolConfig { enabled: true, idle_timeout: 60, pool_max_idle_per_host: 1 };
        let mut builder = Client::builder(TokioExecutor::new());
        builder.pool_idle_timeout(Duration::from_secs(pool.idle_timeout));
        builder.pool_max_idle_per_host(pool.pool_max_idle_per_host);

        Self { inner: builder.build(connector) }
    }

    pub fn inner(&self) -> &HttpHealthClient {
        &self.inner
    }
}

/// `GET http://{address}{path}` with `Host: {address}`; returns `true` if the response status
/// equals `expected_status` and the body is read to completion within `timeout` (connect + TTFB
/// + drain).
pub async fn check_http(
    client: &HealthCheckHttpClient,
    address: &str,
    path: &str,
    expected_status: u16,
    timeout: Duration,
) -> bool {
    let uri: http::Uri = match format!("http://{address}{path}").parse() {
        Ok(u) => u,
        Err(_) => {
            trace!(%address, %path, "HTTP health check: invalid URI");
            return false;
        }
    };

    let req = match Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header("Host", address)
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(e) => {
            trace!(%address, %path, error = %e, "HTTP health check: request build failed");
            return false;
        }
    };

    let res = match time::timeout(timeout, client.inner().request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            trace!(%address, %path, error = %e, "HTTP health check: request failed");
            return false;
        }
        Err(_) => {
            trace!(%address, %path, "HTTP health check: request timed out");
            return false;
        }
    };

    let (parts, body) = res.into_parts();
    let ok = parts.status.as_u16() == expected_status;
    if let Err(e) = body.collect().await {
        trace!(%address, %path, error = %e, "HTTP health check: body read failed");
        return false;
    }

    trace!(
        %address,
        %path,
        status = parts.status.as_u16(),
        expected = expected_status,
        result = if ok { "ok" } else { "mismatch" },
        "HTTP health check"
    );

    ok
}
