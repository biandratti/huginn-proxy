use crate::telemetry::metrics::values;
use crate::telemetry::Metrics;
use std::sync::Arc;

use tracing::warn;

pub async fn serve_with_timeout<F, E>(
    serve_fut: F,
    timeout_duration: tokio::time::Duration,
    metrics: Arc<Metrics>,
    peer: std::net::SocketAddr,
) where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    match pingora_timeout::timeout(timeout_duration, serve_fut).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(?peer, error = %e, "serve_connection error");
        }
        Err(_) => {
            warn!(?peer, "connection handling timeout");
            metrics.record_timeout(values::TIMEOUT_CONNECTION_HANDLING);
        }
    }
}
