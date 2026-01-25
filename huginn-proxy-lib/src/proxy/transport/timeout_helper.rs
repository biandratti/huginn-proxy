use std::sync::Arc;
use tracing::warn;

use crate::telemetry::Metrics;
use opentelemetry::KeyValue;

/// Helper function to handle connection serving with timeout
///
/// This function wraps a connection serving future and applies a timeout.
/// If the timeout is exceeded, it logs a warning and records a metric.
/// If the connection fails, it logs the error.
pub async fn serve_with_timeout<F, E>(
    serve_fut: F,
    timeout_duration: tokio::time::Duration,
    metrics: Option<Arc<Metrics>>,
    peer: std::net::SocketAddr,
) where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    match tokio::time::timeout(timeout_duration, serve_fut).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(?peer, error = %e, "serve_connection error");
        }
        Err(_) => {
            warn!(?peer, "connection handling timeout");
            if let Some(ref m) = metrics {
                m.timeouts_total
                    .add(1, &[KeyValue::new("type", "connection_handling")]);
            }
        }
    }
}
