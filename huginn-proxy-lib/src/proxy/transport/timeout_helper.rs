use std::sync::Arc;
use tracing::warn;

use crate::telemetry::Metrics;
use opentelemetry::KeyValue;

/// Helper function to handle connection serving with optional timeout
///
/// This function wraps a connection serving future and applies an optional timeout.
/// If the timeout is exceeded, it logs a warning and records a metric.
/// If the connection fails, it logs the error.
pub async fn serve_with_timeout<F, E>(
    serve_fut: F,
    timeout_duration: Option<tokio::time::Duration>,
    metrics: Option<Arc<Metrics>>,
    peer: std::net::SocketAddr,
) where
    F: std::future::Future<Output = Result<(), E>>,
    E: std::fmt::Display,
{
    if let Some(timeout) = timeout_duration {
        match tokio::time::timeout(timeout, serve_fut).await {
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
    } else if let Err(e) = serve_fut.await {
        warn!(?peer, error = %e, "serve_connection error");
    }
}
