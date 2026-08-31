use crate::proxy::shutdown::ShutdownWatch;
use crate::telemetry::metrics::values;
use crate::telemetry::Metrics;
use hyper::body::{Body, Incoming};
use hyper::rt::{Read, Write};
use hyper::service::HttpService;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::{Connection, HttpServerConnExec};
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::{debug, warn};

/// HTTP connection future that can emit GOAWAY / `Connection: close`.
pub trait GracefulShutdown {
    fn graceful_shutdown(self: Pin<&mut Self>);
}

impl<I, S, B> GracefulShutdown for Connection<'static, I, S, TokioExecutor>
where
    S: HttpService<Incoming, ResBody = B>,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    I: Read + Write + Unpin + Send + 'static,
    B: Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    TokioExecutor: HttpServerConnExec<S::Future, B>,
{
    fn graceful_shutdown(self: Pin<&mut Self>) {
        Connection::graceful_shutdown(self);
    }
}

pub async fn serve_with_timeout<C, Err>(
    mut serve_fut: Pin<Box<C>>,
    timeout_duration: tokio::time::Duration,
    mut shutdown_rx: ShutdownWatch,
    metrics: Arc<Metrics>,
    peer: std::net::SocketAddr,
) where
    C: Future<Output = Result<(), Err>> + GracefulShutdown,
    Err: Display,
{
    let mut goaway_sent = false;
    let start = tokio::time::Instant::now();
    let deadline = crate::utils::deadline_from(start, timeout_duration);

    loop {
        tokio::select! {
            result = serve_fut.as_mut() => {
                match result {
                    Ok(()) => {}
                    Err(e) => {
                        debug!(?peer, reason = %e, "connection ended");
                    }
                }
                return;
            }
            _ = shutdown_rx.wait_for(|phase| phase.is_stopping()), if !goaway_sent => {
                serve_fut.as_mut().graceful_shutdown();
                goaway_sent = true;
            }
            _ = tokio::time::sleep_until(deadline) => {
                warn!(?peer, "connection handling timeout");
                metrics.record_timeout(values::TIMEOUT_CONNECTION_HANDLING);
                return;
            }
        }
    }
}
