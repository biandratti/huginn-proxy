use crate::config::HealthFormat;
use crate::telemetry::router::dispatch;
use crate::telemetry::Readiness;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use prometheus::Registry;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{info, warn};

/// Start the observability server that handles metrics and health checks
/// This server runs on a dedicated port and serves:
/// - `/metrics` - Prometheus metrics
/// - `/health` - Health check endpoint
/// - `/ready` - Readiness check endpoint
/// - `/live` - Liveness check endpoint
///
/// `readiness` is flipped to `true` by the proxy once its listeners are accepting
/// connections and back to `false` during graceful shutdown; `/ready` reflects it.
///
/// Shutdown is **not** tied to SIGTERM: the process signal is used for traffic
/// drain. `main` sends `true` on `stop_rx` after `run()` returns.
pub async fn start_observability_server(
    port: u16,
    registry: Registry,
    readiness: Readiness,
    format: HealthFormat,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let registry = Arc::new(registry);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    info!(?addr, "Observability server started (metrics + health checks)");

    loop {
        tokio::select! {
            _ = stop_rx.wait_for(|stop| *stop) => {
                info!("Observability server: stop requested, shutting down");
                break;
            }
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok((stream, peer)) => (stream, peer),
                    Err(e) => {
                        warn!(error = %e, "Observability server: accept error");
                        continue;
                    }
                };

                let registry = registry.clone();
                let readiness = readiness.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let registry = registry.clone();
                        let readiness = readiness.clone();
                        async move {
                            Ok::<_, hyper::Error>(dispatch(
                                req.uri().path(),
                                &registry,
                                &readiness,
                                format,
                            ))
                        }
                    });

                    let builder = ConnBuilder::new(TokioExecutor::new());
                    if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                        warn!(?peer, error = %e, "Observability server: serve_connection error");
                    }
                });
            }
        }
    }

    info!("Observability server stopped");
    Ok(())
}
