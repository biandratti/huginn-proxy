use crate::telemetry::router::dispatch;
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use prometheus::Registry;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};

pub async fn start_observability_server(
    listen_addr: &str,
    port: u16,
    registry: Arc<Registry>,
    pin_path: String,
) -> crate::error::Result<()> {
    let addr = format!("{}:{}", listen_addr, port);
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "Observability server started (health, ready, live, metrics)");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(ok) => ok,
            Err(e) => {
                warn!(error = %e, "accept error");
                continue;
            }
        };

        let registry = Arc::clone(&registry);
        let pin_path = pin_path.clone();
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                let registry = registry.clone();
                let pin_path = pin_path.clone();
                async move { Ok::<_, hyper::Error>(dispatch(req.uri().path(), &registry, &pin_path)) }
            });

            let builder = ConnBuilder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                warn!(?peer, error = %e, "serve_connection error");
            }
        });
    }
}
