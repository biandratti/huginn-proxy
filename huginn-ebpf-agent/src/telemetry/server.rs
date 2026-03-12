use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use prometheus::Registry;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn};
use crate::telemetry::health;
use crate::telemetry::metrics_handler;

pub async fn start_observability_server(
    listen_addr: &str,
    port: u16,
    registry: Arc<Registry>,
    pin_path: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("{}:{}", listen_addr, port);
    let listener = TcpListener::bind(&addr).await?;
    info!(%addr, "Observability server started (metrics + ready)");

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
                async move {
                    let path = req.uri().path();
                    if path == "/metrics" {
                        match metrics_handler::handle_metrics(&registry) {
                            Ok(resp) => Ok::<_, hyper::Error>(resp),
                            Err(e) => {
                                warn!(%e, "handle_metrics failed");
                                let body = Full::new(Bytes::from("Internal Server Error"))
                                    .map_err(|never| match never {})
                                    .boxed();
                                let mut resp = Response::new(body);
                                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                Ok(resp)
                            }
                        }
                    } else if path == "/ready" {
                        match health::ready_check_response(&pin_path) {
                            Ok(resp) => Ok::<_, hyper::Error>(resp),
                            Err(e) => {
                                warn!(%e, "ready_check_response failed");
                                let body = Full::new(Bytes::from("Internal Server Error"))
                                    .map_err(|never| match never {})
                                    .boxed();
                                let mut resp = Response::new(body);
                                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                Ok(resp)
                            }
                        }
                    } else {
                        let body = Full::new(Bytes::from("Not Found"))
                            .map_err(|never| match never {})
                            .boxed();
                        let mut resp = Response::new(body);
                        *resp.status_mut() = StatusCode::NOT_FOUND;
                        Ok(resp)
                    }
                }
            });

            let builder = ConnBuilder::new(TokioExecutor::new());
            if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                warn!(?peer, error = %e, "serve_connection error");
            }
        });
    }
}
