use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpStream;
use tracing::warn;

use crate::proxy::synthetic_response::synthetic_error_response;
use crate::telemetry::Metrics;
use http::StatusCode;
use http_body_util::BodyExt;
use opentelemetry::KeyValue;

/// Configuration for handling plain HTTP connections
pub struct PlainConnectionConfig {
    pub routes: Vec<crate::config::Route>,
    pub backends: Arc<Vec<crate::config::Backend>>,
    pub keep_alive: crate::config::KeepAliveConfig,
    pub security: crate::proxy::SecurityContext,
    pub metrics: Option<Arc<Metrics>>,
    pub builder: ConnBuilder<TokioExecutor>,
}

/// Handle a plain HTTP connection
pub async fn handle_plain_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: PlainConnectionConfig,
) {
    let backends = config.backends.clone();
    let metrics = config.metrics.clone();
    let routes_template = config.routes.clone();
    let keep_alive = config.keep_alive.clone();
    let security = config.security.clone();

    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let routes = routes_template.clone();
        let backends = backends.clone();
        let metrics = metrics.clone();
        let keep_alive = keep_alive.clone();
        let security = security.clone();

        async move {
            let metrics_for_match = metrics.clone();
            let http_result = crate::proxy::handler::request::handle_proxy_request(
                req,
                routes,
                backends,
                None,
                None,
                &keep_alive,
                &security,
                metrics,
                peer,
                false, // is_https = false for plain HTTP connections
            )
            .await;

            match http_result {
                Ok(v) => {
                    if let Some(ref m) = metrics_for_match {
                        m.requests_total.add(
                            1,
                            &[KeyValue::new("status_code", v.status().as_u16().to_string())],
                        );
                    }
                    Ok::<_, hyper::Error>(v)
                }
                Err(e) => {
                    tracing::error!("{e}");
                    let code = StatusCode::from(e.clone());
                    if let Some(ref m) = metrics_for_match {
                        m.errors_total
                            .add(1, &[KeyValue::new("error_type", e.error_type())]);
                    }
                    match synthetic_error_response(code) {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            let body = http_body_util::Full::new(bytes::Bytes::from(format!(
                                "Failed to create error response: {e}"
                            )))
                            .map_err(|never| match never {})
                            .boxed();
                            let mut resp = hyper::Response::new(body);
                            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                            Ok(resp)
                        }
                    }
                }
            }
        }
    });

    if let Err(e) = config
        .builder
        .serve_connection(TokioIo::new(stream), svc)
        .await
    {
        warn!(?peer, error = %e, "serve_connection error");
    }
}
