use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tracing::warn;

use crate::fingerprinting::{read_client_hello, CapturingStream};
use crate::proxy::connection::{PrefixedStream, TlsConnectionGuard};
use crate::proxy::handler::headers::tls_header_value;
use crate::proxy::synthetic_response::synthetic_error_response;
use crate::telemetry::Metrics;
use crate::tls::record_tls_handshake_metrics;
use http::StatusCode;
use http_body_util::BodyExt;
use opentelemetry::KeyValue;

/// Configuration for handling TLS connections
pub struct TlsConnectionConfig {
    pub tls_acceptor: Arc<tokio::sync::RwLock<Option<TlsAcceptor>>>,
    pub fingerprint_config: crate::config::FingerprintConfig,
    pub routes: Vec<crate::config::Route>,
    pub backends: Arc<Vec<crate::config::Backend>>,
    pub keep_alive: crate::config::KeepAliveConfig,
    pub metrics: Option<Arc<Metrics>>,
    pub builder: ConnBuilder<TokioExecutor>,
}

/// Handle a TLS connection
pub async fn handle_tls_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    config: TlsConnectionConfig,
) {
    let metrics_for_connection = config.metrics.clone();
    let acc_opt = config.tls_acceptor.read().await.clone();
    if let Some(acc) = acc_opt {
        let handshake_start = Instant::now();
        let (prefix, ja4) =
            match read_client_hello(&mut stream, metrics_for_connection.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(?peer, error = %e, "failed to read client hello");
                    if let Some(ref m) = metrics_for_connection {
                        m.tls_handshake_errors_total.add(1, &[]);
                    }
                    return;
                }
            };

        let prefixed = PrefixedStream::new(prefix, stream);
        match acc.accept(prefixed).await {
            Ok(tls) => {
                let handshake_duration = handshake_start.elapsed().as_secs_f64();
                record_tls_handshake_metrics(
                    &tls,
                    handshake_duration,
                    metrics_for_connection.clone(),
                );

                // Create guard to decrement TLS connection metrics counter when connection closes
                // Note: The main active_connections counter is handled by ConnectionGuard
                let tls_connection_guard = TlsConnectionGuard::new(
                    metrics_for_connection
                        .as_ref()
                        .map(|m| m.tls_connections_active.clone()),
                );

                let tls_header = if config.fingerprint_config.tls_enabled {
                    tls_header_value(ja4.as_ref())
                } else {
                    None
                };

                let _tls_guard = tls_connection_guard;

                if config.fingerprint_config.http_enabled {
                    let (fingerprint_tx, fingerprint_rx) =
                        tokio::sync::watch::channel(None::<huginn_net_http::AkamaiFingerprint>);

                    // Create CapturingStream with inline fingerprint processing
                    let (capturing_stream, _fingerprint_extracted) = CapturingStream::new(
                        tls,
                        config.fingerprint_config.max_capture,
                        fingerprint_tx.clone(),
                        metrics_for_connection.clone(),
                    );

                    let backends = config.backends.clone();
                    let metrics = metrics_for_connection.clone();
                    let routes_template = config.routes.clone();
                    let keep_alive = config.keep_alive.clone();

                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let routes = routes_template.clone();
                            let backends = backends.clone();
                            let tls_header = tls_header.clone();
                            let fingerprint_rx = fingerprint_rx.clone();
                            let metrics = metrics.clone();
                            let keep_alive = keep_alive.clone();

                            async move {
                                let metrics_for_match = metrics.clone();
                                let http_result =
                                    crate::proxy::handler::request::handle_proxy_request(
                                        req,
                                        routes,
                                        backends,
                                        tls_header,
                                        Some(fingerprint_rx),
                                        &keep_alive, // Pass by reference
                                        metrics,
                                        peer,
                                        true,
                                    )
                                    .await;

                                match http_result {
                                    Ok(v) => {
                                        if let Some(ref m) = metrics_for_match {
                                            m.requests_total.add(
                                                1,
                                                &[KeyValue::new(
                                                    "status_code",
                                                    v.status().as_u16().to_string(),
                                                )],
                                            );
                                        }
                                        Ok::<_, hyper::Error>(v)
                                    }
                                    Err(e) => {
                                        tracing::error!("{e}");
                                        let code = StatusCode::from(e.clone());
                                        if let Some(ref m) = metrics_for_match {
                                            m.errors_total.add(
                                                1,
                                                &[KeyValue::new("error_type", e.error_type())],
                                            );
                                        }
                                        match synthetic_error_response(code) {
                                            Ok(resp) => Ok(resp),
                                            Err(e) => {
                                                let body = http_body_util::Full::new(
                                                    bytes::Bytes::from(format!(
                                                        "Failed to create error response: {e}"
                                                    )),
                                                )
                                                .map_err(|never| match never {})
                                                .boxed();
                                                let mut resp = hyper::Response::new(body);
                                                *resp.status_mut() =
                                                    StatusCode::INTERNAL_SERVER_ERROR;
                                                Ok(resp)
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    );

                    if let Err(e) = config
                        .builder
                        .serve_connection(TokioIo::new(capturing_stream), svc)
                        .await
                    {
                        warn!(?peer, error = %e, "serve_connection error");
                    }
                } else {
                    let backends = config.backends.clone();
                    let metrics = metrics_for_connection.clone();
                    let routes_template = config.routes.clone();
                    let keep_alive = config.keep_alive.clone();

                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let routes = routes_template.clone();
                            let backends = backends.clone();
                            let tls_header = tls_header.clone();
                            let metrics = metrics.clone();
                            let keep_alive = keep_alive.clone();

                            async move {
                                let metrics_for_match = metrics.clone();
                                let http_result =
                                    crate::proxy::handler::request::handle_proxy_request(
                                        req,
                                        routes,
                                        backends,
                                        tls_header,
                                        None,
                                        &keep_alive, // Pass by reference
                                        metrics,
                                        peer,
                                        true,
                                    )
                                    .await;

                                match http_result {
                                    Ok(v) => {
                                        if let Some(ref m) = metrics_for_match {
                                            m.requests_total.add(
                                                1,
                                                &[KeyValue::new(
                                                    "status_code",
                                                    v.status().as_u16().to_string(),
                                                )],
                                            );
                                        }
                                        Ok::<_, hyper::Error>(v)
                                    }
                                    Err(e) => {
                                        tracing::error!("{e}");
                                        let code = StatusCode::from(e.clone());
                                        if let Some(ref m) = metrics_for_match {
                                            m.errors_total.add(
                                                1,
                                                &[KeyValue::new("error_type", e.error_type())],
                                            );
                                        }
                                        match synthetic_error_response(code) {
                                            Ok(resp) => Ok(resp),
                                            Err(e) => {
                                                let body = http_body_util::Full::new(
                                                    bytes::Bytes::from(format!(
                                                        "Failed to create error response: {e}"
                                                    )),
                                                )
                                                .map_err(|never| match never {})
                                                .boxed();
                                                let mut resp = hyper::Response::new(body);
                                                *resp.status_mut() =
                                                    StatusCode::INTERNAL_SERVER_ERROR;
                                                Ok(resp)
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    );

                    if let Err(e) = config
                        .builder
                        .serve_connection(TokioIo::new(tls), svc)
                        .await
                    {
                        warn!(?peer, error = %e, "serve_connection error");
                    }
                }
            }
            Err(e) => {
                warn!(?peer, error = %e, "tls accept error");
                if let Some(ref m) = metrics_for_connection {
                    m.tls_handshake_errors_total.add(1, &[]);
                }
            }
        }
    }
}
