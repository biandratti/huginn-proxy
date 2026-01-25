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
    pub security: crate::proxy::SecurityContext,
    pub metrics: Option<Arc<Metrics>>,
    pub builder: ConnBuilder<TokioExecutor>,
    pub preserve_host: bool,
    pub tls_handshake_timeout: tokio::time::Duration,
    pub connection_handling_timeout: Option<tokio::time::Duration>,
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
        let tls_accept_result =
            tokio::time::timeout(config.tls_handshake_timeout, acc.accept(prefixed)).await;

        let tls = match tls_accept_result {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
        warn!(?peer, error = %e, "TLS accept failed");
        if let Some(ref m) = metrics_for_connection {
            m.tls_handshake_errors_total.add(1, &[]);
        }
        return;
            }
            Err(_) => {
        warn!(?peer, "TLS handshake timeout");
        if let Some(ref m) = metrics_for_connection {
            m.timeouts_total
                .add(1, &[opentelemetry::KeyValue::new("type", "tls_handshake")]);
            m.tls_handshake_errors_total.add(1, &[]);
        }
        return;
            }
        };

        let handshake_duration = handshake_start.elapsed().as_secs_f64();
        record_tls_handshake_metrics(&tls, handshake_duration, metrics_for_connection.clone());

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
            let security = config.security.clone();

            let svc = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let routes = routes_template.clone();
                    let backends = backends.clone();
                    let tls_header = tls_header.clone();
                    let fingerprint_rx = fingerprint_rx.clone();
                    let metrics = metrics.clone();
                    let keep_alive = keep_alive.clone();
                    let security = security.clone();

                    async move {
                        let metrics_for_match = metrics.clone();
                        let preserve_host = config.preserve_host;
                        let http_result =
                            crate::proxy::handler::request::handle_proxy_request(
                                req,
                                routes,
                                backends,
                                tls_header,
                                Some(fingerprint_rx),
                                &keep_alive,
                                &security,
                                metrics,
                                peer,
                                true,
                                preserve_host,
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

            let serve_fut = config
                .builder
                .serve_connection(TokioIo::new(capturing_stream), svc);

            if let Some(timeout_duration) = config.connection_handling_timeout {
                match tokio::time::timeout(timeout_duration, serve_fut).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(?peer, error = %e, "serve_connection error");
                    }
                    Err(_) => {
                        warn!(?peer, "connection handling timeout");
                        if let Some(ref m) = metrics_for_connection {
                            m.timeouts_total
                                .add(1, &[KeyValue::new("type", "connection_handling")]);
                        }
                    }
                }
            } else if let Err(e) = serve_fut.await {
                warn!(?peer, error = %e, "serve_connection error");
            }
        } else {
            let backends = config.backends.clone();
            let metrics = metrics_for_connection.clone();
            let routes_template = config.routes.clone();
            let keep_alive = config.keep_alive.clone();
            let security = config.security.clone();

            let svc = hyper::service::service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| {
                    let routes = routes_template.clone();
                    let backends = backends.clone();
                    let tls_header = tls_header.clone();
                    let metrics = metrics.clone();
                    let keep_alive = keep_alive.clone();
                    let security = security.clone();

                    async move {
                        let preserve_host = config.preserve_host;
                        let metrics_for_match = metrics.clone();
                        let http_result =
                            crate::proxy::handler::request::handle_proxy_request(
                                req,
                                routes,
                                backends,
                                tls_header,
                                None,
                                &keep_alive,
                                &security,
                                metrics,
                                peer,
                                true,
                                preserve_host,
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

            let serve_fut = config.builder.serve_connection(TokioIo::new(tls), svc);

            if let Some(timeout_duration) = config.connection_handling_timeout {
                match tokio::time::timeout(timeout_duration, serve_fut).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        warn!(?peer, error = %e, "serve_connection error");
                    }
                    Err(_) => {
                        warn!(?peer, "connection handling timeout");
                        if let Some(ref m) = metrics_for_connection {
                            m.timeouts_total
                                .add(1, &[KeyValue::new("type", "connection_handling")]);
                        }
                    }
                }
            } else if let Err(e) = serve_fut.await {
                warn!(?peer, error = %e, "serve_connection error");
            }
        }
    } else {
        warn!(?peer, "TLS acceptor not initialized");
    }
}
