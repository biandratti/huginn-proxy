use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::{TcpListener, TcpStream};
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::fingerprinting::{read_client_hello, CapturingStream};
use crate::proxy::connection::{
    ConnectionError, ConnectionManager, PrefixedStream, TlsConnectionGuard,
};
use crate::proxy::handler::headers::tls_header_value;
use crate::proxy::synthetic_response::synthetic_error_response;
use crate::telemetry::Metrics;
use crate::tls::{record_tls_handshake_metrics, setup_tls_with_hot_reload};
use http::StatusCode;
use http_body_util::BodyExt;
use opentelemetry::KeyValue;

/// Configuration for handling TLS connections
struct TlsConnectionConfig {
    tls_acceptor: Arc<tokio::sync::RwLock<Option<TlsAcceptor>>>,
    fingerprint_config: crate::config::FingerprintConfig,
    routes: Vec<crate::config::Route>,
    backends: Arc<Vec<crate::config::Backend>>,
    metrics: Option<Arc<Metrics>>,
    builder: ConnBuilder<TokioExecutor>,
}

/// Configuration for handling plain HTTP connections
struct PlainConnectionConfig {
    routes: Vec<crate::config::Route>,
    backends: Arc<Vec<crate::config::Backend>>,
    metrics: Option<Arc<Metrics>>,
    builder: ConnBuilder<TokioExecutor>,
}

/// Handle a TLS connection
async fn handle_tls_connection(
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
                    tls_header_value(&ja4)
                } else {
                    None
                };

                let _tls_guard = tls_connection_guard;

                if config.fingerprint_config.http_enabled {
                    let (fingerprint_tx, fingerprint_rx) =
                        watch::channel(None::<huginn_net_http::AkamaiFingerprint>);

                    // Create CapturingStream with inline fingerprint processing
                    let (capturing_stream, _fingerprint_extracted) = CapturingStream::new(
                        tls,
                        config.fingerprint_config.max_capture,
                        fingerprint_tx.clone(),
                        metrics_for_connection.clone(),
                    );

                    let routes_for_service = config.routes.clone();
                    let backends_for_service = config.backends.clone();
                    let tls_header_for_service = tls_header.clone();
                    let fingerprint_rx_for_service = fingerprint_rx.clone();
                    let metrics_for_service = metrics_for_connection.clone();

                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let routes = routes_for_service.clone();
                            let backends = backends_for_service.clone();
                            let tls_header = tls_header_for_service.clone();
                            let fingerprint_rx = fingerprint_rx_for_service.clone();
                            let metrics = metrics_for_service.clone();

                            async move {
                                let http_result =
                                    crate::proxy::handler::request::handle_proxy_request(
                                        req,
                                        routes,
                                        backends,
                                        tls_header,
                                        Some(fingerprint_rx),
                                        metrics.clone(),
                                    )
                                    .await;

                                match http_result {
                                    Ok(v) => {
                                        if let Some(ref m) = metrics {
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
                                        if let Some(ref m) = metrics {
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
                    let routes_for_service = config.routes.clone();
                    let backends_for_service = config.backends.clone();
                    let tls_header_for_service = tls_header.clone();
                    let metrics_for_service = metrics_for_connection.clone();

                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let routes = routes_for_service.clone();
                            let backends = backends_for_service.clone();
                            let tls_header = tls_header_for_service.clone();
                            let metrics = metrics_for_service.clone();

                            async move {
                                let http_result =
                                    crate::proxy::handler::request::handle_proxy_request(
                                        req,
                                        routes,
                                        backends,
                                        tls_header,
                                        None,
                                        metrics.clone(),
                                    )
                                    .await;

                                match http_result {
                                    Ok(v) => {
                                        if let Some(ref m) = metrics {
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
                                        if let Some(ref m) = metrics {
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

/// Handle a plain HTTP connection
async fn handle_plain_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: PlainConnectionConfig,
) {
    let routes_for_service = config.routes.clone();
    let backends_for_service = config.backends.clone();
    let metrics_for_service = config.metrics.clone();

    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let routes = routes_for_service.clone();
        let backends = backends_for_service.clone();
        let metrics = metrics_for_service.clone();

        async move {
            let http_result = crate::proxy::handler::request::handle_proxy_request(
                req,
                routes,
                backends,
                None,
                None,
                metrics.clone(),
            )
            .await;

            match http_result {
                Ok(v) => {
                    if let Some(ref m) = metrics {
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
                    if let Some(ref m) = metrics {
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

pub async fn run(config: Arc<Config>, metrics: Option<Arc<Metrics>>) -> Result<()> {
    let addr = config.listen;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(crate::error::ProxyError::Io)?;

    let builder = ConnBuilder::new(TokioExecutor::new());

    let backends = Arc::new(config.backends.clone());
    let backends_for_loop = Arc::clone(&backends);
    let routes = config.routes.clone();

    // Setup TLS with hot reload support
    let tls_acceptor = match &config.tls {
        Some(tls_config) => {
            let tls_setup = setup_tls_with_hot_reload(tls_config).await?;
            Some(tls_setup.acceptor)
        }
        None => None,
    };

    // Setup connection manager
    let shutdown_signal = Arc::new(AtomicUsize::new(0)); // 0 = running, 1 = shutdown requested
    let (connections_closed_tx, mut connections_closed_rx) = watch::channel(());
    let connection_manager = ConnectionManager::new(
        &config.security,
        shutdown_signal.clone(),
        connections_closed_tx.clone(),
    );
    let active_connections = connection_manager.active_connections();

    // Setup signal handlers
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate()).map_err(|e| {
        crate::error::ProxyError::Io(std::io::Error::other(format!(
            "Failed to setup SIGTERM handler: {e}"
        )))
    })?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt()).map_err(|e| {
        crate::error::ProxyError::Io(std::io::Error::other(format!(
            "Failed to setup SIGINT handler: {e}"
        )))
    })?;

    info!(?addr, "starting proxy");

    loop {
        tokio::select! {
            // Handle shutdown signals
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
                shutdown_signal.store(1, Ordering::Relaxed);
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
                shutdown_signal.store(1, Ordering::Relaxed);
                break;
            }
            // Accept new connections
            result = listener.accept() => {
                let (stream, peer) = match result {
                    Ok((stream, peer)) => (stream, peer),
                    Err(e) => {
                        warn!(error = %e, "accept error");
                        continue;
                    }
                };

                // Try to accept connection (checks limits and shutdown)
                let guard = match connection_manager.try_accept(peer, metrics.as_ref()) {
                    Ok(g) => g,
                    Err(ConnectionError::Shutdown) => {
                        drop(stream);
                        continue;
                    }
                    Err(ConnectionError::LimitExceeded { .. }) => {
                        drop(stream);
                        continue;
                    }
                };

                let builder_clone = builder.clone();
                let backends_clone = Arc::clone(&backends_for_loop);
                let routes_clone = routes.clone();
                let tls_acceptor_clone = tls_acceptor.clone();
                let fingerprint_config = config.fingerprint.clone();
                let metrics_clone = metrics.clone();

                let metrics_for_connection = metrics_clone.clone();
                tokio::spawn(async move {
                    let _guard = guard;

                    if let Some(ref tls_acceptor_lock) = tls_acceptor_clone {
                        handle_tls_connection(
                            stream,
                            peer,
                            TlsConnectionConfig {
                                tls_acceptor: tls_acceptor_lock.clone(),
                                fingerprint_config,
                                routes: routes_clone,
                                backends: backends_clone,
                                metrics: metrics_for_connection,
                                builder: builder_clone,
                            },
                        )
                        .await;
                    } else {
                        handle_plain_connection(
                            stream,
                            peer,
                            PlainConnectionConfig {
                                routes: routes_clone,
                                backends: backends_clone,
                                metrics: metrics_for_connection,
                                builder: builder_clone,
                            },
                        )
                        .await;
                    }
                });
            }
        }
    }

    info!(
        "Waiting for active connections to finish (timeout: {}s)",
        config.timeout.shutdown_secs
    );
    let shutdown_timeout = Duration::from_secs(config.timeout.shutdown_secs);
    let start = Instant::now();

    // Wait for either all connections to close or timeout
    let deadline = start
        .checked_add(shutdown_timeout)
        .unwrap_or_else(|| start.checked_add(Duration::from_secs(60)).unwrap_or(start));
    tokio::select! {
        _ = connections_closed_rx.changed() => {
            let active = active_connections.load(Ordering::Relaxed);
            if active == 0 {
                info!("All connections closed, shutdown complete");
            } else {
                warn!(
                    active_connections = active,
                    "Connection closed notification received but {} connections still active",
                    active
                );
            }
        }
        _ = tokio::time::sleep_until(deadline) => {
            let active = active_connections.load(Ordering::Relaxed);
            if active > 0 {
                warn!(
                    active_connections = active,
                    "Shutdown timeout reached, {} connections still active", active
                );
            } else {
                info!("All connections closed, shutdown complete");
            }
        }
    }

    info!("Proxy server stopped");
    Ok(())
}
