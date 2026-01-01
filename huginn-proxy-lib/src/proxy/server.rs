use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Version;
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use opentelemetry::KeyValue;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::fingerprinting::{read_client_hello, CapturingStream};
use crate::proxy::forwarding::forward;
use crate::proxy::http_result::{HttpError, HttpResult};
use crate::proxy::synthetic_response::synthetic_error_response;
use crate::telemetry::Metrics;
use crate::tls::{record_tls_handshake_metrics, setup_tls_with_hot_reload};
use http::StatusCode;
use huginn_net_http::AkamaiFingerprint;

struct PrefixedStream<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self { prefix, offset: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.offset < self.prefix.len() {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset = self.offset.saturating_add(to_copy);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn akamai_header_value(value: &Option<AkamaiFingerprint>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.fingerprint).ok())
}

fn tls_header_value(value: &Option<huginn_net_tls::Ja4Payload>) -> Option<HeaderValue> {
    value
        .as_ref()
        .and_then(|f| HeaderValue::from_str(&f.full.to_string()).ok())
}

/// Guard to decrement active connections counter when dropped
struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
    notifier: Option<watch::Sender<()>>,
}

impl ConnectionGuard {
    fn new(counter: Arc<AtomicUsize>, notifier: watch::Sender<()>) -> Self {
        Self { counter, notifier: Some(notifier) }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let remaining = self.counter.fetch_sub(1, Ordering::Relaxed);
        // Notify when the last connection closes
        if remaining == 1 {
            if let Some(ref tx) = self.notifier {
                let _ = tx.send(());
            }
        }
    }
}

struct TlsConnectionGuard {
    active_connections: Arc<AtomicUsize>,
    tls_active: Option<opentelemetry::metrics::UpDownCounter<i64>>,
}

impl Drop for TlsConnectionGuard {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
        if let Some(ref counter) = self.tls_active {
            counter.add(-1, &[]);
        }
    }
}

type RespBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

/// Handle request routing and forwarding
#[allow(clippy::too_many_arguments)]
async fn handle_proxy_request(
    mut req: Request<Incoming>,
    routes: Vec<crate::config::Route>,
    backends: Arc<Vec<crate::config::Backend>>,
    tls_header: Option<HeaderValue>,
    fingerprint_rx: Option<watch::Receiver<Option<huginn_net_http::AkamaiFingerprint>>>,
    metrics: Option<Arc<Metrics>>,
) -> HttpResult<hyper::Response<RespBody>> {
    let start = Instant::now();
    let method = req.method().to_string();
    let protocol = format!("{:?}", req.version());

    // Route selection (determine backend and fingerprinting configuration)
    let path = req.uri().path();
    let (backend, should_fingerprint) = if let Some((target, fingerprinting)) =
        crate::proxy::forwarding::pick_route_with_fingerprinting(path, &routes)
    {
        // Route matched: use route's fingerprinting configuration
        let backend_str = target.to_string();
        if let Some(ref m) = metrics {
            m.backend_selections_total
                .add(1, &[KeyValue::new("backend", backend_str.clone())]);
        }
        (backend_str, fingerprinting)
    } else {
        // No route matched: return 404 (consistent with rust-rpxy and Traefik)
        let error = HttpError::NoMatchingRoute;
        if let Some(ref m) = metrics {
            m.errors_total
                .add(1, &[KeyValue::new("error_type", error.error_type())]);
        }
        return Err(error);
    };

    if should_fingerprint {
        if let Some(hv) = tls_header {
            req.headers_mut()
                .insert(HeaderName::from_static("x-huginn-net-tls"), hv);
        }
        if let Some(ref rx) = fingerprint_rx {
            if req.version() == Version::HTTP_2 {
                let akamai = rx.borrow().clone();
                debug!("Handler: akamai fingerprint: {:?}", akamai);
                if let Some(hv) = akamai_header_value(&akamai) {
                    debug!("Handler: injecting x-huginn-net-http header: {:?}", hv);
                    req.headers_mut()
                        .insert(HeaderName::from_static("x-huginn-net-http"), hv);
                } else {
                    debug!("Handler: no HTTP fingerprint header to inject (HTTP/2 connection but fingerprint not extracted)");
                    // Record failure metric if metrics available
                    if let Some(ref m) = metrics {
                        m.http2_fingerprint_failures_total.add(1, &[]);
                    }
                }
            } else {
                // HTTP/1.1 connection - Akamai fingerprint not applicable
                debug!("Handler: HTTP/1.1 connection, Akamai fingerprint not applicable");
                if let Some(ref m) = metrics {
                    m.http2_fingerprint_failures_total.add(1, &[]);
                }
            }
        }
    }

    // Forward request
    let result = forward(req, backend.clone(), &backends, metrics.clone()).await;

    let duration = start.elapsed().as_secs_f64();
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(e) => {
            let code: StatusCode = (*e).clone().into();
            code.as_u16()
        }
    };

    if let Some(ref m) = metrics {
        m.requests_total.add(
            1,
            &[
                KeyValue::new("method", method.clone()),
                KeyValue::new("status_code", status_code.to_string()),
                KeyValue::new("protocol", protocol.clone()),
            ],
        );
        m.requests_duration_seconds.record(
            duration,
            &[
                KeyValue::new("method", method),
                KeyValue::new("status_code", status_code.to_string()),
                KeyValue::new("protocol", protocol),
            ],
        );
    }

    result
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

    // Track active connections for graceful shutdown
    let active_connections = Arc::new(AtomicUsize::new(0));
    let shutdown_signal = Arc::new(AtomicUsize::new(0)); // 0 = running, 1 = shutdown requested
                                                         // Channel to notify when all connections are closed
    let (connections_closed_tx, mut connections_closed_rx) = watch::channel(());

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

                // Check if shutdown was requested
                if shutdown_signal.load(Ordering::Relaxed) == 1 {
                    info!("Shutdown requested, rejecting new connection");
                    drop(stream); // Close the connection
                    continue;
                }

                // Check connection limit (DoS protection)
                let current_connections = active_connections.load(Ordering::Relaxed);
                if current_connections >= config.security.max_connections {
                    if let Some(ref m) = metrics {
                        m.connections_rejected_total.add(1, &[]);
                    }
                    warn!(
                        current = current_connections,
                        limit = config.security.max_connections,
                        peer = %peer,
                        "Connection limit exceeded, rejecting connection"
                    );
                    drop(stream); // Close the connection
                    continue;
                }

                // Increment active connections counter
                active_connections.fetch_add(1, Ordering::Relaxed);

                if let Some(ref m) = metrics {
                    m.connections_total.add(1, &[]);
                    m.connections_active.add(1, &[]);
                }

                let builder = builder.clone();
                let backends_clone = Arc::clone(&backends_for_loop);
                let routes = routes.clone();
                let tls_acceptor = tls_acceptor.clone();
                let active_connections = active_connections.clone();
                let fingerprint_config = config.fingerprint.clone();
                let metrics_clone = metrics.clone();

                let metrics_for_connection = metrics_clone.clone();
                let connections_closed_tx = connections_closed_tx.clone();
                tokio::spawn(async move {
                    // Ensure counter is decremented when connection finishes
                    let active_connections_clone = active_connections.clone();
                    let _guard = ConnectionGuard::new(active_connections_clone.clone(), connections_closed_tx);
                    let mut stream = stream;

                    if let Some(ref m) = metrics_for_connection {
                        m.connections_active.add(-1, &[]);
                    }

                    if let Some(ref tls_acceptor_lock) = tls_acceptor {
                        let acc_opt = tls_acceptor_lock.read().await.clone();
                        if let Some(acc) = acc_opt {
                        let handshake_start = Instant::now();
                        let (prefix, ja4) = match read_client_hello(&mut stream, metrics_for_connection.clone()).await {
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
                                record_tls_handshake_metrics(&tls, handshake_duration, metrics_for_connection.clone());

                                // Create guard to decrement TLS connection counter when connection closes
                                let tls_connection_guard = if let Some(ref m) = metrics_for_connection {
                                    TlsConnectionGuard {
                                        active_connections: active_connections_clone.clone(),
                                        tls_active: Some(m.tls_connections_active.clone()),
                                    }
                                } else {
                                    TlsConnectionGuard {
                                        active_connections: active_connections_clone.clone(),
                                        tls_active: None,
                                    }
                                };

                                let tls_header = if fingerprint_config.tls_enabled {
                                    tls_header_value(&ja4)
                                } else {
                                    None
                                };

                                let _tls_guard = tls_connection_guard;

                                if fingerprint_config.http_enabled {
                                    let (fingerprint_tx, fingerprint_rx) = watch::channel(None::<huginn_net_http::AkamaiFingerprint>);

                                    // Create CapturingStream with inline fingerprint processing
                                    let (capturing_stream, _fingerprint_extracted) =
                                        CapturingStream::new(tls, fingerprint_config.max_capture, fingerprint_tx.clone(), metrics_for_connection.clone());

                                    let metrics_for_service = metrics_for_connection.clone();
                                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                                        let routes = routes.clone();
                                        let backends = backends_clone.clone();
                                        let tls_header = tls_header.clone();
                                        let fingerprint_rx = fingerprint_rx.clone();
                                        let metrics = metrics_for_service.clone();

                                        async move {
                                            let http_result = handle_proxy_request(
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
                                                            use http_body_util::BodyExt;
                                                            let body = http_body_util::Full::new(
                                                                bytes::Bytes::from(format!("Failed to create error response: {e}"))
                                                            )
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

                                    if let Err(e) = builder
                                        .serve_connection(TokioIo::new(capturing_stream), svc)
                                        .await
                                    {
                                        warn!(?peer, error = %e, "serve_connection error");
                                    }
                                } else {
                                    let metrics_for_service = metrics_for_connection.clone();
                                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                                        let routes = routes.clone();
                                        let backends = backends_clone.clone();
                                        let tls_header = tls_header.clone();
                                        let metrics = metrics_for_service.clone();

                                        async move {
                                            let http_result = handle_proxy_request(
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
                                                            use http_body_util::BodyExt;
                                                            let body = http_body_util::Full::new(
                                                                bytes::Bytes::from(format!("Failed to create error response: {e}"))
                                                            )
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

                                    if let Err(e) = builder
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
                    } else {
                        let metrics_for_service = metrics_for_connection.clone();
                        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                            let routes = routes.clone();
                            let backends = backends_clone.clone();
                            let metrics = metrics_for_service.clone();

                            async move {
                                let http_result = handle_proxy_request(
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
                                                use http_body_util::BodyExt;
                                                let body = http_body_util::Full::new(
                                                    bytes::Bytes::from(format!("Failed to create error response: {e}"))
                                                )
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

                        if let Err(e) = builder.serve_connection(TokioIo::new(stream), svc).await {
                            warn!(?peer, error = %e, "serve_connection error");
                        }
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
