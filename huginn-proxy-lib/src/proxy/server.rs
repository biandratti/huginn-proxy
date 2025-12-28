use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

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
use tokio::time::{sleep, Duration, Instant};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::fingerprinting::{process_captured_bytes, CapturingStream};
use crate::load_balancing::RoundRobin;
use crate::proxy::forwarding::{bad_gateway, forward, pick_route};
use crate::telemetry::Metrics;
use crate::tls::{build_rustls, read_client_hello};
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
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

type RespBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

/// Handle request routing and forwarding
#[allow(clippy::too_many_arguments)]
async fn handle_proxy_request(
    mut req: Request<Incoming>,
    routes: Vec<crate::config::Route>,
    backend_list: Arc<Vec<crate::config::Backend>>,
    backends: Arc<Vec<crate::config::Backend>>,
    round_robin: RoundRobin,
    tls_header: Option<HeaderValue>,
    fingerprint_rx: Option<watch::Receiver<Option<huginn_net_http::AkamaiFingerprint>>>,
    metrics: Option<Arc<Metrics>>,
) -> std::result::Result<hyper::Response<RespBody>, hyper::Error> {
    let start = Instant::now();
    let method = req.method().to_string();
    let protocol = format!("{:?}", req.version());
    // Handle TLS fingerprint header
    if let Some(hv) = tls_header {
        req.headers_mut()
            .insert(HeaderName::from_static("x-huginn-net-tls"), hv);
    }

    // Handle HTTP/2 fingerprint header
    if let Some(ref rx) = fingerprint_rx {
        let akamai = rx.borrow().clone();
        debug!("Handler: akamai fingerprint: {:?}", akamai);
        if let Some(hv) = akamai_header_value(&akamai) {
            debug!("Handler: injecting x-huginn-net-http header: {:?}", hv);
            req.headers_mut()
                .insert(HeaderName::from_static("x-huginn-net-http"), hv);
        } else {
            debug!("Handler: no HTTP fingerprint header to inject");
        }
    }

    // Route selection
    let path = req.uri().path();
    let backend = if let Some(target) = pick_route(path, &routes) {
        let backend_str = target.to_string();
        if let Some(ref m) = metrics {
            m.backend_selections_total
                .add(1, &[KeyValue::new("backend", backend_str.clone())]);
        }
        backend_str
    } else {
        if backend_list.is_empty() {
            if let Some(ref m) = metrics {
                m.errors_total
                    .add(1, &[KeyValue::new("error_type", "no_backends")]);
            }
            return Ok(bad_gateway());
        }
        let idx = round_robin.next(backend_list.len());
        let selected_backend = backend_list[idx].address.clone();
        if let Some(ref m) = metrics {
            m.backend_selections_total
                .add(1, &[KeyValue::new("backend", selected_backend.clone())]);
        }
        selected_backend
    };

    // Forward request
    let result = forward(req, backend.clone(), &backends, metrics.clone()).await;

    let duration = start.elapsed().as_secs_f64();
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(_) => 502, // Bad Gateway
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

    match result {
        Ok(resp) => Ok(resp),
        Err(_) => Ok(bad_gateway()),
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
    let tls_acceptor = match &config.tls {
        Some(t) => Some(build_rustls(t)?),
        None => None,
    };

    let round_robin = RoundRobin::new();

    // Track active connections for graceful shutdown
    let active_connections = Arc::new(AtomicUsize::new(0));
    let shutdown_signal = Arc::new(AtomicUsize::new(0)); // 0 = running, 1 = shutdown requested

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

    info!(?addr, "starting L7 proxy (h1/h2)");

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

                // Increment active connections counter
                active_connections.fetch_add(1, Ordering::Relaxed);

                if let Some(ref m) = metrics {
                    m.connections_total.add(1, &[]);
                    m.connections_active.add(1, &[]);
                }

                let builder = builder.clone();
                let backends_clone = Arc::clone(&backends_for_loop);
                let routes = routes.clone();
                let round_robin = round_robin.clone();
                let tls_acceptor = tls_acceptor.clone();
                let active_connections = active_connections.clone();
                let fingerprint_config = config.fingerprint.clone();
                let metrics_clone = metrics.clone();

                let metrics_for_connection = metrics_clone.clone();
                tokio::spawn(async move {
                    // Ensure counter is decremented when connection finishes
                    let _guard = ConnectionGuard(active_connections);
                    let mut stream = stream;
                    let backend_list = backends_clone.clone();

                    if let Some(ref m) = metrics_for_connection {
                        m.connections_active.add(-1, &[]);
                    }

                    if let Some(acc) = tls_acceptor {
                        let (prefix, ja4) = match read_client_hello(&mut stream).await {
                            Ok(v) => v,
                            Err(e) => {
                                warn!(?peer, error = %e, "failed to read client hello");
                                return;
                            }
                        };

                        let prefixed = PrefixedStream::new(prefix, stream);
                        match acc.accept(prefixed).await {
                            Ok(tls) => {
                                let tls_header = if fingerprint_config.tls_enabled {
                                    tls_header_value(&ja4)
                                } else {
                                    None
                                };

                                if fingerprint_config.http_enabled {
                                    let (fingerprint_tx, fingerprint_rx) = watch::channel(None::<huginn_net_http::AkamaiFingerprint>);

                                    // Create CapturingStream with direct access to fingerprint_tx for inline processing
                                    let (capturing_stream, receiver, fingerprint_extracted) =
                                        CapturingStream::new(tls, fingerprint_config.max_capture, fingerprint_tx.clone());

                                    let fingerprint_extracted_for_task = fingerprint_extracted.clone();
                                    tokio::spawn(process_captured_bytes(
                                        receiver,
                                        fingerprint_tx,
                                        fingerprint_extracted_for_task,
                                    ));

                                    let metrics_for_service = metrics_for_connection.clone();
                                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                                        let routes = routes.clone();
                                        let backend_list = backend_list.clone();
                                        let backends = backends_clone.clone();
                                        let round_robin = round_robin.clone();
                                        let tls_header = tls_header.clone();
                                        let fingerprint_rx = fingerprint_rx.clone();
                                        let metrics = metrics_for_service.clone();

                                        async move {
                                            handle_proxy_request(
                                                req,
                                                routes,
                                                backend_list,
                                                backends,
                                                round_robin,
                                                tls_header,
                                                Some(fingerprint_rx),
                                                metrics,
                                            ).await
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
                                        let backend_list = backend_list.clone();
                                        let backends = backends_clone.clone();
                                        let round_robin = round_robin.clone();
                                        let tls_header = tls_header.clone();
                                        let metrics = metrics_for_service.clone();

                                        async move {
                                            handle_proxy_request(
                                                req,
                                                routes,
                                                backend_list,
                                                backends,
                                                round_robin,
                                                tls_header,
                                                None,
                                                metrics,
                                            ).await
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
                            }
                        }
                    } else {
                        let metrics_for_service = metrics_for_connection.clone();
                        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                            let routes = routes.clone();
                            let backend_list = backend_list.clone();
                            let backends = backends_clone.clone();
                            let round_robin = round_robin.clone();
                            let metrics = metrics_for_service.clone();

                            async move {
                                handle_proxy_request(
                                    req,
                                    routes,
                                    backend_list,
                                    backends,
                                    round_robin,
                                    None,
                                    None,
                                    metrics,
                                ).await
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
    let start = std::time::Instant::now();

    loop {
        let active = active_connections.load(Ordering::Relaxed);
        if active == 0 {
            info!("All connections closed, shutdown complete");
            break;
        }

        if start.elapsed() >= shutdown_timeout {
            warn!(
                active_connections = active,
                "Shutdown timeout reached, {} connections still active", active
            );
            break;
        }

        info!(active_connections = active, "Waiting for connections to close");
        sleep(Duration::from_millis(100)).await;
    }

    info!("Proxy server stopped");
    Ok(())
}
