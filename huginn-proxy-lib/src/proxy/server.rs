use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::fingerprinting::{process_captured_bytes, CapturingStream};
use crate::load_balancing::RoundRobin;
use crate::proxy::forwarding::{bad_gateway, forward, pick_route};
use crate::tls::{build_rustls, read_client_hello};

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

/// Convert fingerprint value to HeaderValue
fn header_value(value: &Option<String>) -> Option<HeaderValue> {
    value.as_ref().and_then(|f| HeaderValue::from_str(f).ok())
}

/// Guard to decrement active connections counter when dropped
struct ConnectionGuard(Arc<AtomicUsize>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn run(config: Arc<Config>) -> Result<()> {
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

                let builder = builder.clone();
                let backends_clone = Arc::clone(&backends_for_loop);
                let routes = routes.clone();
                let round_robin = round_robin.clone();
                let tls_acceptor = tls_acceptor.clone();
                let active_connections = active_connections.clone();
                let fingerprint_config = config.fingerprint.clone();

                tokio::spawn(async move {
                    // Ensure counter is decremented when connection finishes
                    let _guard = ConnectionGuard(active_connections);
                    let mut stream = stream;
                    let backend_list = backends_clone.clone();

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
                                    header_value(&ja4)
                                } else {
                                    None
                                };

                                if fingerprint_config.http_enabled {
                                    let (fingerprint_tx, fingerprint_rx) = watch::channel(None::<String>);

                                    // Create CapturingStream with direct access to fingerprint_tx for inline processing
                                    let (capturing_stream, receiver, fingerprint_extracted) =
                                        CapturingStream::new(tls, 64 * 1024, fingerprint_tx.clone());

                                    let fingerprint_extracted_for_task = fingerprint_extracted.clone();
                                    tokio::spawn(process_captured_bytes(
                                        receiver,
                                        fingerprint_tx,
                                        fingerprint_extracted_for_task,
                                    ));

                                    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                                        let routes = routes.clone();
                                        let backend_list = backend_list.clone();
                                        let backends = backends_clone.clone();
                                        let round_robin = round_robin.clone();
                                        let tls_header = tls_header.clone();
                                        let fingerprint_rx = fingerprint_rx.clone();

                                        async move {
                                            if let Some(hv) = tls_header {
                                                req.headers_mut()
                                                    .insert(HeaderName::from_static("x-huginn-net-tls"), hv);
                                            }

                                            // Get HTTP/2 fingerprint from watch channel
                                            let akamai = fingerprint_rx.borrow().clone();
                                            debug!("Handler: akamai fingerprint: {:?}", akamai);
                                            if let Some(hv) = header_value(&akamai) {
                                                debug!("Handler: injecting x-huginn-net-http header: {:?}", hv);
                                                req.headers_mut()
                                                    .insert(HeaderName::from_static("x-huginn-net-http"), hv);
                                            } else {
                                                debug!("Handler: no HTTP fingerprint header to inject");
                                            }

                                            // Route selection
                                            let path = req.uri().path();
                                            let backend = if let Some(target) = pick_route(path, &routes) {
                                                target.to_string()
                                            } else {
                                                if backend_list.is_empty() {
                                                    return Ok::<_, hyper::Error>(bad_gateway());
                                                }
                                                let idx = round_robin.next(backend_list.len());
                                                backend_list[idx].address.clone()
                                            };

                                            // Forward request
                                            match forward(req, backend, &backends).await {
                                                Ok(resp) => Ok::<_, hyper::Error>(resp),
                                                Err(_) => Ok::<_, hyper::Error>(bad_gateway()),
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
                                    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
                                        let routes = routes.clone();
                                        let backend_list = backend_list.clone();
                                        let backends = backends_clone.clone();
                                        let round_robin = round_robin.clone();
                                        let tls_header = tls_header.clone();

                                        async move {
                                            if let Some(hv) = tls_header {
                                                req.headers_mut()
                                                    .insert(HeaderName::from_static("x-huginn-net-tls"), hv);
                                            }

                                            // Route selection
                                            let path = req.uri().path();
                                            let backend = if let Some(target) = pick_route(path, &routes) {
                                                target.to_string()
                                            } else {
                                                if backend_list.is_empty() {
                                                    return Ok::<_, hyper::Error>(bad_gateway());
                                                }
                                                let idx = round_robin.next(backend_list.len());
                                                backend_list[idx].address.clone()
                                            };

                                            // Forward request
                                            match forward(req, backend, &backends).await {
                                                Ok(resp) => Ok::<_, hyper::Error>(resp),
                                                Err(_) => Ok::<_, hyper::Error>(bad_gateway()),
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
                            }
                        }
                    } else {
                        let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                            let routes = routes.clone();
                            let backend_list = backend_list.clone();
                            let backends = backends_clone.clone();
                            let round_robin = round_robin.clone();

                            async move {
                                let path = req.uri().path();
                                let backend = if let Some(target) = pick_route(path, &routes) {
                                    target.to_string()
                                } else {
                                    if backend_list.is_empty() {
                                        return Ok::<_, hyper::Error>(bad_gateway());
                                    }
                                    let idx = round_robin.next(backend_list.len());
                                    backend_list[idx].address.clone()
                                };

                                match forward(req, backend, &backends).await {
                                    Ok(resp) => Ok::<_, hyper::Error>(resp),
                                    Err(_) => Ok::<_, hyper::Error>(bad_gateway()),
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
