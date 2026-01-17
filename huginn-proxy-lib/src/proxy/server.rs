use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::Result;
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::transport::{
    handle_plain_connection, handle_tls_connection, PlainConnectionConfig, TlsConnectionConfig,
};
use crate::telemetry::Metrics;
use crate::tls::setup_tls_with_hot_reload;

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
                let keep_alive_config = config.timeout.keep_alive.clone();
                let security_headers = config.security.headers.clone();
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
                                keep_alive: keep_alive_config.clone(),
                                security_headers: security_headers.clone(),
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
                                keep_alive: keep_alive_config,
                                security_headers: security_headers.clone(),
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
