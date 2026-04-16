use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use hyper_util::rt::TokioExecutor;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::{BackendPoolConfig, DynamicConfig, StaticConfig};
use crate::error::Result;
use crate::fingerprinting::{SynResult, TcpObservation};
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::transport::{
    handle_plain_connection, handle_tls_connection, PlainConnectionConfig, TlsConnectionConfig,
};
use crate::proxy::ClientPool;
use crate::telemetry::Metrics;
use crate::tls::setup_tls_with_hot_reload;

/// Callback type for TCP SYN fingerprint lookup.
///
/// Returns a [`SynResult`] so the server can record a precise metric label.
/// Implemented by `huginn-proxy` when the `ebpf-tcp` feature is enabled.
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;

/// Options controlling filesystem watching for hot reload.
///
/// Passed at startup via CLI flags (`--watch`, `--watch-delay-secs`) or env vars
/// (`HUGINN_WATCH`, `HUGINN_WATCH_DELAY_SECS`). Not part of the TOML config.
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Enable filesystem watching for TLS certificate hot reload (and config reload in Fase 1).
    pub watch: bool,
    /// Debounce delay in seconds before applying a reload after a file-change event.
    pub watch_delay_secs: u32,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self { watch: false, watch_delay_secs: 60 }
    }
}

/// Bind a TCP listener to `addr` with the given `listen(2)` backlog.
///
/// IPv6 sockets are created with `IPV6_V6ONLY = 1` so they accept only native
/// IPv6 connections. This prevents the dual-stack ambiguity where an IPv4 client
/// arrives as `::ffff:x.y.z.w` (`SocketAddr::V6`), which would cause the SYN
/// fingerprint lookup to hit the wrong eBPF map.
fn bind_listener(addr: SocketAddr, backlog: i32) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

pub async fn run(
    static_cfg: Arc<StaticConfig>,
    dynamic_cfg: Arc<ArcSwap<DynamicConfig>>,
    metrics: Option<Arc<Metrics>>,
    syn_probe: Option<SynProbe>,
    watch_opts: WatchOptions,
) -> Result<()> {
    // Load a snapshot of the current dynamic configuration.
    // In this PR, this snapshot is used for the full lifetime of the server.
    // Actual hot-swapping of the ArcSwap pointer comes in a later PR.
    let dynamic = dynamic_cfg.load();

    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .keep_alive(static_cfg.timeout.keep_alive.enabled);

    let backends = Arc::new(dynamic.backends.clone());
    let routes = dynamic.routes.clone();

    let rate_limit_manager = if dynamic.security.rate_limit.enabled {
        Some(Arc::new(crate::security::RateLimitManager::new(
            &dynamic.security.rate_limit,
            &routes,
        )))
    } else {
        None
    };

    let security_context = crate::proxy::SecurityContext::new(
        dynamic.security.headers.clone(),
        dynamic.security.ip_filter.clone(),
        dynamic.security.rate_limit.clone(),
        rate_limit_manager,
        dynamic.headers.clone(),
    );

    // Setup TLS with hot reload support
    let tls_acceptor = match &static_cfg.tls {
        Some(tls_config) => {
            let tls_setup = setup_tls_with_hot_reload(
                tls_config,
                watch_opts.watch,
                watch_opts.watch_delay_secs,
            )
            .await?;
            Some(tls_setup.acceptor)
        }
        None => None,
    };

    // Setup connection manager (shared across all listeners)
    let shutdown_signal = Arc::new(AtomicUsize::new(0)); // 0 = running, 1 = shutdown requested
    let (connections_closed_tx, mut connections_closed_rx) = watch::channel(());
    let connection_manager = Arc::new(ConnectionManager::new(
        static_cfg.max_connections,
        shutdown_signal.clone(),
        connections_closed_tx.clone(),
    ));
    let active_connections = connection_manager.active_connections();

    // Setup client pool for backend connections (shared across all listeners)
    let pool_config = BackendPoolConfig::default();
    let client_pool =
        Arc::new(ClientPool::new(&static_cfg.timeout.keep_alive, pool_config.clone()));

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

    // Bind one listener per configured address
    let backlog = static_cfg.listen.tcp_backlog;
    let listeners: Vec<(SocketAddr, TcpListener)> = static_cfg
        .listen
        .addrs
        .iter()
        .map(|&addr| {
            bind_listener(addr, backlog)
                .map(|l| (addr, l))
                .map_err(crate::error::ProxyError::Io)
        })
        .collect::<Result<_>>()?;

    for (addr, _) in &listeners {
        info!(?addr, "starting proxy");
    }

    let preserve_host = dynamic.preserve_host;
    let fingerprint_config = static_cfg.fingerprint.clone();
    let keep_alive_config = static_cfg.timeout.keep_alive.clone();
    let tls_handshake_timeout = Duration::from_secs(static_cfg.timeout.tls_handshake_secs);
    let connection_handling_timeout =
        Duration::from_secs(static_cfg.timeout.connection_handling_secs);

    // Spawn one accept task per listener
    let mut accept_tasks = tokio::task::JoinSet::new();
    for (addr, listener) in listeners {
        let shutdown_signal_clone = shutdown_signal.clone();
        let connection_manager_clone = connection_manager.clone();
        let backends_clone = Arc::clone(&backends);
        let routes_clone = routes.clone();
        let tls_acceptor_clone = tls_acceptor.clone();
        let fingerprint_config = fingerprint_config.clone();
        let keep_alive_config = keep_alive_config.clone();
        let security = security_context.clone();
        let metrics_clone = metrics.clone();
        let client_pool_clone = client_pool.clone();
        let builder_clone = builder.clone();
        let syn_probe_clone = syn_probe.clone();

        accept_tasks.spawn(async move {
            loop {
                if shutdown_signal_clone.load(Ordering::Relaxed) != 0 {
                    break;
                }

                let (stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, ?addr, "accept error");
                        continue;
                    }
                };

                // Try to accept connection (checks limits and shutdown)
                let guard = match connection_manager_clone.try_accept(peer, metrics_clone.as_ref())
                {
                    Ok(g) => g,
                    Err(ConnectionError::Shutdown) => {
                        drop(stream);
                        break;
                    }
                    Err(ConnectionError::LimitExceeded { .. }) => {
                        drop(stream);
                        continue;
                    }
                };

                let syn_start = Instant::now();
                let syn_result = syn_probe_clone.as_ref().map(|probe| probe(peer));
                let syn_duration = syn_start.elapsed().as_secs_f64();

                let syn_fingerprint: Option<TcpObservation> = match syn_result {
                    Some(ref r) => {
                        if let Some(ref m) = metrics_clone {
                            let label = match r {
                                SynResult::Hit(_) => "hit",
                                SynResult::Miss => "miss",
                                SynResult::Malformed => "malformed",
                            };
                            m.record_tcp_syn_fingerprint(label, syn_duration);
                        }
                        match r {
                            SynResult::Hit(obs) => Some(obs.clone()),
                            _ => None,
                        }
                    }
                    None => None,
                };

                let builder_task = builder_clone.clone();
                let backends_task = Arc::clone(&backends_clone);
                let routes_task = routes_clone.clone();
                let tls_acceptor_task = tls_acceptor_clone.clone();
                let fingerprint_config_task = fingerprint_config.clone();
                let keep_alive_task = keep_alive_config.clone();
                let security_task = security.clone();
                let metrics_task = metrics_clone.clone();
                let client_pool_task = client_pool_clone.clone();

                tokio::spawn(async move {
                    let _guard = guard;

                    if let Some(ref tls_acceptor_lock) = tls_acceptor_task {
                        handle_tls_connection(
                            stream,
                            peer,
                            TlsConnectionConfig {
                                tls_acceptor: tls_acceptor_lock.clone(),
                                fingerprint_config: fingerprint_config_task,
                                routes: routes_task,
                                backends: backends_task,
                                keep_alive: keep_alive_task.clone(),
                                security: security_task.clone(),
                                metrics: metrics_task.clone(),
                                builder: builder_task.clone(),
                                preserve_host,
                                tls_handshake_timeout,
                                connection_handling_timeout,
                                client_pool: client_pool_task.clone(),
                                syn_fingerprint: syn_fingerprint.clone(),
                            },
                        )
                        .await;
                    } else {
                        handle_plain_connection(
                            stream,
                            peer,
                            PlainConnectionConfig {
                                routes: routes_task,
                                backends: backends_task,
                                keep_alive: keep_alive_task,
                                security: security_task,
                                metrics: metrics_task,
                                builder: builder_task,
                                preserve_host,
                                connection_handling_timeout,
                                client_pool: client_pool_task,
                                syn_fingerprint,
                            },
                        )
                        .await;
                    }
                });
            }
        });
    }

    // Wait for a shutdown signal, then stop all accept tasks
    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown");
            shutdown_signal.store(1, Ordering::Relaxed);
        }
        _ = sigint.recv() => {
            info!("Received SIGINT, initiating graceful shutdown");
            shutdown_signal.store(1, Ordering::Relaxed);
        }
    }

    accept_tasks.abort_all();
    drop(accept_tasks);

    info!(
        "Waiting for active connections to finish (timeout: {}s)",
        static_cfg.timeout.shutdown_secs
    );
    let shutdown_timeout = Duration::from_secs(static_cfg.timeout.shutdown_secs);
    let start = Instant::now();

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
