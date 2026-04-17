use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::config::watcher::spawn_config_watcher;
use crate::config::{DynamicConfig, StaticConfig};
use crate::error::Result;
use crate::fingerprinting::{SynResult, TcpObservation};
use crate::proxy::connection::{ConnectionError, ConnectionManager};
use crate::proxy::context::SecurityContext;
use crate::proxy::reload::{initial_client_pool, initial_rate_limiter, try_reload};
use crate::proxy::transport::{
    handle_plain_connection, handle_tls_connection, PlainConnectionConfig, TlsConnectionConfig,
};
use crate::telemetry::Metrics;
use crate::tls::setup_tls_with_hot_reload;

/// Callback type for TCP SYN fingerprint lookup.
///
/// Returns a [`SynResult`] so the server can record a precise metric label.
/// Implemented by `huginn-proxy` when the `ebpf-tcp` feature is enabled.
pub type SynProbe = Arc<dyn Fn(SocketAddr) -> SynResult + Send + Sync>;

/// Options controlling filesystem watching and hot reload.
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Path to the TOML config file, required for SIGHUP reload and `--watch` TOML watching.
    /// `None` disables config hot-reload (reload attempts are silently skipped).
    pub config_path: Option<PathBuf>,
    /// Enable filesystem watching for TLS certificate and config hot reload.
    pub watch: bool,
    /// Debounce delay in seconds before applying a reload after a file-change event.
    pub watch_delay_secs: u32,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self { config_path: None, watch: false, watch_delay_secs: 60 }
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
    metrics: Arc<Metrics>,
    syn_probe: Option<SynProbe>,
    watch_opts: WatchOptions,
) -> Result<()> {
    let rate_limiter = Arc::new(initial_rate_limiter(&dynamic_cfg.load()));
    let client_pool = initial_client_pool(&static_cfg, &dynamic_cfg.load().backend_pool);

    let idle_timeout = Duration::from_millis(static_cfg.timeout.proxy_idle_ms);

    let mut builder = ConnBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .keep_alive(static_cfg.timeout.keep_alive.enabled)
        .header_read_timeout(idle_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(idle_timeout)
        .keep_alive_timeout(idle_timeout.saturating_add(Duration::from_secs(1)));

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

    let shutdown_signal = Arc::new(AtomicUsize::new(0)); // 0 = running, 1 = shutdown requested
    let (connections_closed_tx, mut connections_closed_rx) = watch::channel(());
    let connection_manager = Arc::new(ConnectionManager::new(
        static_cfg.max_connections,
        shutdown_signal.clone(),
        connections_closed_tx.clone(),
    ));
    let active_connections = connection_manager.active_connections();

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
    // SIGHUP handler — always active, triggers config hot reload.
    let mut sighup = signal::unix::signal(signal::unix::SignalKind::hangup()).map_err(|e| {
        crate::error::ProxyError::Io(std::io::Error::other(format!(
            "Failed to setup SIGHUP handler: {e}"
        )))
    })?;

    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    if watch_opts.watch {
        if let Some(ref config_path) = watch_opts.config_path {
            spawn_config_watcher(config_path.clone(), reload_tx, watch_opts.watch_delay_secs)?;
        }
    }

    let reload_mutex = Arc::new(tokio::sync::Mutex::new(()));

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

    let fingerprint_config = static_cfg.fingerprint.clone();
    let keep_alive_config = static_cfg.timeout.keep_alive.clone();
    let tls_handshake_timeout = Duration::from_secs(static_cfg.timeout.tls_handshake_secs);
    let connection_handling_timeout =
        Duration::from_secs(static_cfg.timeout.connection_handling_secs);

    // Spawn one accept task per listener.
    // Each new connection loads a fresh snapshot of DynamicConfig + rate-limiter so it
    // automatically picks up any hot-reloaded configuration.
    let mut accept_tasks = tokio::task::JoinSet::new();
    for (addr, listener) in listeners {
        let shutdown_signal_clone = shutdown_signal.clone();
        let connection_manager_clone = connection_manager.clone();
        let dynamic_cfg_clone = Arc::clone(&dynamic_cfg);
        let rate_limiter_clone = Arc::clone(&rate_limiter);
        let tls_acceptor_clone = tls_acceptor.clone();
        let fingerprint_config = fingerprint_config.clone();
        let keep_alive_config = keep_alive_config.clone();
        let metrics_clone = metrics.clone();
        let client_pool_clone = Arc::clone(&client_pool);
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
                let guard = match connection_manager_clone.try_accept(peer, &metrics_clone) {
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
                        let label = match r {
                            SynResult::Hit(_) => "hit",
                            SynResult::Miss => "miss",
                            SynResult::Malformed => "malformed",
                        };
                        metrics_clone.record_tcp_syn_fingerprint(label, syn_duration);
                        match r {
                            SynResult::Hit(obs) => Some(obs.clone()),
                            _ => None,
                        }
                    }
                    None => None,
                };

                // Load fresh config snapshot for this connection (lock-free ArcSwap load).
                let dynamic = dynamic_cfg_clone.load();
                let rate_mgr = rate_limiter_clone
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                let security = SecurityContext::new(
                    dynamic.security.headers.clone(),
                    dynamic.security.ip_filter.clone(),
                    dynamic.security.rate_limit.clone(),
                    rate_mgr,
                    dynamic.headers.clone(),
                );
                let backends = Arc::new(dynamic.backends.clone());
                let routes = dynamic.routes.clone();
                let preserve_host = dynamic.preserve_host;

                let builder_task = builder_clone.clone();
                let tls_acceptor_task = tls_acceptor_clone.clone();
                let fingerprint_config_task = fingerprint_config.clone();
                let keep_alive_task = keep_alive_config.clone();
                let metrics_task = metrics_clone.clone();
                let client_pool_task = client_pool_clone.load_full();

                tokio::spawn(async move {
                    let _guard = guard;

                    if let Some(ref tls_acceptor_lock) = tls_acceptor_task {
                        handle_tls_connection(
                            stream,
                            peer,
                            TlsConnectionConfig {
                                tls_acceptor: tls_acceptor_lock.clone(),
                                fingerprint_config: fingerprint_config_task,
                                routes,
                                backends,
                                keep_alive: keep_alive_task.clone(),
                                security: security.clone(),
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
                                routes,
                                backends,
                                keep_alive: keep_alive_task,
                                security,
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

    // Signal loop: handle SIGHUP (reload) in a loop; exit on SIGTERM / SIGINT.
    loop {
        tokio::select! {
            // SIGHUP triggers an immediate config reload attempt.
            _ = sighup.recv() => {
                info!("Received SIGHUP, triggering config reload");
                if let Some(ref config_path) = watch_opts.config_path {
                    try_reload(
                        config_path,
                        &static_cfg,
                        &dynamic_cfg,
                        &rate_limiter,
                        &client_pool,
                        &reload_mutex,
                        &metrics,
                    ).await;
                } else {
                    warn!("SIGHUP received but no config path configured — reload skipped");
                }
            }
            // filesystem watcher sends here when TOML changes (--watch only).
            Some(_) = reload_rx.recv() => {
                if let Some(ref config_path) = watch_opts.config_path {
                    try_reload(
                        config_path,
                        &static_cfg,
                        &dynamic_cfg,
                        &rate_limiter,
                        &client_pool,
                        &reload_mutex,
                        &metrics,
                    ).await;
                }
            }
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
