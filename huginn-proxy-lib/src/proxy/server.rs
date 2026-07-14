use crate::backend::health_check::{HealthCheckSupervisor, HealthRegistry};
use crate::backend::BackendSelector;
use crate::config::watcher::spawn_config_watcher;
use crate::config::{EffectiveConfigSummary, EffectiveConfigView, StaticConfig};
use crate::error::Result;
pub use crate::proxy::accept::SynProbe;
use crate::proxy::accept::{accept_loop, AcceptContext};
use crate::proxy::connection::ConnectionManager;
use crate::proxy::listener::{bind_listener, register_signal};
use crate::proxy::peer_resolution::ResolvedProxyProtocol;
use crate::proxy::protocol::warn_proxy_protocol_trust_gap;
use crate::proxy::reload::{
    initial_client_pool, initial_rate_limiter, try_reload, SharedDynamicConfig,
};
use crate::proxy::shutdown::{wait_for_drain, ServiceHandle, ShutdownSender};
pub use crate::proxy::watch::WatchOptions;
use crate::telemetry::{Metrics, Readiness};
use crate::tls::{build_tls_acceptor, DynamicCertResolver};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::signal;
use tokio::sync::watch;
use tokio::time::Duration;
use tracing::{debug, info, warn};

pub async fn run(
    static_cfg: Arc<StaticConfig>,
    dynamic_cfg: SharedDynamicConfig,
    metrics: Arc<Metrics>,
    syn_probe: Option<SynProbe>,
    watch_opts: WatchOptions,
    shutdown_tx: ShutdownSender,
    readiness: Readiness,
) -> Result<()> {
    // Derive receiver from the sender so all clones share the same channel
    let shutdown_rx = shutdown_tx.subscribe();

    let rate_limiter = Arc::new(initial_rate_limiter(&dynamic_cfg.load()));
    let client_pool = initial_client_pool(&static_cfg, &dynamic_cfg.load().backend_pool);

    let health_registry = Arc::new(HealthRegistry::new());
    let health_supervisor = Arc::new(HealthCheckSupervisor::new(health_registry.clone()));
    health_supervisor.reconcile(&dynamic_cfg.load().backends, &metrics, &Handle::current());
    let backend_selector = Arc::new(BackendSelector::new());

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

    // Collect background service handles for ordered cooperative shutdown.
    let mut services: Vec<ServiceHandle> = Vec::new();

    // Build the cert resolver and load initial certs from the current dynamic config.
    // `None` when TLS is not configured (plain HTTP mode).
    let cert_resolver: Option<Arc<DynamicCertResolver>> = if let Some(tls) = &static_cfg.tls {
        let resolver = Arc::new(DynamicCertResolver::new(tls.options.sni_strict));
        let report = resolver.update(&dynamic_cfg.load().domains, &metrics).await;
        if report.is_partial() {
            info!(
                failed = report.failed,
                loaded = report.loaded,
                "Some domain certificates failed to load at startup; those domains will not serve TLS"
            );
        }
        if !resolver.has_serviceable_cert() && !dynamic_cfg.load().domains.is_empty() {
            info!(
                "TLS is configured but no certificate is serviceable; all TLS handshakes will be \
                 rejected until a cert is provided"
            );
        }
        Some(resolver)
    } else {
        None
    };

    let tls_acceptor = match (&static_cfg.tls, &cert_resolver) {
        (Some(tls_config), Some(resolver)) => {
            Some(build_tls_acceptor(tls_config, Arc::clone(resolver)).await?)
        }
        _ => None,
    };

    let shutdown_signal = Arc::new(AtomicUsize::new(0));
    let (connections_closed_tx, connections_closed_rx) = watch::channel(());
    let connection_manager = Arc::new(ConnectionManager::new(
        static_cfg.max_connections,
        shutdown_signal.clone(),
        connections_closed_tx.clone(),
    ));

    let mut sigterm = register_signal(signal::unix::SignalKind::terminate(), "SIGTERM")?;
    let mut sigint = register_signal(signal::unix::SignalKind::interrupt(), "SIGINT")?;
    let mut sighup = register_signal(signal::unix::SignalKind::hangup(), "SIGHUP")?;

    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let sighup_tx = reload_tx.clone();
    if watch_opts.watch {
        match &watch_opts.config_path {
            Some(config_path) => {
                let svc = spawn_config_watcher(
                    config_path.clone(),
                    reload_tx,
                    watch_opts.watch_delay_secs,
                    shutdown_rx.clone(),
                )?;
                services.push(svc);
            }
            None => {
                warn!("HUGINN_WATCH=true but no config path provided hot-reload disabled");
            }
        }
    } else {
        info!("Config hot-reload disabled (set HUGINN_WATCH=true to enable)");
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

    let ctx = Arc::new(AcceptContext {
        dynamic_cfg: Arc::clone(&dynamic_cfg),
        rate_limiter: Arc::clone(&rate_limiter),
        tls_acceptor,
        fingerprint_config: static_cfg.fingerprint.clone(),
        keep_alive_config: static_cfg.timeout.keep_alive.clone(),
        metrics: Arc::clone(&metrics),
        client_pool: Arc::clone(&client_pool),
        builder,
        syn_probe,
        health_registry: Arc::clone(&health_registry),
        backend_selector: Arc::clone(&backend_selector),
        tls_handshake_timeout: Duration::from_secs(static_cfg.timeout.tls_handshake_secs),
        connection_handling_timeout: Duration::from_secs(
            static_cfg.timeout.connection_handling_secs,
        ),
        proxy_protocol: ResolvedProxyProtocol::resolve(static_cfg.listen.proxy_protocol),
    });

    // Spawn one accept task per listener.
    // Each new connection loads a fresh snapshot of DynamicConfig + rate-limiter so it
    // automatically picks up any hot-reloaded configuration.
    let mut accept_tasks = tokio::task::JoinSet::new();
    for (addr, listener) in listeners {
        accept_tasks.spawn(accept_loop(
            addr,
            listener,
            Arc::clone(&shutdown_signal),
            shutdown_rx.clone(),
            Arc::clone(&connection_manager),
            Arc::clone(&ctx),
        ));
    }

    warn_proxy_protocol_trust_gap(
        static_cfg.listen.proxy_protocol.mode,
        &dynamic_cfg.load().security.trusted_proxies,
    );

    readiness.mark_ready();
    let effective_dynamic = dynamic_cfg.load();
    let summary = EffectiveConfigSummary::new(&static_cfg, &effective_dynamic);
    info!(
        listeners = summary.listener_count,
        tls = summary.tls_enabled,
        proxy_protocol = summary.proxy_protocol_mode,
        domains = summary.domain_count,
        routes = summary.route_count,
        backends = summary.backend_count,
        rate_limit = summary.rate_limit_enabled,
        trusted_proxies = summary.trusted_proxy_count,
        preserve_host = summary.preserve_host,
        max_connections = summary.max_connections,
        "Effective config loaded"
    );
    if tracing::enabled!(tracing::Level::DEBUG) {
        match EffectiveConfigView::new(&static_cfg, &effective_dynamic).to_json() {
            Ok(config) => debug!(config, "Effective config details"),
            Err(error) => warn!(%error, "Failed to serialize effective config details"),
        }
    }
    info!("Proxy ready: accepting connections");

    // Signal loop: SIGHUP forwards to the reload channel; SIGTERM/SIGINT trigger shutdown.
    loop {
        tokio::select! {
            _ = sighup.recv() => {
                info!("Received SIGHUP, triggering config reload");
                if watch_opts.config_path.is_some() {
                    let _ = sighup_tx.send(());
                } else {
                    warn!("SIGHUP received but no config path configured reload skipped");
                }
            }
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
                        &health_supervisor,
                        cert_resolver.as_ref(),
                    )
                    .await;
                }
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
                readiness.mark_not_ready();
                health_supervisor.shutdown();
                shutdown_signal.store(1, Ordering::Relaxed);
                shutdown_tx.send(true).ok();
                break;
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
                readiness.mark_not_ready();
                health_supervisor.shutdown();
                shutdown_signal.store(1, Ordering::Relaxed);
                shutdown_tx.send(true).ok();
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
    wait_for_drain(
        connections_closed_rx,
        connection_manager.active_connections(),
        static_cfg.timeout.shutdown_secs,
    )
    .await;

    // Await background services in order. By the time connection drain
    // completes, each service has already received the shutdown signal
    // and should be ready, the timeout is defence-in-depth only.
    for service in services {
        service.shutdown(Duration::from_secs(5)).await;
    }

    info!("Proxy server stopped");
    Ok(())
}
