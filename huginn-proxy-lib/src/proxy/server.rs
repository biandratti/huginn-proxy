use crate::backend::health_check::{HealthCheckSupervisor, HealthRegistry};
use crate::backend::BackendSelector;
use crate::config::watcher::spawn_config_watcher;
use crate::config::StaticConfig;
use crate::error::Result;
pub use crate::proxy::accept::SynProbe;
use crate::proxy::accept::{accept_loop, AcceptContext};
pub use crate::proxy::acme_runtime::AcmeRuntime;
use crate::proxy::connection::ConnectionManager;
use crate::proxy::listener::{bind_listener, register_signal};
use crate::proxy::protocol::warn_proxy_protocol_trust_gap;
use crate::proxy::reload::{
    initial_client_pool, initial_rate_limiter, try_reload, SharedDynamicConfig,
};
use crate::proxy::shutdown::{wait_for_drain, ServiceHandle, ShutdownSender};
pub use crate::proxy::watch::WatchOptions;
use crate::telemetry::{Metrics, Readiness};
use crate::tls::{build_tls_acceptor, CompositeResolver, DynamicCertResolver};
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
use tokio_rustls::rustls::server::ResolvesServerCert;
use tracing::{info, warn};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    static_cfg: Arc<StaticConfig>,
    dynamic_cfg: SharedDynamicConfig,
    metrics: Arc<Metrics>,
    syn_probe: Option<SynProbe>,
    acme: Option<AcmeRuntime>,
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

    // `true` once ACME produced at least one per-host resolver. Computed before `acme` is
    // moved into the composite, and used both for the ALPN `acme-tls/1` advertisement and for
    // the composite-aware serviceability check below (so an ACME-only deploy doesn't warn).
    let acme_active = acme.as_ref().is_some_and(|rt| !rt.resolvers.is_empty());

    let mut acme = acme;
    let acme_cert_ready_rx: Option<watch::Receiver<bool>> =
        acme.as_mut().and_then(|rt| rt.cert_ready_rx.take());

    // Build the static cert resolver and load initial certs from the current dynamic config.
    // `None` when TLS is not configured (plain HTTP mode). This is the resolver the hot-reload
    // path keeps updating; the composite (if any) shares it by `Arc`.
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
        // Composite-aware: ACME hosts also make TLS serviceable, so only warn when neither a
        // file cert nor an ACME host can serve a handshake.
        if !resolver.has_serviceable_cert()
            && !acme_active
            && !dynamic_cfg.load().domains.is_empty()
        {
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
            // Compose the static resolver with any per-host ACME resolvers and register the
            // ACME background tasks for ordered shutdown. Without ACME, use the static resolver
            // directly (behavior unchanged).
            let effective: Arc<dyn ResolvesServerCert> = match acme {
                Some(rt) if !rt.resolvers.is_empty() => {
                    metrics.set_acme_domains(rt.resolvers.len() as u64);
                    services.extend(rt.tasks);
                    Arc::new(CompositeResolver::new(Arc::clone(resolver), rt.resolvers))
                }
                Some(rt) => {
                    // ACME configured but no resolvers produced; still register its tasks.
                    services.extend(rt.tasks);
                    Arc::clone(resolver) as Arc<dyn ResolvesServerCert>
                }
                None => Arc::clone(resolver) as Arc<dyn ResolvesServerCert>,
            };
            Some(build_tls_acceptor(tls_config, effective, acme_active).await?)
        }
        _ => {
            // No TLS acceptor (plain HTTP). The loader forbids `acme` without `[tls]`, but if a
            // runtime were still supplied, register its tasks so they shut down cleanly.
            if let Some(rt) = acme {
                services.extend(rt.tasks);
            }
            None
        }
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
        proxy_protocol: static_cfg.listen.proxy_protocol,
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
            Arc::clone(&connection_manager),
            Arc::clone(&ctx),
        ));
    }

    warn_proxy_protocol_trust_gap(
        static_cfg.listen.proxy_protocol,
        &dynamic_cfg.load().security.trusted_proxies,
    );

    // If ACME is active, defer `/ready` until the first certificate is deployed. This prevents
    // the LB from routing traffic during a cold start before a cert exists on the listener.
    // The timeout is defence-in-depth: if issuance stalls (rate-limit, network outage) the
    // proxy eventually marks itself ready anyway so health-check failures trigger the alert
    // instead of leaving the pod in a permanent not-ready loop.
    // (D4 will make this timeout configurable via `[acme].ready_timeout_secs`.)
    if let Some(mut rx) = acme_cert_ready_rx {
        const ACME_READY_TIMEOUT_SECS: u64 = 300;
        match tokio::time::timeout(
            Duration::from_secs(ACME_READY_TIMEOUT_SECS),
            rx.wait_for(|v| *v),
        )
        .await
        {
            Ok(Ok(_)) => info!("ACME: first certificate deployed, marking proxy ready"),
            Ok(Err(_)) => warn!("ACME ready channel closed before first certificate"),
            Err(_) => warn!(
                timeout_secs = ACME_READY_TIMEOUT_SECS,
                "Timed out waiting for first ACME certificate; marking proxy ready without cert"
            ),
        }
    }

    readiness.mark_ready();
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
                        acme_active,
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
