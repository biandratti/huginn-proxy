#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser;
use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::proxy::shutdown::{shutdown_channel, ServiceHandle, ServiceName};
use huginn_proxy_lib::run;
use huginn_proxy_lib::telemetry::{
    init_metrics, init_tracing_with_otel, shutdown_tracing, start_observability_server, Readiness,
};
use huginn_proxy_lib::WatchOptions;
use tokio::time::Duration;
use tracing::info;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Parser)]
#[command(name = "huginn-proxy", about = "High-performance reverse proxy")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(value_name = "CONFIG", env = "HUGINN_CONFIG_PATH")]
    config_path: PathBuf,

    /// Parse and validate the config file without starting the proxy
    #[arg(long)]
    validate: bool,

    /// Enable filesystem watching for config and TLS certificate hot reload
    #[arg(long, env = "HUGINN_WATCH")]
    watch: bool,

    /// Debounce delay in seconds before applying a reload after a file-change event
    #[arg(long, default_value = "60", env = "HUGINN_WATCH_DELAY_SECS")]
    watch_delay_secs: u32,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();

    let config = load_from_path(&cli.config_path)?;
    config.validate_cross_refs()?;

    if cli.validate {
        println!("Config OK: {}", cli.config_path.display());
        return Ok(());
    }

    // RUST_LOG environment variable can override at runtime (e.g., docker run -e RUST_LOG=debug)
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    init_tracing_with_otel(
        log_level,
        config.logging.show_target,
        config.telemetry.otel_log_level.clone(),
    )?;

    let huginn_proxy_lib::config::ConfigParts { static_cfg, dynamic_cfg } = config.into_parts();
    let static_cfg = Arc::new(static_cfg);
    let dynamic_cfg = Arc::new(ArcSwap::from_pointee(dynamic_cfg));

    // Single shutdown channel shared by all background tasks
    let (shutdown_tx, shutdown_rx) = shutdown_channel();

    // metrics (Arc<Metrics>) is kept alive for run(); only registry is moved into the spawn.
    let (metrics, registry) =
        init_metrics().map_err(|e| format!("Failed to initialize metrics: {e}"))?;

    // Readiness shared between the proxy and the observability server's `/ready` endpoint.
    // Not-ready until the proxy listeners are accepting; not-ready again on shutdown.
    let readiness = Readiness::new();

    let metrics_service: Option<ServiceHandle> =
        if let Some(metrics_port) = static_cfg.telemetry.metrics_port {
            info!(port = metrics_port, "Metrics initialized, starting observability server");
            let readiness_for_observability = readiness.clone();
            let mut metrics_shutdown = shutdown_rx.clone();
            let handle = tokio::spawn(async move {
                tokio::select! {
                    biased;
                    _ = metrics_shutdown.wait_for(|v| *v) => {
                        info!("Metrics server shutting down");
                    }
                    result = start_observability_server(
                        metrics_port,
                        registry,
                        readiness_for_observability,
                    ) => {
                        if let Err(e) = result {
                            tracing::error!(error = %e, "Observability server error");
                        }
                    }
                }
            });
            Some(ServiceHandle { handle, name: ServiceName::MetricsServer })
        } else {
            info!("Metrics initialized (no metrics_port, Prometheus endpoint disabled)");
            drop(registry);
            None
        };

    // TCP SYN fingerprinting via eBPF/XDP.
    // When tcp_enabled = true the proxy opens BPF maps pinned by huginn-ebpf-agent.
    // The agent may start after the proxy, so we retry with backoff until the maps appear.
    #[cfg(feature = "ebpf-tcp")]
    let syn_probe: Option<huginn_proxy_lib::SynProbe> = {
        use huginn_ebpf::{parse_syn_v4, parse_syn_v6, EbpfProbe};
        use huginn_proxy_lib::fingerprinting::SynResult;
        use std::net::SocketAddr;

        if !static_cfg.fingerprint.tcp_enabled {
            tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
            None
        } else {
            let pin_path = env::var("HUGINN_EBPF_PIN_PATH")
                .unwrap_or_else(|_| huginn_ebpf::pin::DEFAULT_PIN_BASE.to_string());
            let syn_map_max_entries = env::var("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES);

            const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

            let probe = loop {
                match EbpfProbe::from_pinned(&pin_path, syn_map_max_entries) {
                    Ok(p) => break p,
                    Err(_) => {
                        tracing::warn!(
                            pin_path,
                            "eBPF agent maps not available yet, retrying in {}s...",
                            RETRY_INTERVAL.as_secs()
                        );
                        tokio::time::sleep(RETRY_INTERVAL).await;
                    }
                }
            };

            let probe = Arc::new(probe);
            Some(Arc::new(move |peer: SocketAddr| -> SynResult {
                match peer {
                    SocketAddr::V4(a) => {
                        let Some(raw) = probe.lookup(*a.ip(), a.port()) else {
                            return SynResult::Miss;
                        };
                        match parse_syn_v4(&raw) {
                            Some(obs) => SynResult::Hit(obs),
                            None => SynResult::Malformed,
                        }
                    }
                    SocketAddr::V6(a) => {
                        let Some(raw) = probe.lookup_v6(*a.ip(), a.port()) else {
                            return SynResult::Miss;
                        };
                        match parse_syn_v6(&raw) {
                            Some(obs) => SynResult::Hit(obs),
                            None => SynResult::Malformed,
                        }
                    }
                }
            }))
        }
    };

    #[cfg(not(feature = "ebpf-tcp"))]
    let syn_probe: Option<huginn_proxy_lib::SynProbe> = None;

    info!("huginn-proxy starting");

    let watch_opts = WatchOptions {
        config_path: Some(cli.config_path.clone()),
        watch: cli.watch,
        watch_delay_secs: cli.watch_delay_secs,
    };

    // run() broadcasts shutdown_tx on SIGTERM/SIGINT and awaits cert-reload + config-watcher
    // handles before returning. ACME (feature `acme`) is wired in here, mirroring `syn_probe`:
    // `huginn-acme` drives the issuance/renewal state machines and hands back `(host, resolver)`
    // pairs + tasks; the library only ever sees trait objects and shutdown handles.
    #[cfg(feature = "acme")]
    let acme: Option<huginn_proxy_lib::AcmeRuntime> = match &static_cfg.acme {
        Some(acme_cfg) => {
            let hosts: Vec<String> = dynamic_cfg
                .load()
                .domains
                .iter()
                .filter(|d| d.is_acme(true))
                .filter_map(|d| d.host.clone())
                .collect();
            if hosts.is_empty() {
                info!("[acme] is configured but no domain resolves to ACME; ACME disabled");
                None
            } else {
                let cancel = tokio_util::sync::CancellationToken::new();

                // Channel used to gate `/ready` until the first ACME cert is deployed.
                // The sender lives inside `on_event` (wrapped in Arc so the closure can be
                // cloned across domains). The receiver is passed to `AcmeRuntime` and read
                // by `run()` before calling `readiness.mark_ready()`.
                let (acme_ready_tx, acme_ready_rx) = tokio::sync::watch::channel(false);
                let acme_ready_tx = Arc::new(acme_ready_tx);

                let metrics_for_acme = Arc::clone(&metrics);
                let ready_tx = Arc::clone(&acme_ready_tx);
                let on_event: huginn_acme::OnAcmeEvent = Arc::new(move |domain, event| {
                    use huginn_acme::AcmeEvent;
                    match event {
                        AcmeEvent::DeployedNewCert => {
                            metrics_for_acme.record_acme_renewal_success(domain);
                            metrics_for_acme.set_acme_cert_ready(domain, true);
                            ready_tx.send(true).ok();
                        }
                        AcmeEvent::DeployedCachedCert => {
                            metrics_for_acme.record_acme_cached_cert(domain);
                            metrics_for_acme.set_acme_cert_ready(domain, true);
                            ready_tx.send(true).ok();
                        }
                        AcmeEvent::CacheStored => {
                            metrics_for_acme.record_acme_cache_stored(domain);
                        }
                        AcmeEvent::Error => {
                            metrics_for_acme.record_acme_error(domain);
                        }
                    }
                });
                // The outer Arc (`acme_ready_tx`) is no longer needed; the closure holds the
                // only remaining reference through `ready_tx`.
                drop(acme_ready_tx);

                let handles = huginn_acme::start_acme(
                    &acme_cfg.contact_email,
                    &acme_cfg.cache_dir,
                    acme_cfg.staging,
                    acme_cfg.directory_url.as_deref(),
                    acme_cfg.directory_ca_path.as_deref(),
                    &hosts,
                    cancel.clone(),
                    Some(on_event),
                )?;
                let mut acme_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let _ = acme_shutdown.wait_for(|v| *v).await;
                    cancel.cancel();
                });
                let tasks = handles
                    .tasks
                    .into_iter()
                    .map(|handle| ServiceHandle { handle, name: ServiceName::Acme })
                    .collect();
                info!(domains = hosts.len(), "ACME enabled (TLS-ALPN-01)");
                Some(huginn_proxy_lib::AcmeRuntime {
                    resolvers: handles.resolvers,
                    tasks,
                    cert_ready_rx: Some(acme_ready_rx),
                })
            }
        }
        None => None,
    };
    // Built without ACME support: warn loudly if the config expects it, so ACME-managed domains
    // don't silently end up without a certificate.
    #[cfg(not(feature = "acme"))]
    let acme: Option<huginn_proxy_lib::AcmeRuntime> = {
        if static_cfg.acme.is_some() {
            tracing::warn!(
                "[acme] is configured but this binary was built without the `acme` feature; \
                 ACME-managed domains will have no certificate. Rebuild with `--features acme`."
            );
        }
        None
    };

    let result = run(
        Arc::clone(&static_cfg),
        Arc::clone(&dynamic_cfg),
        metrics,
        syn_probe,
        acme,
        watch_opts,
        shutdown_tx,
        readiness,
    )
    .await;

    // Metrics server already received the shutdown signal (via shutdown_rx clone).
    if let Some(svc) = metrics_service {
        svc.shutdown(Duration::from_secs(2)).await;
    }

    // All background tasks have exited and flushed their logs, safe to tear down tracing.
    shutdown_tracing();

    result?;
    Ok(())
}
