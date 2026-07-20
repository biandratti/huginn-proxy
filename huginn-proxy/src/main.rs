#![forbid(unsafe_code)]

mod validation;

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser;
use huginn_proxy::ebpf;
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
#[command(
    name = "huginn-proxy",
    version,
    about = "High-performance reverse proxy",
    long_about = "High-performance reverse proxy with passive client fingerprinting (TLS JA4, \
HTTP/2 Akamai, TCP SYN), TLS termination, hot-reload config, and Prometheus metrics.",
    after_help = "EXAMPLES:\n  \
huginn-proxy config.toml                              Start the proxy\n  \
huginn-proxy --validate config.toml                  Validate the config, then exit\n  \
huginn-proxy --validate --strict config.toml         Validate and fail on any warning\n  \
huginn-proxy --print-effective-config config.toml    Print the effective, secret-redacted config as JSON\n\n\
ENVIRONMENT:\n  \
HUGINN_CONFIG_PATH   Config file path (alternative to the CONFIG argument)\n  \
RUST_LOG             Override the log level at runtime (e.g. RUST_LOG=debug)\n\n\
Filesystem hot reload is configured in the [reload] section of the config file (watch on by default).\n\
Run --help to see all options."
)]
struct Cli {
    /// Path to the TOML or YAML configuration file
    #[arg(value_name = "CONFIG", env = "HUGINN_CONFIG_PATH")]
    config_path: PathBuf,

    /// Parse and validate the config file without starting the proxy
    #[arg(long)]
    validate: bool,

    /// Validate and print the effective, secret-redacted config as JSON, then exit
    #[arg(long)]
    print_effective_config: bool,

    /// With --validate/--print-effective-config, exit non-zero if any config warnings are found
    #[arg(long)]
    strict: bool,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cli = Cli::parse();
    let validation_mode = cli.validate || cli.print_effective_config;

    if validation_mode {
        return validation::run(&cli.config_path, cli.print_effective_config, cli.strict);
    }

    let config = load_from_path(&cli.config_path)?;
    config.validate_cross_refs()?;

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

    let (syn_probe, ebpf_reconnect_service) =
        ebpf::connect_syn_probe(&static_cfg, Arc::clone(&metrics), shutdown_rx.clone()).await;

    info!("huginn-proxy starting");

    let watch_opts = WatchOptions {
        config_path: Some(cli.config_path.clone()),
        watch: static_cfg.reload.watch,
        debounce_secs: static_cfg.reload.debounce_secs,
    };

    // run() broadcasts shutdown_tx on SIGTERM/SIGINT and awaits
    // cert-reload + config-watcher handles before returning.
    let result = run(
        Arc::clone(&static_cfg),
        Arc::clone(&dynamic_cfg),
        metrics,
        syn_probe,
        watch_opts,
        shutdown_tx,
        readiness,
    )
    .await;

    // Metrics server already received the shutdown signal (via shutdown_rx clone).
    if let Some(svc) = metrics_service {
        svc.shutdown(Duration::from_secs(2)).await;
    }
    if let Some(svc) = ebpf_reconnect_service {
        svc.shutdown(Duration::from_secs(2)).await;
    }

    // All background tasks have exited and flushed their logs, safe to tear down tracing.
    shutdown_tracing();

    result?;
    Ok(())
}
