#![forbid(unsafe_code)]

use std::env;
use std::sync::Arc;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::run;
use huginn_proxy_lib::telemetry::{
    init_metrics, init_tracing_with_otel, shutdown_tracing, start_observability_server,
};
use tracing::info;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = env::args();
    let _bin = args.next();
    let config_path = args.next().ok_or("usage: huginn-proxy <config-path>")?;

    let config = Arc::new(load_from_path(&config_path)?);

    // Use config file log level as default
    // RUST_LOG environment variable can override at runtime (e.g., docker run -e RUST_LOG=debug)
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    init_tracing_with_otel(
        log_level,
        config.logging.show_target,
        config.telemetry.otel_log_level.clone(),
    )?;

    let (metrics, metrics_handle) = if let Some(metrics_port) = config.telemetry.metrics_port {
        let (metrics, registry) =
            init_metrics().map_err(|e| format!("Failed to initialize metrics: {e}"))?;

        info!(port = metrics_port, "Metrics initialized, starting observability server");
        let backends_for_observability = Arc::new(config.backends.clone());
        let handle = tokio::spawn(async move {
            if let Err(e) =
                start_observability_server(metrics_port, registry, backends_for_observability).await
            {
                tracing::error!(error = %e, "Observability server error");
            }
        });
        (Some(metrics), Some(handle))
    } else {
        info!("Metrics disabled (no metrics_port configured)");
        (None, None)
    };

    info!("huginn-proxy starting");

    let result = run(config, metrics).await;

    if let Some(handle) = metrics_handle {
        tracing::info!("Shutting down observability server");
        handle.abort();
    }

    shutdown_tracing();

    result?;
    Ok(())
}
