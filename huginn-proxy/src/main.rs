#![forbid(unsafe_code)]

use std::env;
use std::sync::Arc;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::run;
use huginn_proxy_lib::telemetry::{
    init_metrics, init_tracing_with_otel, shutdown_tracing, start_metrics_server,
};
use tracing::info;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut args = env::args();
    let _bin = args.next();
    let config_path = args.next().ok_or("usage: huginn-proxy <config-path>")?;

    let config = Arc::new(load_from_path(&config_path)?);

    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| config.logging.level.clone());

    init_tracing_with_otel(
        log_level,
        config.logging.show_target,
        config.telemetry.otel_log_level.clone(),
    )?;

    let metrics_handle = if let Some(metrics_port) = config.telemetry.metrics_port {
        match init_metrics() {
            Ok((_metrics, registry)) => {
                info!(port = metrics_port, "Metrics initialized, starting metrics server");
                Some(tokio::spawn(async move {
                    if let Err(e) = start_metrics_server(metrics_port, registry).await {
                        tracing::error!(error = %e, "Metrics server error");
                    }
                }))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to initialize metrics, continuing without metrics");
                None
            }
        }
    } else {
        info!("Metrics disabled (no metrics_port configured)");
        None
    };

    info!("huginn-proxy starting");

    let result = run(config).await;

    if let Some(handle) = metrics_handle {
        tracing::info!("Shutting down metrics server");
        handle.abort();
    }

    shutdown_tracing();

    result?;
    Ok(())
}
