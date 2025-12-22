#![forbid(unsafe_code)]

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use huginn_proxy_lib::config::load_from_path;
use huginn_proxy_lib::tcp::metrics::{serve_prometheus_metrics, ConnectionCount};
use huginn_proxy_lib::tcp;
use tokio::signal;
use tokio::sync::watch;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args();
    let _bin = args.next();
    let config_path = args.next().ok_or("usage: huginn-proxy <config-path>")?;

    let config = Arc::new(load_from_path(&config_path)?);

    let log_level = config
        .telemetry
        .log_level
        .clone()
        .unwrap_or_else(|| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(false)
        .init();

    let counters = Arc::new(ConnectionCount::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let metrics_task = if config.telemetry.basic_metrics {
        let addr: SocketAddr = config
            .telemetry
            .metrics_addr
            .ok_or("telemetry.metrics_addr is required when telemetry.basic_metrics = true")?;
        Some(tokio::spawn(serve_prometheus_metrics(addr, counters.clone(), "huginn_tcp")))
    } else {
        None
    };

    let handler = tokio::spawn({
        let cfg = config.clone();
        let ctrs = counters.clone();
        let rx = shutdown_rx.clone();
        async move { tcp::run(cfg, ctrs, rx).await }
    });

    info!("huginn-proxy started; waiting for shutdown signal");
    signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);

    let _ = handler.await;
    if let Some(task) = metrics_task {
        task.abort();
    }
    Ok(())
}
