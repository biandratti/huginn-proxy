#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use huginn_proxy_lib::tcp::metrics::{serve_prometheus_metrics, ConnectionCount};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let counters = Arc::new(ConnectionCount::default());
    let metrics_addr: SocketAddr = "127.0.0.1:9900".parse()?;

    let metrics =
        tokio::spawn(serve_prometheus_metrics(metrics_addr, counters.clone(), "huginn_tcp"));

    signal::ctrl_c().await?;
    metrics.abort();
    Ok(())
}
