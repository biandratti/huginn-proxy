//! Standalone eBPF agent that loads the XDP program, pins BPF maps, and
//! stays alive until SIGTERM. Designed to run as a DaemonSet so that
//! the proxy (Deployment) can open the pinned maps without needing
//! CAP_NET_ADMIN or seccomp:unconfined.

#![forbid(unsafe_code)]

mod config;
mod metrics;
mod routes;

use std::env;

use huginn_ebpf::EbpfProbe;
use tokio::signal;

use crate::config::from_env;

/// Wait for SIGTERM or SIGINT (same as huginn-proxy-lib).
async fn wait_for_shutdown_signal() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
        .map_err(|e| std::io::Error::other(format!("Failed to setup SIGTERM handler: {e}")))?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
        .map_err(|e| std::io::Error::other(format!("Failed to setup SIGINT handler: {e}")))?;
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = sigint.recv() => {}
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let default_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let get_var = |name: &str| env::var(name).ok();
    let cfg = from_env(get_var)?;

    let mut probe = EbpfProbe::new(&cfg.interface, cfg.dst_ip, cfg.dst_port)?;
    probe.pin_maps(&cfg.pin_path)?;

    let pin_path = std::sync::Arc::new(cfg.pin_path.clone());
    let (registry, agent_metrics) = metrics::init_metrics(pin_path)?;
    agent_metrics.set_ready();
    routes::spawn_server(
        std::sync::Arc::new(registry),
        cfg.pin_path.clone(),
        &cfg.metrics_listen_addr,
        cfg.metrics_port,
    );

    tracing::info!(
        interface = %cfg.interface,
        pin_path = %cfg.pin_path,
        "eBPF agent ready — waiting for SIGTERM"
    );

    wait_for_shutdown_signal().await?;

    tracing::info!("Shutting down — unpinning maps and detaching XDP");
    EbpfProbe::unpin_maps(&cfg.pin_path);
    drop(probe);

    Ok(())
}
