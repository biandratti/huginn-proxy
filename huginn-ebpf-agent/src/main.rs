//! Standalone eBPF agent that loads the XDP program, pins BPF maps, and
//! stays alive until SIGTERM. Designed to run as a DaemonSet so that
//! the proxy (Deployment) can open the pinned maps without needing
//! CAP_NET_ADMIN or seccomp:unconfined.

#![forbid(unsafe_code)]

mod config;
mod healthchecks;
mod telemetry;
use crate::config::from_env;
use huginn_ebpf::EbpfProbe;
use std::env;
use std::sync::Arc;
use tokio::signal;

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

    let iface_path = std::path::Path::new("/sys/class/net").join(&cfg.interface);
    if !iface_path.exists() {
        return Err(std::io::Error::other(format!(
            "interface {} not found (no such path: {})",
            cfg.interface,
            iface_path.display()
        ))
        .into());
    }

    let mut probe = EbpfProbe::new(&cfg.interface, cfg.dst_ip, cfg.dst_port)?;
    probe.pin_maps(&cfg.pin_path)?;

    let pin_path = std::sync::Arc::new(cfg.pin_path.clone());
    let (registry, metrics) = telemetry::init_metrics(pin_path)?;
    metrics.set_ready();

    let registry = Arc::new(registry);
    let pin_path_str = cfg.pin_path.clone();
    let listen_addr = cfg.metrics_listen_addr.clone();
    let port = cfg.metrics_port;
    tokio::spawn(async move {
        let _ =
            telemetry::start_observability_server(&listen_addr, port, registry, pin_path_str).await;
    });

    tracing::info!(
        interface = %cfg.interface,
        pin_path = %cfg.pin_path,
        dst_ip = %cfg.dst_ip,
        dst_port = %cfg.dst_port,
        "eBPF agent ready — waiting for SIGTERM"
    );

    wait_for_shutdown_signal().await?;

    tracing::info!("Shutting down — unpinning maps and detaching XDP");
    EbpfProbe::unpin_maps(&cfg.pin_path);
    drop(probe);

    Ok(())
}
