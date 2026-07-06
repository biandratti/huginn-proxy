//! Standalone eBPF agent that loads the XDP program, pins BPF maps, and
//! stays alive until SIGTERM. Designed to run as a DaemonSet so that
//! the proxy (Deployment) can open the pinned maps without needing
//! CAP_NET_ADMIN or seccomp:unconfined.

use huginn_ebpf::{EbpfLogLevel, EbpfLogPoller, EbpfProbe};
use huginn_ebpf_agent::config::{capture_label, from_env};
use huginn_ebpf_agent::error::Result;
use std::env;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal;

/// Spawn a background task that drains the eBPF log ring buffer whenever its fd is readable.
///
/// The poller's fd is edge-triggered via `AsyncFd`; on each readiness we `flush()` all pending
/// records (forwarded to the tracing subscriber) and clear readiness. If the fd registration
/// fails the task logs once and exits — losing debug logs must never take down the agent.
fn spawn_ebpf_log_drain(poller: EbpfLogPoller) {
    tokio::spawn(async move {
        let mut async_fd = match AsyncFd::with_interest(poller, Interest::READABLE) {
            Ok(fd) => fd,
            Err(e) => {
                tracing::warn!(error = %e, "failed to register eBPF log fd; debug logs disabled");
                return;
            }
        };
        loop {
            let mut guard = match async_fd.readable_mut().await {
                Ok(guard) => guard,
                Err(e) => {
                    tracing::warn!(error = %e, "eBPF log fd readiness error; stopping log drain");
                    return;
                }
            };
            guard.get_inner_mut().flush();
            guard.clear_ready();
        }
    });
}

async fn wait_for_shutdown_signal() -> Result<()> {
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
async fn main() -> Result<()> {
    let get_var = |name: &str| env::var(name).ok();
    let cfg = from_env(get_var)?;

    // When eBPF logging is enabled and RUST_LOG is unset, default the filter to the chosen level so
    // the kernel records are actually shown; otherwise they could be filtered out below `info`.
    let fallback_level = match cfg.log_level {
        EbpfLogLevel::Off => "info",
        other => other.as_str(),
    };
    let default_level = env::var("RUST_LOG").unwrap_or_else(|_| fallback_level.to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    // `.init()` also installs the log->tracing bridge (tracing-subscriber's `tracing-log`
    // feature), so `aya-log` records emitted via the `log` facade reach this subscriber.
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let iface_path = std::path::Path::new("/sys/class/net").join(&cfg.interface);
    if !iface_path.exists() {
        return Err(std::io::Error::other(format!(
            "interface {} not found (no such path: {})",
            cfg.interface,
            iface_path.display()
        ))
        .into());
    }

    let mut probe = EbpfProbe::new(
        &cfg.interface,
        cfg.dst_ip_v4,
        cfg.dst_ip_v6,
        cfg.dst_port,
        cfg.syn_map_max_entries,
        cfg.capture,
        cfg.log_level,
    )?;
    probe.pin_maps(&cfg.pin_path)?;

    // If logging is enabled, drain the eBPF log ring buffer on a background task. aya-log does not
    // poll itself: we register the ring-buffer fd with tokio and flush on readability.
    if let Some(poller) = probe.take_debug_log_poller()? {
        spawn_ebpf_log_drain(poller);
    }

    let pin_path = Arc::new(cfg.pin_path.clone());
    let (registry, metrics) = huginn_ebpf_agent::telemetry::init_metrics(pin_path)?;
    metrics.set_ready();

    let registry = Arc::new(registry);
    let pin_path_str = cfg.pin_path.clone();
    let listen_addr = cfg.metrics_listen_addr.clone();
    let port = cfg.metrics_port;
    tokio::spawn(async move {
        let _ = huginn_ebpf_agent::telemetry::start_observability_server(
            &listen_addr,
            port,
            registry,
            pin_path_str,
        )
        .await;
    });

    let capture_str = capture_label(cfg.capture);
    tracing::info!(
        interface = %cfg.interface,
        pin_path = %cfg.pin_path,
        dst_ip_v4 = %cfg.dst_ip_v4,
        dst_ip_v6 = %cfg.dst_ip_v6,
        dst_port = %cfg.dst_port,
        capture = capture_str,
        log_level = cfg.log_level.as_str(),
        "eBPF agent ready, waiting for SIGTERM"
    );

    wait_for_shutdown_signal().await?;

    tracing::info!("Shutting down, unpinning maps and detaching capture program");
    EbpfProbe::unpin_maps(&cfg.pin_path);
    drop(probe);

    Ok(())
}
