//! eBPF agent: loads the capture program, pins maps, serves metrics.

use huginn_ebpf::{
    bump_capture_generation, new_agent_boot_id, read_capture_state, write_capture_state,
    CaptureState, EbpfLogLevel, EbpfLogPoller, EbpfProbe,
};
use huginn_ebpf_agent::config::from_env;
use huginn_ebpf_agent::error::Result;
use huginn_ebpf_agent::healthchecks::AgentHealth;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::signal;

/// Drain the eBPF log ring buffer when its fd is readable.
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

    // Default RUST_LOG to the eBPF log level when logging is enabled.
    let fallback_level = match cfg.log_level {
        EbpfLogLevel::Off => "info",
        other => other.as_str(),
    };
    let default_level = env::var("RUST_LOG").unwrap_or_else(|_| fallback_level.to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

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

    // Loading pins the maps under `pin_path`, reusing them if the previous
    // agent instance left them behind.
    let mut probe = EbpfProbe::new(
        &cfg.interface,
        cfg.dst_ip_v4,
        cfg.dst_ip_v6,
        cfg.dst_port,
        cfg.syn_map_max_entries,
        cfg.capture,
        cfg.log_level,
        &cfg.pin_path,
        std::path::Path::new(&cfg.link_pin_path),
        cfg.rate_limit,
    )?;

    if let Some(poller) = probe.take_debug_log_poller()? {
        spawn_ebpf_log_drain(poller);
    }

    let boot_id = new_agent_boot_id()?;
    write_capture_state(&cfg.pin_path, CaptureState::capturing(boot_id, 1))?;

    let health = AgentHealth::new(cfg.pin_path.clone(), cfg.link_pin_path.clone());
    health.mark_attached(probe.link_pinned());

    let pin_path = Arc::new(cfg.pin_path.clone());
    let (registry, metrics) = huginn_ebpf_agent::telemetry::init_metrics(pin_path)?;
    metrics.set_ready(health.is_ready());
    metrics.set_rate_limit_enabled(cfg.rate_limit.enabled());
    if let Some(mode) = probe.capture_mode() {
        metrics.set_capture_info(mode, probe.link_pinned());
    }

    let stop_heartbeat = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop_heartbeat);
        let pin = cfg.pin_path.clone();
        let health = Arc::clone(&health);
        let metrics = metrics.clone();
        let interval = Duration::from_secs(cfg.heartbeat_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if stop.load(Ordering::Acquire) {
                    break;
                }
                if let Err(error) = bump_capture_generation(&pin) {
                    tracing::debug!(%error, "failed to bump capture_state generation");
                }
                metrics.set_ready(health.is_ready());
            }
        });
    }

    let registry = Arc::new(registry);
    let listen_addr = cfg.metrics_listen_addr.clone();
    let port = cfg.metrics_port;
    let health_for_http = Arc::clone(&health);
    let health_format = cfg.health_format;
    tokio::spawn(async move {
        let _ = huginn_ebpf_agent::telemetry::start_observability_server(
            &listen_addr,
            port,
            registry,
            health_for_http,
            health_format,
        )
        .await;
    });

    let capture_str = cfg.capture.as_str();
    let capture_mode_str = probe
        .capture_mode()
        .map(|m| m.as_str())
        .unwrap_or(capture_str);
    tracing::info!(
        interface = %cfg.interface,
        pin_path = %cfg.pin_path,
        link_pin_path = %cfg.link_pin_path,
        dst_ip_v4 = %cfg.dst_ip_v4,
        dst_ip_v6 = %cfg.dst_ip_v6,
        dst_port = %cfg.dst_port,
        capture = capture_str,
        capture_mode = capture_mode_str,
        link_pinned = probe.link_pinned(),
        log_level = cfg.log_level.as_str(),
        "eBPF agent ready, waiting for SIGTERM"
    );

    wait_for_shutdown_signal().await?;

    stop_heartbeat.store(true, Ordering::Release);
    health.mark_draining();
    if let Ok(mut state) = read_capture_state(&cfg.pin_path) {
        state.lifecycle = huginn_ebpf::pin::CAPTURE_LIFECYCLE_DRAINING;
        if let Err(error) = write_capture_state(&cfg.pin_path, state) {
            tracing::warn!(%error, "failed to publish capture_state draining");
        }
    }
    metrics.set_ready(health.is_ready());

    if cfg.drain_delay_secs > 0 {
        tracing::info!(
            drain_delay_secs = cfg.drain_delay_secs,
            "agent draining; capture still attached"
        );
        tokio::time::sleep(Duration::from_secs(cfg.drain_delay_secs)).await;
    }

    // Map pins and the capture link pin are left in place. The next agent
    // instance reuses the maps (same kernel IDs) and, when the link is pinned
    // (TCX / XDP fd-link), atomically replaces the program via attach_to_link
    // so capture never detaches. Netlink attaches still detach on drop.
    tracing::info!(
        link_pinned = probe.link_pinned(),
        "Shutting down (map and link pins left for reuse)"
    );
    drop(probe);

    Ok(())
}
