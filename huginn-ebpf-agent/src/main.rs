/// Standalone eBPF agent that loads the XDP program, pins BPF maps, and
/// stays alive until SIGTERM. Designed to run as a DaemonSet so that
/// the proxy (Deployment) can open the pinned maps without needing
/// CAP_NET_ADMIN or seccomp:unconfined.
use std::net::Ipv4Addr;

use huginn_ebpf::pin::DEFAULT_PIN_BASE;
use huginn_ebpf::EbpfProbe;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let default_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let iface = std::env::var("HUGINN_EBPF_INTERFACE")
        .map_err(|_| "HUGINN_EBPF_INTERFACE env var is required")?;

    let dst_ip: Ipv4Addr = std::env::var("HUGINN_EBPF_DST_IP")
        .unwrap_or_else(|_| "0.0.0.0".to_string())
        .parse()
        .map_err(|_| "HUGINN_EBPF_DST_IP must be a valid IPv4 address")?;

    let dst_port: u16 = std::env::var("HUGINN_EBPF_DST_PORT")
        .unwrap_or_else(|_| "0".to_string())
        .parse()
        .map_err(|_| "HUGINN_EBPF_DST_PORT must be a valid port number")?;

    let pin_path =
        std::env::var("HUGINN_EBPF_PIN_PATH").unwrap_or_else(|_| DEFAULT_PIN_BASE.to_string());

    let mut probe = EbpfProbe::new(&iface, dst_ip, dst_port)?;
    probe.pin_maps(&pin_path)?;

    tracing::info!("eBPF agent ready — waiting for SIGTERM");

    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || {
        let _ = tx.send(());
    })?;
    rx.recv().ok();

    tracing::info!("Shutting down — unpinning maps and detaching XDP");
    EbpfProbe::unpin_maps(&pin_path);
    drop(probe);

    Ok(())
}
