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

    // Initialize TCP SYN eBPF probe when feature is enabled.
    // Both `fingerprint.tcp_enabled = true` and `fingerprint.ebpf_tcp_interface` must be set.
    // On failure, logs a warning and continues without eBPF (graceful degradation).
    #[cfg(feature = "ebpf-tcp")]
    let syn_probe: Option<huginn_proxy_lib::SynProbe> = {
        use huginn_proxy_ebpf::EbpfProbe;
        use huginn_proxy_lib::fingerprinting::{parse_syn_raw, SynFingerprint, TcpSynData};
        use std::net::SocketAddr;

        if !config.fingerprint.tcp_enabled {
            tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
            None
        } else if let Some(ref iface) = config.fingerprint.ebpf_tcp_interface {
            let listen_ip = match config.listen {
                SocketAddr::V4(a) => Some(*a.ip()),
                SocketAddr::V6(_) => {
                    tracing::warn!("eBPF TCP SYN probe requires IPv4 listen address; skipping");
                    None
                }
            };
            let listen_port = config.listen.port();

            if let Some(ip) = listen_ip {
                match EbpfProbe::new(iface, Some(ip), Some(listen_port)) {
                    Ok(probe) => {
                        info!(interface = %iface, "eBPF TCP SYN probe initialized");
                        let probe = Arc::new(probe);
                        Some(Arc::new(
                            move |peer: std::net::SocketAddr| -> Option<SynFingerprint> {
                                let (peer_ip, peer_port) = match peer {
                                    SocketAddr::V4(a) => (*a.ip(), a.port()),
                                    SocketAddr::V6(_) => return None,
                                };
                                let raw = probe.lookup(peer_ip, peer_port)?;
                                let data = TcpSynData {
                                    ip_ttl: raw.ip_ttl,
                                    window: raw.window,
                                    optlen: raw.optlen,
                                    options: raw.options,
                                };
                                parse_syn_raw(&data)
                            },
                        ))
                    }
                    Err(e) => {
                        tracing::warn!("eBPF TCP SYN probe failed to initialize: {e:#?}. Continuing without SYN fingerprinting.");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            tracing::warn!(
                "TCP SYN fingerprinting enabled but `fingerprint.ebpf_tcp_interface` is not set; skipping"
            );
            None
        }
    };

    #[cfg(not(feature = "ebpf-tcp"))]
    let syn_probe: Option<huginn_proxy_lib::SynProbe> = None;

    info!("huginn-proxy starting");

    let result = run(config, metrics, syn_probe).await;

    if let Some(handle) = metrics_handle {
        info!("Shutting down observability server");
        handle.abort();
    }

    shutdown_tracing();

    result?;
    Ok(())
}
