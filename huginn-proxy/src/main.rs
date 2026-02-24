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
        use huginn_net_tcp::tcp::{IpVersion, PayloadSize};
        use huginn_proxy_ebpf::EbpfProbe;
        use huginn_proxy_lib::fingerprinting::{parse_syn_raw, SynResult, TcpSynData};
        use std::net::SocketAddr;

        // eBPF filter parameters are infrastructure-specific — read from env vars set in
        // docker-compose or K8s Deployment YAML. Not part of the application config file.
        // When tcp_enabled = true all three are required; missing vars are a startup error.
        //   HUGINN_EBPF_INTERFACE — network interface the XDP program attaches to
        //   HUGINN_EBPF_DST_IP   — destination IP filter (0.0.0.0 = all interfaces)
        //   HUGINN_EBPF_DST_PORT — destination port filter (must match proxy listen port)
        if !config.fingerprint.tcp_enabled {
            tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
            None
        } else {
            let iface = env::var("HUGINN_EBPF_INTERFACE")
                .map_err(|_| "HUGINN_EBPF_INTERFACE env var is required when tcp_enabled = true")?;

            let dst_ip: std::net::Ipv4Addr = env::var("HUGINN_EBPF_DST_IP")
                .map_err(|_| "HUGINN_EBPF_DST_IP env var is required when tcp_enabled = true")?
                .parse()
                .map_err(|_| "HUGINN_EBPF_DST_IP must be a valid IPv4 address (e.g. 0.0.0.0)")?;

            let dst_port: u16 = env::var("HUGINN_EBPF_DST_PORT")
                .map_err(|_| "HUGINN_EBPF_DST_PORT env var is required when tcp_enabled = true")?
                .parse()
                .map_err(|_| "HUGINN_EBPF_DST_PORT must be a valid port number (1-65535)")?;

            match config.listen {
                SocketAddr::V6(_) => {
                    return Err("eBPF TCP SYN probe requires an IPv4 listen address".into());
                }
                SocketAddr::V4(_) => {}
            }

            let probe = EbpfProbe::new(&iface, dst_ip, dst_port)
                .map_err(|e| format!("eBPF TCP SYN probe failed to initialize: {e:#?}"))?;

            let probe = Arc::new(probe);
            Some(Arc::new(move |peer: SocketAddr| -> SynResult {
                let (peer_ip, peer_port) = match peer {
                    SocketAddr::V4(a) => (*a.ip(), a.port()),
                    SocketAddr::V6(_) => return SynResult::Miss,
                };
                let Some(raw) = probe.lookup(peer_ip, peer_port) else {
                    return SynResult::Miss;
                };
                let data = TcpSynData {
                    ip_ttl: raw.ip_ttl,
                    window: raw.window,
                    optlen: raw.optlen,
                    options: raw.options,
                    // XDP program filters non-IPv4 at entry; V4 is always correct here.
                    ip_version: IpVersion::V4,
                    olen: raw.ip_olen,
                    // DF, ECN, seq=0, ack+, push/urg flags — readable in XDP, not yet extracted.
                    quirks: vec![],
                    // SYN packets never carry payload — invariant by TCP spec.
                    pclass: PayloadSize::Zero,
                };
                match parse_syn_raw(&data) {
                    Some(obs) => SynResult::Hit(obs),
                    None => SynResult::Malformed,
                }
            }))
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
