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

    // TCP SYN fingerprinting via eBPF/XDP.
    // When tcp_enabled = true the proxy opens BPF maps pinned by huginn-ebpf-agent.
    // The agent may start after the proxy (e.g. network_mode: "service:proxy" in
    // Docker Compose), so we retry with backoff until the maps appear.
    #[cfg(feature = "ebpf-tcp")]
    let syn_probe: Option<huginn_proxy_lib::SynProbe> = {
        use huginn_ebpf::{parse_syn, EbpfProbe};
        use huginn_proxy_lib::fingerprinting::SynResult;
        use std::net::SocketAddr;

        if !config.fingerprint.tcp_enabled {
            tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
            None
        } else {
            let pin_path = env::var("HUGINN_EBPF_PIN_PATH")
                .unwrap_or_else(|_| huginn_ebpf::pin::DEFAULT_PIN_BASE.to_string());

            const RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

            let probe = loop {
                match EbpfProbe::from_pinned(&pin_path) {
                    Ok(p) => break p,
                    Err(_) => {
                        tracing::warn!(
                            pin_path,
                            "eBPF agent maps not available yet, retrying in {}s...",
                            RETRY_INTERVAL.as_secs()
                        );
                        std::thread::sleep(RETRY_INTERVAL);
                    }
                }
            };

            let probe = Arc::new(probe);
            Some(Arc::new(move |peer: SocketAddr| -> SynResult {
                let (peer_ip, peer_port) = match peer {
                    SocketAddr::V4(a) => (*a.ip(), a.port()),
                    SocketAddr::V6(_) => return SynResult::Miss,
                };
                let Some(raw) = probe.lookup(peer_ip, peer_port) else {
                    return SynResult::Miss;
                };
                match parse_syn(&raw) {
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
