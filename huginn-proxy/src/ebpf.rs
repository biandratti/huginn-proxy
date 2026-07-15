use huginn_proxy_lib::config::StaticConfig;
use huginn_proxy_lib::proxy::shutdown::{ServiceHandle, ShutdownWatch};
use huginn_proxy_lib::telemetry::Metrics;
use huginn_proxy_lib::SynProbe;
use std::sync::Arc;

#[cfg(feature = "ebpf-tcp")]
use {
    arc_swap::ArcSwap,
    huginn_ebpf::{parse_syn_v4, parse_syn_v6, EbpfProbe},
    huginn_proxy::ebpf_config::reconnect_poll_secs,
    huginn_proxy_lib::fingerprinting::SynResult,
    huginn_proxy_lib::proxy::shutdown::ServiceName,
    std::{env, net::SocketAddr, time::Duration},
    tokio::time::MissedTickBehavior,
};

#[cfg(feature = "ebpf-tcp")]
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[cfg(feature = "ebpf-tcp")]
pub(crate) async fn connect_syn_probe(
    static_cfg: &StaticConfig,
    metrics: Arc<Metrics>,
    shutdown_rx: ShutdownWatch,
) -> (Option<SynProbe>, Option<ServiceHandle>) {
    if !static_cfg.fingerprint.tcp_enabled {
        tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
        return (None, None);
    }

    let pin_path = env::var("HUGINN_EBPF_PIN_PATH")
        .unwrap_or_else(|_| huginn_ebpf::pin::DEFAULT_PIN_BASE.to_string());
    let syn_map_max_entries = env::var("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES);
    let reconnect_poll_secs =
        reconnect_poll_secs(env::var("HUGINN_EBPF_RECONNECT_POLL_SECS").ok().as_deref());

    let probe = loop {
        match EbpfProbe::from_pinned(&pin_path, syn_map_max_entries) {
            Ok(probe) => break probe,
            Err(_) => {
                tracing::warn!(
                    pin_path,
                    "eBPF agent maps not available yet, retrying in {}s...",
                    RETRY_INTERVAL.as_secs()
                );
                tokio::time::sleep(RETRY_INTERVAL).await;
            }
        }
    };

    let probe = Arc::new(ArcSwap::from_pointee(probe));
    let lookup_probe = Arc::clone(&probe);
    let syn_probe: SynProbe = Arc::new(move |peer| {
        let current = lookup_probe.load();
        lookup_syn(current.as_ref(), peer)
    });

    if reconnect_poll_secs == 0 {
        tracing::info!("automatic eBPF pinned-map reconnection disabled");
        return (Some(syn_probe), None);
    }

    let poll_interval = Duration::from_secs(reconnect_poll_secs);
    let handle = tokio::spawn(watch_pinned_maps(
        probe,
        pin_path,
        syn_map_max_entries,
        poll_interval,
        metrics,
        shutdown_rx,
    ));
    let watcher = ServiceHandle { handle, name: ServiceName::EbpfReconnect };
    (Some(syn_probe), Some(watcher))
}

#[cfg(feature = "ebpf-tcp")]
fn lookup_syn(probe: &EbpfProbe, peer: SocketAddr) -> SynResult {
    match peer {
        SocketAddr::V4(address) => {
            let Some(raw) = probe.lookup(*address.ip(), address.port()) else {
                return SynResult::Miss;
            };
            match parse_syn_v4(&raw) {
                Some(observation) => SynResult::Hit(observation),
                None => SynResult::Malformed,
            }
        }
        SocketAddr::V6(address) => {
            let Some(raw) = probe.lookup_v6(*address.ip(), address.port()) else {
                return SynResult::Miss;
            };
            match parse_syn_v6(&raw) {
                Some(observation) => SynResult::Hit(observation),
                None => SynResult::Malformed,
            }
        }
    }
}

#[cfg(feature = "ebpf-tcp")]
async fn watch_pinned_maps(
    probe: Arc<ArcSwap<EbpfProbe>>,
    pin_path: String,
    syn_map_max_entries: u32,
    poll_interval: Duration,
    metrics: Arc<Metrics>,
    mut shutdown_rx: ShutdownWatch,
) {
    let mut interval = tokio::time::interval(poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    interval.tick().await;

    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|shutting_down| *shutting_down) => {
                tracing::info!("eBPF pinned-map reconnect watcher shutting down");
                break;
            }
            _ = interval.tick() => {
                if let Err(error) = reconnect_if_changed(
                    &probe,
                    &pin_path,
                    syn_map_max_entries,
                    &metrics,
                ) {
                    tracing::debug!(
                        %error,
                        pin_path,
                        "eBPF pins unavailable or changing; retaining current maps"
                    );
                }
            }
        }
    }
}

#[cfg(feature = "ebpf-tcp")]
fn reconnect_if_changed(
    probe: &ArcSwap<EbpfProbe>,
    pin_path: &str,
    syn_map_max_entries: u32,
    metrics: &Metrics,
) -> Result<(), huginn_ebpf::EbpfError> {
    let current = probe.load();
    let Some(old_ids) = current.pinned_map_ids() else {
        return Ok(());
    };
    let published_ids = EbpfProbe::pinned_map_ids_from_path(pin_path)?;
    if published_ids == old_ids {
        return Ok(());
    }
    drop(current);

    let replacement = EbpfProbe::from_pinned(pin_path, syn_map_max_entries)?;
    let Some(new_ids) = replacement.pinned_map_ids() else {
        return Ok(());
    };

    // The agent removes and re-pins maps sequentially. Publish only a complete,
    // still-current snapshot; otherwise retry on the next tick.
    if EbpfProbe::pinned_map_ids_from_path(pin_path)? != new_ids {
        return Ok(());
    }

    probe.store(Arc::new(replacement));
    if old_ids.ipv4 != new_ids.ipv4 {
        metrics.record_ebpf_map_reconnect("ipv4");
    }
    if old_ids.ipv6 != new_ids.ipv6 {
        metrics.record_ebpf_map_reconnect("ipv6");
    }
    tracing::warn!(
        old_ipv4_map_id = old_ids.ipv4,
        new_ipv4_map_id = new_ids.ipv4,
        old_ipv6_map_id = old_ids.ipv6,
        new_ipv6_map_id = new_ids.ipv6,
        "reconnected to replacement eBPF pinned maps"
    );
    Ok(())
}

#[cfg(not(feature = "ebpf-tcp"))]
pub(crate) async fn connect_syn_probe(
    _static_cfg: &StaticConfig,
    _metrics: Arc<Metrics>,
    _shutdown_rx: ShutdownWatch,
) -> (Option<SynProbe>, Option<ServiceHandle>) {
    (None, None)
}
