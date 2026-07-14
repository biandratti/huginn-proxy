use huginn_proxy_lib::config::StaticConfig;
use huginn_proxy_lib::SynProbe;

#[cfg(feature = "ebpf-tcp")]
use {
    huginn_ebpf::{parse_syn_v4, parse_syn_v6, EbpfProbe},
    huginn_proxy_lib::fingerprinting::SynResult,
    std::{env, net::SocketAddr, sync::Arc, time::Duration},
};

#[cfg(feature = "ebpf-tcp")]
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[cfg(feature = "ebpf-tcp")]
pub(crate) async fn connect_syn_probe(static_cfg: &StaticConfig) -> Option<SynProbe> {
    if !static_cfg.fingerprint.tcp_enabled {
        tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
        return None;
    }

    let pin_path = env::var("HUGINN_EBPF_PIN_PATH")
        .unwrap_or_else(|_| huginn_ebpf::pin::DEFAULT_PIN_BASE.to_string());
    let syn_map_max_entries = env::var("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES);

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

    let probe = Arc::new(probe);
    Some(Arc::new(move |peer| lookup_syn(&probe, peer)))
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

#[cfg(not(feature = "ebpf-tcp"))]
pub(crate) async fn connect_syn_probe(_static_cfg: &StaticConfig) -> Option<SynProbe> {
    None
}
