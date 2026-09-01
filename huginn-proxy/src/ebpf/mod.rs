pub mod config;

use huginn_proxy_lib::config::StaticConfig;
use huginn_proxy_lib::proxy::shutdown::{ServiceHandle, ShutdownWatch};
use huginn_proxy_lib::telemetry::Metrics;
use huginn_proxy_lib::SynProbe;
use std::sync::Arc;

#[cfg(feature = "ebpf-tcp")]
use {
    self::config::{
        capture_poll_secs_from_env, capture_stale_ticks_from_env, reconnect_poll_secs_from_env,
    },
    self::gate::{default_link_pin_path, load_gate, resolve as resolve_gate, store_gate},
    arc_swap::ArcSwap,
    huginn_ebpf::{parse_syn_v4, parse_syn_v6, EbpfProbe},
    huginn_proxy_lib::fingerprinting::SynResult,
    huginn_proxy_lib::proxy::shutdown::ServiceName,
    huginn_proxy_lib::{GateState, ReadinessGate},
    std::{env, net::SocketAddr, sync::atomic::AtomicU8, time::Duration},
    tokio::time::{Instant, MissedTickBehavior},
};

#[cfg(feature = "ebpf-tcp")]
pub mod gate;

pub struct SynProbeConnect {
    pub syn_probe: Option<SynProbe>,
    pub watcher: Option<ServiceHandle>,
    pub gate: Option<huginn_proxy_lib::ReadinessGate>,
}

#[cfg(feature = "ebpf-tcp")]
pub fn connect_syn_probe(
    static_cfg: &StaticConfig,
    metrics: Arc<Metrics>,
    shutdown_rx: ShutdownWatch,
) -> Result<SynProbeConnect, config::ParseError> {
    if !static_cfg.fingerprint.tcp_enabled {
        tracing::info!("TCP SYN fingerprinting disabled (`fingerprint.tcp_enabled = false`)");
        return Ok(SynProbeConnect { syn_probe: None, watcher: None, gate: None });
    }

    let pin_path = env::var("HUGINN_EBPF_PIN_PATH")
        .unwrap_or_else(|_| huginn_ebpf::pin::DEFAULT_PIN_BASE.to_string());
    let link_pin_path = default_link_pin_path(&pin_path);
    let reconnect_poll_secs =
        reconnect_poll_secs_from_env(env::var("HUGINN_EBPF_RECONNECT_POLL_SECS").ok())?;
    let capture_poll_secs =
        capture_poll_secs_from_env(env::var("HUGINN_EBPF_CAPTURE_POLL_SECS").ok())?;
    let stale_ticks =
        capture_stale_ticks_from_env(env::var("HUGINN_EBPF_CAPTURE_STALE_TICKS").ok())?;

    let gate_slot = Arc::new(AtomicU8::new(GateState::Absent as u8));
    let gate_for_ready = Arc::clone(&gate_slot);
    let gate: ReadinessGate = Arc::new(move || load_gate(&gate_for_ready));

    let probe = Arc::new(ArcSwap::from_pointee(None::<EbpfProbe>));
    let lookup_probe = Arc::clone(&probe);
    let syn_probe: SynProbe = Arc::new(move |peer| match lookup_probe.load().as_ref() {
        Some(current) => lookup_syn(current, peer),
        None => SynResult::Miss,
    });

    if reconnect_poll_secs == 0 {
        tracing::info!(
            "automatic eBPF pinned-map reconnection disabled (capture gate still polls)"
        );
    }

    let handle = tokio::spawn(watch_pinned_maps(WatchConfig {
        probe,
        pin_path,
        link_pin_path,
        capture_poll: Duration::from_secs(capture_poll_secs),
        reconnect_poll: if reconnect_poll_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(reconnect_poll_secs))
        },
        stale_ticks,
        gate_slot,
        metrics,
        shutdown_rx,
    }));
    let watcher = ServiceHandle { handle, name: ServiceName::EbpfWatcher };
    Ok(SynProbeConnect { syn_probe: Some(syn_probe), watcher: Some(watcher), gate: Some(gate) })
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
struct WatchConfig {
    probe: Arc<ArcSwap<Option<EbpfProbe>>>,
    pin_path: String,
    link_pin_path: String,
    capture_poll: Duration,
    reconnect_poll: Option<Duration>,
    stale_ticks: u32,
    gate_slot: Arc<AtomicU8>,
    metrics: Arc<Metrics>,
    shutdown_rx: ShutdownWatch,
}

#[cfg(feature = "ebpf-tcp")]
async fn watch_pinned_maps(mut cfg: WatchConfig) {
    // The first tick fires immediately: the probe must be populated and the gate resolved
    // before `/ready` can flip, otherwise startup reports `capture_absent` and misses SYN
    // lookups for a whole `capture_poll` even when the agent has been publishing for hours.
    let mut interval = tokio::time::interval(cfg.capture_poll);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut last_generation = None;
    let mut stagnant_ticks = 0_u32;
    let mut last_reconnect =
        Instant::now().checked_sub(cfg.reconnect_poll.unwrap_or(cfg.capture_poll));

    loop {
        tokio::select! {
            biased;
            _ = cfg.shutdown_rx.wait_for(|phase| phase.is_stopping()) => {
                tracing::info!("eBPF watcher shutting down");
                break;
            }
            _ = interval.tick() => {
                try_populate_or_reconnect(
                    &cfg.probe,
                    &cfg.pin_path,
                    &cfg.metrics,
                    cfg.reconnect_poll,
                    &mut last_reconnect,
                );
                let state = resolve_gate(
                    &cfg.pin_path,
                    &cfg.link_pin_path,
                    &mut last_generation,
                    &mut stagnant_ticks,
                    cfg.stale_ticks,
                );
                store_gate(&cfg.gate_slot, state);
            }
        }
    }
}

#[cfg(feature = "ebpf-tcp")]
fn try_populate_or_reconnect(
    probe: &ArcSwap<Option<EbpfProbe>>,
    pin_path: &str,
    metrics: &Metrics,
    reconnect_poll: Option<Duration>,
    last_reconnect: &mut Option<Instant>,
) {
    let current = probe.load();
    if current.is_none() {
        if let Ok(opened) = EbpfProbe::from_pinned(pin_path) {
            probe.store(Arc::new(Some(opened)));
            tracing::info!(pin_path, "eBPF TCP SYN fingerprinting connected to pinned maps");
        }
        return;
    }

    let Some(interval) = reconnect_poll else {
        return;
    };
    let due = match *last_reconnect {
        None => true,
        Some(at) => at.elapsed() >= interval,
    };
    if !due {
        return;
    }
    *last_reconnect = Some(Instant::now());
    if let Err(error) = reconnect_if_changed(probe, pin_path, metrics) {
        tracing::debug!(
            %error,
            pin_path,
            "eBPF pins unavailable or changing; retaining current maps"
        );
    }
}

#[cfg(feature = "ebpf-tcp")]
fn reconnect_if_changed(
    probe: &ArcSwap<Option<EbpfProbe>>,
    pin_path: &str,
    metrics: &Metrics,
) -> Result<(), huginn_ebpf::EbpfError> {
    let current = probe.load();
    let Some(inner) = current.as_ref() else {
        return Ok(());
    };
    let Some(old_ids) = inner.pinned_map_ids() else {
        return Ok(());
    };
    let published_ids = EbpfProbe::pinned_map_ids_from_path(pin_path)?;
    if published_ids == old_ids {
        return Ok(());
    }
    drop(current);

    let replacement = EbpfProbe::from_pinned(pin_path)?;
    let Some(new_ids) = replacement.pinned_map_ids() else {
        return Ok(());
    };

    if EbpfProbe::pinned_map_ids_from_path(pin_path)? != new_ids {
        return Ok(());
    }

    probe.store(Arc::new(Some(replacement)));
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
pub fn connect_syn_probe(
    _static_cfg: &StaticConfig,
    _metrics: Arc<Metrics>,
    _shutdown_rx: ShutdownWatch,
) -> Result<SynProbeConnect, config::ParseError> {
    Ok(SynProbeConnect { syn_probe: None, watcher: None, gate: None })
}
