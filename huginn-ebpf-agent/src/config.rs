use huginn_ebpf::pin;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;
pub use huginn_ebpf::{CaptureBackend, EbpfLogLevel, XdpAttachMode};

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip_v4: Ipv4Addr,
    pub dst_ip_v6: Ipv6Addr,
    pub dst_port: u16,
    pub pin_path: String,
    pub syn_map_max_entries: u32,
    pub capture: CaptureBackend,
    pub metrics_listen_addr: String,
    pub metrics_port: u16,
    pub log_level: EbpfLogLevel,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {name} is required")]
    Missing { name: String },

    #[error("environment variable {name}: invalid value '{value}' — {reason}")]
    Invalid {
        name: String,
        value: String,
        reason: String,
    },
}

pub fn from_env(get_var: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
    let interface = get_var("HUGINN_EBPF_INTERFACE")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_INTERFACE".to_string() })?;

    let dst_ip_v4_str = get_var("HUGINN_EBPF_DST_IP_V4")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_IP_V4".to_string() })?;
    let dst_ip_v4: Ipv4Addr = dst_ip_v4_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_IP_V4".to_string(),
        value: dst_ip_v4_str.clone(),
        reason: "must be a valid IPv4 address".to_string(),
    })?;

    let dst_ip_v6: Ipv6Addr = match get_var("HUGINN_EBPF_DST_IP_V6") {
        Some(s) => s.parse().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_DST_IP_V6".to_string(),
            value: s.clone(),
            reason: "must be a valid IPv6 address".to_string(),
        })?,
        None => Ipv6Addr::UNSPECIFIED,
    };

    let dst_port_str = get_var("HUGINN_EBPF_DST_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_PORT".to_string() })?;
    let dst_port: u16 = dst_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_PORT".to_string(),
        value: dst_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    let pin_path = get_var("HUGINN_EBPF_PIN_PATH").unwrap_or_else(|| DEFAULT_PIN_PATH.to_string());

    let syn_map_max_entries = get_var("HUGINN_EBPF_SYN_MAP_MAX_ENTRIES")
        .map(|s| {
            s.parse().map_err(|_| ConfigError::Invalid {
                name: "HUGINN_EBPF_SYN_MAP_MAX_ENTRIES".to_string(),
                value: s.clone(),
                reason: "must be a positive integer".to_string(),
            })
        })
        .transpose()
        .map(|opt| opt.unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES))?;

    let metrics_listen_addr = get_var("HUGINN_EBPF_METRICS_ADDR")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_ADDR".to_string() })?;

    let metrics_port_str = get_var("HUGINN_EBPF_METRICS_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_PORT".to_string() })?;
    let metrics_port: u16 = metrics_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_METRICS_PORT".to_string(),
        value: metrics_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    let capture = resolve_capture_backend(&get_var)?;

    let log_level = resolve_log_level(&get_var)?;

    Ok(Config {
        interface,
        dst_ip_v4,
        dst_ip_v6,
        dst_port,
        pin_path,
        syn_map_max_entries,
        capture,
        metrics_listen_addr,
        metrics_port,
        log_level,
    })
}

fn resolve_log_level(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<EbpfLogLevel, ConfigError> {
    let Some(raw) = get_var("HUGINN_EBPF_LOG_LEVEL") else {
        return Ok(EbpfLogLevel::Off);
    };
    EbpfLogLevel::parse(&raw).ok_or_else(|| ConfigError::Invalid {
        name: "HUGINN_EBPF_LOG_LEVEL".to_string(),
        value: raw,
        reason: "must be one of: off, error, warn, info, debug, trace (case-insensitive)"
            .to_string(),
    })
}

/// Resolve `HUGINN_EBPF_CAPTURE` (`xdp-native` | `xdp-skb` | `tc`). Default: `xdp-native`.
///
/// On VLAN/bond edges prefer `tc`: generic XDP drops GRO-merged packets; TC never drops.
pub fn resolve_capture_backend(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<CaptureBackend, ConfigError> {
    let Some(raw) = get_var("HUGINN_EBPF_CAPTURE") else {
        return Ok(CaptureBackend::Xdp(XdpAttachMode::Native));
    };

    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "xdp-native" => Ok(CaptureBackend::Xdp(XdpAttachMode::Native)),
        "xdp-skb" => Ok(CaptureBackend::Xdp(XdpAttachMode::Skb)),
        "tc" => Ok(CaptureBackend::Tc),
        _ => Err(ConfigError::Invalid {
            name: "HUGINN_EBPF_CAPTURE".to_string(),
            value: raw,
            reason: "must be 'xdp-native', 'xdp-skb', or 'tc' (case-insensitive)".to_string(),
        }),
    }
}

/// Human-readable label for the resolved capture backend (for startup logging).
pub fn capture_label(backend: CaptureBackend) -> &'static str {
    match backend {
        CaptureBackend::Xdp(XdpAttachMode::Native) => "xdp-native",
        CaptureBackend::Xdp(XdpAttachMode::Skb) => "xdp-skb",
        CaptureBackend::Tc => "tc",
    }
}
