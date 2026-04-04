use huginn_ebpf::pin;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;
pub use huginn_ebpf::XdpMode;

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip_v4: Ipv4Addr,
    pub dst_ip_v6: Ipv6Addr,
    pub dst_port: u16,
    pub pin_path: String,
    pub syn_map_max_entries: u32,
    pub xdp_mode: XdpMode,
    pub metrics_listen_addr: String,
    pub metrics_port: u16,
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

    let xdp_mode = match get_var("HUGINN_EBPF_XDP_MODE").as_deref() {
        Some("skb") => XdpMode::Skb,
        Some("native") | None => XdpMode::Native,
        Some(v) => {
            return Err(ConfigError::Invalid {
                name: "HUGINN_EBPF_XDP_MODE".to_string(),
                value: v.to_string(),
                reason: "must be 'native' or 'skb'".to_string(),
            });
        }
    };

    Ok(Config {
        interface,
        dst_ip_v4,
        dst_ip_v6,
        dst_port,
        pin_path,
        syn_map_max_entries,
        xdp_mode,
        metrics_listen_addr,
        metrics_port,
    })
}
