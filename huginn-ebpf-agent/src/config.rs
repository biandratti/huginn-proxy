use huginn_ebpf::pin;
use std::net::{Ipv4Addr, Ipv6Addr};

mod capture;
mod health_format;
mod log_level;
mod rate_limit;
pub use capture::resolve_capture_backend;
use health_format::parse_health_format;
pub use health_format::HealthFormat;
use log_level::resolve_log_level;
use rate_limit::resolve_rate_limit;
pub use rate_limit::{DEFAULT_BURST, DEFAULT_WINDOW_SECONDS};

pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;
pub use huginn_ebpf::{CaptureBackend, EbpfLogLevel, SynRateLimit, XdpAttachMode};

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip_v4: Ipv4Addr,
    pub dst_ip_v6: Ipv6Addr,
    pub dst_port: u16,
    pub pin_path: String,
    pub link_pin_path: String,
    pub syn_map_max_entries: u32,
    pub capture: CaptureBackend,
    pub metrics_listen_addr: String,
    pub metrics_port: u16,
    pub log_level: EbpfLogLevel,
    pub rate_limit: SynRateLimit,
    pub drain_delay_secs: u64,
    pub heartbeat_secs: u64,
    pub health_format: HealthFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {name} is required")]
    Missing { name: String },

    #[error("environment variable {name}: invalid value '{value}': {reason}")]
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

    let link_pin_path = match get_var("HUGINN_EBPF_LINK_PIN_PATH") {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::Invalid {
                    name: "HUGINN_EBPF_LINK_PIN_PATH".to_string(),
                    value: s,
                    reason: "must be a non-empty bpffs path".to_string(),
                });
            }
            trimmed.to_string()
        }
        None => pin::capture_link_path(&pin_path).display().to_string(),
    };

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

    let rate_limit = resolve_rate_limit(&get_var)?;

    let drain_delay_secs = parse_optional_u64(&get_var, "HUGINN_EBPF_DRAIN_DELAY_SECS", 0, false)?;
    let heartbeat_secs = parse_optional_u64(&get_var, "HUGINN_EBPF_HEARTBEAT_SECS", 1, true)?;

    let health_format = parse_health_format(&get_var)?;

    Ok(Config {
        interface,
        dst_ip_v4,
        dst_ip_v6,
        dst_port,
        pin_path,
        link_pin_path,
        syn_map_max_entries,
        capture,
        metrics_listen_addr,
        metrics_port,
        log_level,
        rate_limit,
        drain_delay_secs,
        heartbeat_secs,
        health_format,
    })
}

fn parse_optional_u64(
    get_var: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: u64,
    reject_zero: bool,
) -> Result<u64, ConfigError> {
    let Some(raw) = get_var(name) else {
        return Ok(default);
    };
    let parsed = raw.parse::<u64>().map_err(|_| ConfigError::Invalid {
        name: name.to_string(),
        value: raw.clone(),
        reason: "must be a non-negative integer".to_string(),
    })?;
    if reject_zero && parsed == 0 {
        return Err(ConfigError::Invalid {
            name: name.to_string(),
            value: raw,
            reason: "must be a positive integer".to_string(),
        });
    }
    Ok(parsed)
}
