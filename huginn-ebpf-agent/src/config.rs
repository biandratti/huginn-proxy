use huginn_ebpf::pin;
use std::net::{Ipv4Addr, Ipv6Addr};

mod capture;
pub mod env;
mod health_format;
mod log_level;
mod rate_limit;
pub use capture::resolve_capture_backend;
pub use health_format::HealthFormat;
use health_format::parse_health_format;
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
    pub dst_ports: Vec<u16>,
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

impl ConfigError {
    fn missing(name: &'static str) -> Self {
        Self::Missing { name: name.to_string() }
    }

    fn invalid(name: &'static str, value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Invalid { name: name.to_string(), value: value.into(), reason: reason.into() }
    }
}

pub fn from_env(get_var: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
    let interface = get_var(env::INTERFACE).ok_or(ConfigError::missing(env::INTERFACE))?;

    let dst_ip_v4_str = get_var(env::DST_IP_V4).ok_or(ConfigError::missing(env::DST_IP_V4))?;
    let dst_ip_v4: Ipv4Addr = dst_ip_v4_str.parse().map_err(|_| {
        ConfigError::invalid(env::DST_IP_V4, dst_ip_v4_str.clone(), "must be a valid IPv4 address")
    })?;

    let dst_ip_v6: Ipv6Addr = match get_var(env::DST_IP_V6) {
        Some(s) => s.parse().map_err(|_| {
            ConfigError::invalid(env::DST_IP_V6, s.clone(), "must be a valid IPv6 address")
        })?,
        None => Ipv6Addr::UNSPECIFIED,
    };

    let dst_ports_str = get_var(env::DST_PORTS).ok_or(ConfigError::missing(env::DST_PORTS))?;
    let dst_ports = parse_dst_ports(&dst_ports_str)?;

    let pin_path = get_var(env::PIN_PATH).unwrap_or_else(|| DEFAULT_PIN_PATH.to_string());

    let link_pin_path = match get_var(env::LINK_PIN_PATH) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::invalid(
                    env::LINK_PIN_PATH,
                    s,
                    "must be a non-empty bpffs path",
                ));
            }
            trimmed.to_string()
        }
        None => pin::capture_link_path(&pin_path).display().to_string(),
    };

    let syn_map_max_entries = get_var(env::SYN_MAP_MAX_ENTRIES)
        .map(|s| {
            s.parse().map_err(|_| {
                ConfigError::invalid(
                    env::SYN_MAP_MAX_ENTRIES,
                    s.clone(),
                    "must be a positive integer",
                )
            })
        })
        .transpose()
        .map(|opt| opt.unwrap_or(huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES))?;

    let metrics_listen_addr =
        get_var(env::METRICS_ADDR).ok_or(ConfigError::missing(env::METRICS_ADDR))?;

    let metrics_port_str =
        get_var(env::METRICS_PORT).ok_or(ConfigError::missing(env::METRICS_PORT))?;
    let metrics_port: u16 = metrics_port_str.parse().map_err(|_| {
        ConfigError::invalid(
            env::METRICS_PORT,
            metrics_port_str.clone(),
            "must be a valid port number (1-65535)",
        )
    })?;

    let capture = resolve_capture_backend(&get_var)?;

    let log_level = resolve_log_level(&get_var)?;

    let rate_limit = resolve_rate_limit(&get_var)?;

    let drain_delay_secs = parse_optional_u64(&get_var, env::DRAIN_DELAY_SECS, 0, false)?;
    let heartbeat_secs = parse_optional_u64(&get_var, env::HEARTBEAT_SECS, 1, true)?;

    let health_format = parse_health_format(&get_var)?;

    Ok(Config {
        interface,
        dst_ip_v4,
        dst_ip_v6,
        dst_ports,
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

fn parse_dst_ports(raw: &str) -> Result<Vec<u16>, ConfigError> {
    let parts: Vec<&str> = raw.split(',').map(str::trim).collect();
    if parts.is_empty() || parts.len() > 2 || parts.iter().any(|part| part.is_empty()) {
        return Err(ConfigError::invalid(
            env::DST_PORTS,
            raw,
            "must be one or two comma-separated ports",
        ));
    }
    let mut ports = Vec::with_capacity(parts.len());
    for part in parts {
        let port: u16 = part.parse().map_err(|_| {
            ConfigError::invalid(env::DST_PORTS, raw, "must be a port number in 1..=65535")
        })?;
        if port == 0 {
            return Err(ConfigError::invalid(
                env::DST_PORTS,
                raw,
                "must be a port number in 1..=65535; 0 is not a filter",
            ));
        }
        if ports.contains(&port) {
            return Err(ConfigError::invalid(env::DST_PORTS, raw, "ports must be distinct"));
        }
        ports.push(port);
    }
    Ok(ports)
}

fn parse_optional_u64(
    get_var: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u64,
    reject_zero: bool,
) -> Result<u64, ConfigError> {
    let Some(raw) = get_var(name) else {
        return Ok(default);
    };
    let parsed = raw
        .parse::<u64>()
        .map_err(|_| ConfigError::invalid(name, raw.clone(), "must be a non-negative integer"))?;
    if reject_zero && parsed == 0 {
        return Err(ConfigError::invalid(name, raw, "must be a positive integer"));
    }
    Ok(parsed)
}
