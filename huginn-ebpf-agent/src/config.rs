use std::net::Ipv4Addr;
use huginn_ebpf::pin;

pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;

#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub pin_path: String,
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

    let dst_ip_str = get_var("HUGINN_EBPF_DST_IP")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_IP".to_string() })?;
    let dst_ip: Ipv4Addr = dst_ip_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_IP".to_string(),
        value: dst_ip_str.clone(),
        reason: "must be a valid IPv4 address".to_string(),
    })?;

    let dst_port_str = get_var("HUGINN_EBPF_DST_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_DST_PORT".to_string() })?;
    let dst_port: u16 = dst_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_DST_PORT".to_string(),
        value: dst_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    let pin_path = get_var("HUGINN_EBPF_PIN_PATH").unwrap_or_else(|| DEFAULT_PIN_PATH.to_string());

    let metrics_listen_addr = get_var("HUGINN_EBPF_METRICS_ADDR")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_ADDR".to_string() })?;

    let metrics_port_str = get_var("HUGINN_EBPF_METRICS_PORT")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_METRICS_PORT".to_string() })?;
    let metrics_port: u16 = metrics_port_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_METRICS_PORT".to_string(),
        value: metrics_port_str.clone(),
        reason: "must be a valid port number (1-65535)".to_string(),
    })?;

    Ok(Config { interface, dst_ip, dst_port, pin_path, metrics_listen_addr, metrics_port })
}
