//! Configuration from environment variables.

use std::net::Ipv4Addr;

use huginn_ebpf::pin;

/// Default base path for pinned BPF maps (same as proxy expectation).
pub const DEFAULT_PIN_PATH: &str = pin::DEFAULT_PIN_BASE;

/// Agent configuration (env vars).
#[derive(Debug, Clone)]
pub struct Config {
    pub interface: String,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub pin_path: String,
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

impl Config {
    /// Load configuration from environment variables.
    /// `HUGINN_EBPF_PIN_PATH` defaults to `/sys/fs/bpf/huginn` if unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        let interface = std::env::var("HUGINN_EBPF_INTERFACE")
            .map_err(|_| ConfigError::Missing { name: "HUGINN_EBPF_INTERFACE".to_string() })?;

        let dst_ip_str = std::env::var("HUGINN_EBPF_DST_IP")
            .map_err(|_| ConfigError::Missing { name: "HUGINN_EBPF_DST_IP".to_string() })?;
        let dst_ip: Ipv4Addr = dst_ip_str.parse().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_DST_IP".to_string(),
            value: dst_ip_str.clone(),
            reason: "must be a valid IPv4 address".to_string(),
        })?;

        let dst_port_str = std::env::var("HUGINN_EBPF_DST_PORT")
            .map_err(|_| ConfigError::Missing { name: "HUGINN_EBPF_DST_PORT".to_string() })?;
        let dst_port: u16 = dst_port_str.parse().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_DST_PORT".to_string(),
            value: dst_port_str.clone(),
            reason: "must be a valid port number (1-65535)".to_string(),
        })?;

        let pin_path =
            std::env::var("HUGINN_EBPF_PIN_PATH").unwrap_or_else(|_| DEFAULT_PIN_PATH.to_string());

        Ok(Self { interface, dst_ip, dst_port, pin_path })
    }
}
