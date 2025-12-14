use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub listen: SocketAddr,
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub peek_http: bool,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub telemetry: Telemetry,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub address: String,
    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Forward,
    TlsTermination,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeouts {
    #[serde(default = "Timeouts::default_connect_ms")]
    pub connect_ms: u64,
    #[serde(default = "Timeouts::default_idle_ms")]
    pub idle_ms: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self { connect_ms: Self::default_connect_ms(), idle_ms: Self::default_idle_ms() }
    }
}

impl Timeouts {
    const fn default_connect_ms() -> u64 {
        5_000
    }
    const fn default_idle_ms() -> u64 {
        60_000
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Telemetry {
    #[serde(default)]
    pub access_log: bool,
    #[serde(default)]
    pub basic_metrics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub server_names: Vec<String>,
}
