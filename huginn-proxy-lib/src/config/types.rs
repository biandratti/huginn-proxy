use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Deserialize, Clone)]
pub struct Backend {
    pub address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Route {
    pub prefix: String,
    pub backend: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    #[serde(default)]
    pub alpn: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct FingerprintConfig {
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
    #[serde(default = "default_true")]
    pub http_enabled: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_false")]
    pub show_target: bool,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct TimeoutConfig {
    #[serde(default = "default_connect_timeout")]
    pub connect_ms: u64,
    #[serde(default = "default_idle_timeout")]
    pub idle_ms: u64,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub fingerprint: FingerprintConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub timeout: TimeoutConfig,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_idle_timeout() -> u64 {
    60000
}

fn default_shutdown_timeout() -> u64 {
    30
}
