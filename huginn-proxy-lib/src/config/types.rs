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

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Graceful shutdown timeout in seconds (default: 30) // TODO: make this configurable
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

fn default_shutdown_timeout() -> u64 {
    30
}

