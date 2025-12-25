use serde::Deserialize;
use std::{fs, net::SocketAddr, path::Path};

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
}

pub fn load_from_path<P: AsRef<Path>>(
    p: P,
) -> Result<Config, Box<dyn std::error::Error + Send + Sync>> {
    let txt = fs::read_to_string(p)?;
    let cfg: Config = toml::from_str(&txt)?;
    Ok(cfg)
}
