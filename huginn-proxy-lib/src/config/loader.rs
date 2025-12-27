use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::error::{ProxyError, Result};

pub fn load_from_path<P: AsRef<Path>>(p: P) -> Result<Config> {
    let txt = fs::read_to_string(p)
        .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;
    let cfg: Config = toml::from_str(&txt)
        .map_err(|e| ProxyError::Config(format!("Failed to parse config: {e}")))?;
    
    validate_config(&cfg)?;
    
    Ok(cfg)
}

fn validate_config(cfg: &Config) -> Result<()> {
    if cfg.backends.is_empty() {
        return Err(ProxyError::NoBackends);
    }

    if let Some(tls) = &cfg.tls {
        if !Path::new(&tls.cert_path).exists() {
            return Err(ProxyError::Config(format!(
                "Certificate file not found: {}",
                tls.cert_path
            )));
        }
        if !Path::new(&tls.key_path).exists() {
            return Err(ProxyError::Config(format!(
                "Key file not found: {}",
                tls.key_path
            )));
        }
    }

    let backend_addresses: std::collections::HashSet<_> = cfg
        .backends
        .iter()
        .map(|b| b.address.as_str())
        .collect();

    for route in &cfg.routes {
        if !backend_addresses.contains(route.backend.as_str()) {
            return Err(ProxyError::Config(format!(
                "Route references unknown backend: {}",
                route.backend
            )));
        }
    }

    Ok(())
}

