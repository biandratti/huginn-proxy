use std::fs;
use std::path::Path;

use crate::config::parser::ConfigFormat;
use crate::config::Config;
use crate::error::{ProxyError, Result};

pub fn load_from_path<P: AsRef<Path>>(p: P) -> Result<Config> {
    let path = p.as_ref();
    let format = ConfigFormat::from_path(path)?;

    let content = fs::read_to_string(path)
        .map_err(|e| ProxyError::Config(format!("Failed to read config file: {e}")))?;

    let cfg = format.parser().parse(&content)?;

    validate_config(&cfg)?;

    Ok(cfg)
}

fn validate_config(cfg: &Config) -> Result<()> {
    for domain in &cfg.domains {
        let host = domain.host.as_deref().unwrap_or("_default_");
        match (&domain.cert_path, &domain.key_path) {
            (Some(cert), Some(key)) => {
                if !Path::new(cert).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': certificate file not found: {cert}"
                    )));
                }
                if !Path::new(key).exists() {
                    return Err(ProxyError::Config(format!(
                        "Domain '{host}': key file not found: {key}"
                    )));
                }
            }
            (None, None) => {}
            _ => {
                return Err(ProxyError::Config(format!(
                    "Domain '{host}': cert_path and key_path must both be set or both omitted"
                )));
            }
        }
    }

    cfg.validate_cross_refs()?;

    Ok(())
}
