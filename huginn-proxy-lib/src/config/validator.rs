use crate::config::types::{Config, Mode};

pub fn validate(config: &Config) -> Result<(), String> {
    if config.backends.is_empty() {
        return Err("at least one backend is required".into());
    }
    if config.backends.iter().any(|b| b.address.trim().is_empty()) {
        return Err("backend address cannot be empty".into());
    }
    if matches!(config.mode, Mode::TlsTermination) && config.tls.is_none() {
        return Err("tls configuration is required when mode = \"tls_termination\"".into());
    }
    if config.timeouts.connect_ms == 0 {
        return Err("connect_ms must be > 0".into());
    }
    if config.timeouts.idle_ms == 0 {
        return Err("idle_ms must be > 0".into());
    }
    Ok(())
}
