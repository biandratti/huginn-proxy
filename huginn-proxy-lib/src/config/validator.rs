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
    for route in &config.http.routes {
        if route.prefix.is_empty() {
            return Err("http route prefix cannot be empty".into());
        }
        if route.backend.trim().is_empty() {
            return Err("http route backend cannot be empty".into());
        }
    }
    if config.http.max_peek_bytes == 0 {
        return Err("http.max_peek_bytes must be > 0".into());
    }
    if let Some(addr) = config.telemetry.metrics_addr {
        if addr.port() == 0 {
            return Err("telemetry.metrics_addr port must be > 0".into());
        }
    }
    if let Some(max) = config.max_connections {
        if max == 0 {
            return Err("max_connections must be > 0 when set".into());
        }
    }
    if let Some(backlog) = config.backlog {
        if backlog == 0 {
            return Err("backlog must be > 0 when set".into());
        }
    }
    Ok(())
}
