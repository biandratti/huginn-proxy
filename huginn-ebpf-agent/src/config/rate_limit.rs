use super::ConfigError;
use huginn_ebpf::SynRateLimit;

/// Resolve the per-source-IP SYN rate limit from the environment. Mirrors the proxy's global
/// `[security.rate_limit]`: `HUGINN_EBPF_RATE_LIMIT_BURST` is the per-window per-IP threshold
/// and `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` the window. Disabled by default.
pub(super) fn resolve_rate_limit(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<SynRateLimit, ConfigError> {
    let enabled = match get_var("HUGINN_EBPF_RATE_LIMIT_ENABLED") {
        Some(s) => s.parse::<bool>().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_RATE_LIMIT_ENABLED".to_string(),
            value: s.clone(),
            reason: "must be 'true' or 'false'".to_string(),
        })?,
        None => false,
    };

    if !enabled {
        return Ok(SynRateLimit::disabled());
    }

    let burst_str = get_var("HUGINN_EBPF_RATE_LIMIT_BURST")
        .ok_or(ConfigError::Missing { name: "HUGINN_EBPF_RATE_LIMIT_BURST".to_string() })?;
    let burst: u32 = burst_str.parse().map_err(|_| ConfigError::Invalid {
        name: "HUGINN_EBPF_RATE_LIMIT_BURST".to_string(),
        value: burst_str.clone(),
        reason: "must be a positive integer".to_string(),
    })?;
    if burst == 0 {
        return Err(ConfigError::Invalid {
            name: "HUGINN_EBPF_RATE_LIMIT_BURST".to_string(),
            value: burst_str,
            reason: "must be greater than zero".to_string(),
        });
    }

    let window_seconds: u64 = match get_var("HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS") {
        Some(s) => s.parse().map_err(|_| ConfigError::Invalid {
            name: "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS".to_string(),
            value: s.clone(),
            reason: "must be a positive integer".to_string(),
        })?,
        None => 1,
    };
    if window_seconds == 0 {
        return Err(ConfigError::Invalid {
            name: "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS".to_string(),
            value: "0".to_string(),
            reason: "must be greater than zero".to_string(),
        });
    }

    Ok(SynRateLimit::from_burst_window(true, burst, window_seconds))
}
