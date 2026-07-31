use super::ConfigError;
use huginn_ebpf::SynRateLimit;
use std::str::FromStr;

/// `burst` when `HUGINN_EBPF_RATE_LIMIT_BURST` is unset.
pub const DEFAULT_BURST: u32 = 2000;

/// Window when `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` is unset.
pub const DEFAULT_WINDOW_SECONDS: u64 = 1;

/// Resolve the per-source-IP SYN rate limit from the environment: `HUGINN_EBPF_RATE_LIMIT_BURST`
/// is the per-window per-IP threshold and `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` the window.
/// Disabled by default. Not the proxy's `[security.rate_limit]`: this one counts SYNs and is
/// enforced per CPU, so the same number means something different. See `EBPF-SETUP.md`.
pub(super) fn resolve_rate_limit(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<SynRateLimit, ConfigError> {
    let enabled = parse_or_default(
        get_var,
        "HUGINN_EBPF_RATE_LIMIT_ENABLED",
        false,
        "must be 'true' or 'false'",
        |_| true,
    )?;
    if !enabled {
        return Ok(SynRateLimit::disabled());
    }

    let max_burst = SynRateLimit::MAX_THRESHOLD;
    let burst = parse_or_default(
        get_var,
        "HUGINN_EBPF_RATE_LIMIT_BURST",
        DEFAULT_BURST,
        &format!("must be an integer between 1 and {max_burst}"),
        |b| b > 0 && b <= max_burst,
    )?;

    let max_window = SynRateLimit::MAX_WINDOW_SECONDS;
    let window_seconds = parse_or_default(
        get_var,
        "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_WINDOW_SECONDS,
        &format!("must be an integer between 1 and {max_window} seconds"),
        |w| w > 0 && w <= max_window,
    )?;

    Ok(SynRateLimit::from_burst_window(true, burst, window_seconds))
}

/// Parse `name` trimmed and lowercased, defaulting when unset.
fn parse_or_default<T: FromStr + Copy>(
    get_var: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: T,
    reason: &str,
    usable: impl Fn(T) -> bool,
) -> Result<T, ConfigError> {
    let Some(raw) = get_var(name) else {
        return Ok(default);
    };
    match raw.trim().to_ascii_lowercase().parse::<T>() {
        Ok(value) if usable(value) => Ok(value),
        _ => Err(ConfigError::Invalid {
            name: name.to_string(),
            value: raw,
            reason: reason.to_string(),
        }),
    }
}
