use huginn_ebpf::SynRateLimit;
use std::fmt::Display;
use std::str::FromStr;

/// Fallback `burst` when `HUGINN_EBPF_RATE_LIMIT_BURST` is missing or unusable.
pub const DEFAULT_BURST: u32 = 2000;

/// Fallback window when `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` is missing or unusable.
pub const DEFAULT_WINDOW_SECONDS: u64 = 1;

/// Resolve the per-source-IP SYN rate limit from the environment: `HUGINN_EBPF_RATE_LIMIT_BURST`
/// is the per-window per-IP threshold and `HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS` the window.
/// Disabled by default. Not the proxy's `[security.rate_limit]`: this one counts SYNs and is
/// enforced per CPU, so the same number means something different. See `EBPF-SETUP.md`.
///
/// Never fails. A bad value is logged at ERROR and replaced with its default. Exiting would
/// leave the proxy waiting for pinned maps that never appear.
pub(super) fn resolve_rate_limit(get_var: &impl Fn(&str) -> Option<String>) -> SynRateLimit {
    let enabled =
        or_default(get_var, "HUGINN_EBPF_RATE_LIMIT_ENABLED", false, "'true' or 'false'", |_| true);
    if !enabled {
        return SynRateLimit::disabled();
    }

    let max_burst = SynRateLimit::MAX_THRESHOLD;
    let burst = or_default(
        get_var,
        "HUGINN_EBPF_RATE_LIMIT_BURST",
        DEFAULT_BURST,
        &format!("an integer between 1 and {max_burst}"),
        |b| b > 0 && b <= max_burst,
    );
    let max_window = SynRateLimit::MAX_WINDOW_SECONDS;
    let window_seconds = or_default(
        get_var,
        "HUGINN_EBPF_RATE_LIMIT_WINDOW_SECONDS",
        DEFAULT_WINDOW_SECONDS,
        &format!("an integer between 1 and {max_window} (seconds)"),
        |w| w > 0 && w <= max_window,
    );

    SynRateLimit::from_burst_window(true, burst, window_seconds)
}

fn or_default<T: FromStr + Display + Copy>(
    get_var: &impl Fn(&str) -> Option<String>,
    name: &str,
    default: T,
    expected: &str,
    usable: impl Fn(T) -> bool,
) -> T {
    let Some(raw) = get_var(name) else {
        return default;
    };
    match raw.trim().to_ascii_lowercase().parse::<T>() {
        Ok(value) if usable(value) => value,
        _ => {
            tracing::error!(
                name,
                value = %raw,
                expected,
                fallback = %default,
                "invalid eBPF rate-limit configuration; using the default instead"
            );
            default
        }
    }
}
