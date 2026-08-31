/// Default interval for detecting eBPF maps replaced by the agent.
pub const DEFAULT_RECONNECT_POLL_SECS: u64 = 5;
/// Default interval for refreshing the capture readiness gate.
pub const DEFAULT_CAPTURE_POLL_SECS: u64 = 1;
/// Polls without a `generation` bump before `capture_detached` on the netlink path.
pub const DEFAULT_CAPTURE_STALE_TICKS: u32 = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("environment variable {name}: invalid value '{value}': {reason}")]
    Invalid {
        name: &'static str,
        value: String,
        reason: &'static str,
    },
}

/// Parse `HUGINN_EBPF_RECONNECT_POLL_SECS`, defaulting when unset. `0` disables map reconnection.
pub fn reconnect_poll_secs_from_env(raw: Option<String>) -> Result<u64, ParseError> {
    parse_u64(raw, "HUGINN_EBPF_RECONNECT_POLL_SECS", DEFAULT_RECONNECT_POLL_SECS, false)
}

/// Parse `HUGINN_EBPF_CAPTURE_POLL_SECS`. Unset → 1. `0` is a configuration error.
pub fn capture_poll_secs_from_env(raw: Option<String>) -> Result<u64, ParseError> {
    parse_u64(raw, "HUGINN_EBPF_CAPTURE_POLL_SECS", DEFAULT_CAPTURE_POLL_SECS, true)
}

/// Parse `HUGINN_EBPF_CAPTURE_STALE_TICKS`. Unset → 3. `0` is a configuration error.
pub fn capture_stale_ticks_from_env(raw: Option<String>) -> Result<u32, ParseError> {
    let secs = parse_u64(
        raw,
        "HUGINN_EBPF_CAPTURE_STALE_TICKS",
        u64::from(DEFAULT_CAPTURE_STALE_TICKS),
        true,
    )?;
    u32::try_from(secs).map_err(|_| ParseError::Invalid {
        name: "HUGINN_EBPF_CAPTURE_STALE_TICKS",
        value: secs.to_string(),
        reason: "must fit in u32",
    })
}

fn parse_u64(
    raw: Option<String>,
    name: &'static str,
    default: u64,
    reject_zero: bool,
) -> Result<u64, ParseError> {
    let value = match raw {
        None => return Ok(default),
        Some(value) => value,
    };
    let parsed = value.parse::<u64>().map_err(|_| ParseError::Invalid {
        name,
        value: value.clone(),
        reason: "must be a non-negative integer",
    })?;
    if reject_zero && parsed == 0 {
        return Err(ParseError::Invalid { name, value, reason: "must be a positive integer" });
    }
    Ok(parsed)
}
