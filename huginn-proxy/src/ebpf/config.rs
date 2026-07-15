/// Default interval for detecting eBPF maps replaced by the agent.
pub const DEFAULT_RECONNECT_POLL_SECS: u64 = 5;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("environment variable {name}: invalid value '{value}': {reason}")]
    Invalid {
        name: &'static str,
        value: String,
        reason: &'static str,
    },
}

fn parse_optional_u64(
    name: &'static str,
    raw: Option<String>,
    default: u64,
    reason: &'static str,
) -> Result<u64, ParseError> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|_| ParseError::Invalid { name, value, reason })
    })
    .transpose()
    .map(|opt| opt.unwrap_or(default))
}

fn parse_optional_u32(
    name: &'static str,
    raw: Option<String>,
    default: u32,
    reason: &'static str,
) -> Result<u32, ParseError> {
    raw.map(|value| {
        value
            .parse()
            .map_err(|_| ParseError::Invalid { name, value, reason })
    })
    .transpose()
    .map(|opt| opt.unwrap_or(default))
}

/// Parse `HUGINN_EBPF_RECONNECT_POLL_SECS`, defaulting when unset (same pattern as
/// `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES` in the eBPF agent).
pub fn reconnect_poll_secs_from_env(raw: Option<String>) -> Result<u64, ParseError> {
    parse_optional_u64(
        "HUGINN_EBPF_RECONNECT_POLL_SECS",
        raw,
        DEFAULT_RECONNECT_POLL_SECS,
        "must be a non-negative integer",
    )
}

/// Parse `HUGINN_EBPF_SYN_MAP_MAX_ENTRIES`, defaulting when unset.
pub fn syn_map_max_entries_from_env(raw: Option<String>, default: u32) -> Result<u32, ParseError> {
    parse_optional_u32(
        "HUGINN_EBPF_SYN_MAP_MAX_ENTRIES",
        raw,
        default,
        "must be a positive integer",
    )
}
