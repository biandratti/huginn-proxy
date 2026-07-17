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

/// Parse `HUGINN_EBPF_RECONNECT_POLL_SECS`, defaulting when unset.
pub fn reconnect_poll_secs_from_env(raw: Option<String>) -> Result<u64, ParseError> {
    raw.map(|value| {
        value.parse().map_err(|_| ParseError::Invalid {
            name: "HUGINN_EBPF_RECONNECT_POLL_SECS",
            value,
            reason: "must be a non-negative integer",
        })
    })
    .transpose()
    .map(|opt| opt.unwrap_or(DEFAULT_RECONNECT_POLL_SECS))
}
