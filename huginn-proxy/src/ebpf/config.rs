/// Default interval for detecting eBPF maps replaced by the agent.
pub const DEFAULT_RECONNECT_POLL_SECS: u64 = 5;

/// Parse the reconnect poll interval, falling back to the default for invalid values.
pub fn reconnect_poll_secs(raw: Option<&str>) -> u64 {
    match raw {
        Some(value) => match value.parse::<u64>() {
            Ok(seconds) => seconds,
            Err(error) => {
                tracing::warn!(
                    value,
                    %error,
                    default = DEFAULT_RECONNECT_POLL_SECS,
                    "invalid HUGINN_EBPF_RECONNECT_POLL_SECS, using default"
                );
                DEFAULT_RECONNECT_POLL_SECS
            }
        },
        None => DEFAULT_RECONNECT_POLL_SECS,
    }
}
