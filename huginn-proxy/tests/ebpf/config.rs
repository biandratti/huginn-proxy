use huginn_ebpf::DEFAULT_SYN_MAP_MAX_ENTRIES;
use huginn_proxy::ebpf::config::{
    reconnect_poll_secs_from_env, syn_map_max_entries_from_env, ParseError,
    DEFAULT_RECONNECT_POLL_SECS,
};

#[test]
fn reconnect_poll_uses_default_when_unset() {
    assert_eq!(reconnect_poll_secs_from_env(None), Ok(DEFAULT_RECONNECT_POLL_SECS));
}

#[test]
fn reconnect_poll_rejects_invalid_values() {
    assert_eq!(
        reconnect_poll_secs_from_env(Some("invalid".to_string())),
        Err(ParseError::Invalid {
            name: "HUGINN_EBPF_RECONNECT_POLL_SECS",
            value: "invalid".to_string(),
            reason: "must be a non-negative integer",
        })
    );
}

#[test]
fn reconnect_poll_accepts_zero_and_positive_values() {
    assert_eq!(reconnect_poll_secs_from_env(Some("0".to_string())), Ok(0));
    assert_eq!(reconnect_poll_secs_from_env(Some("17".to_string())), Ok(17));
}

#[test]
fn syn_map_max_entries_uses_default_when_unset() {
    assert_eq!(
        syn_map_max_entries_from_env(None, DEFAULT_SYN_MAP_MAX_ENTRIES),
        Ok(DEFAULT_SYN_MAP_MAX_ENTRIES)
    );
}

#[test]
fn syn_map_max_entries_rejects_invalid_values() {
    assert_eq!(
        syn_map_max_entries_from_env(Some("nope".to_string()), DEFAULT_SYN_MAP_MAX_ENTRIES),
        Err(ParseError::Invalid {
            name: "HUGINN_EBPF_SYN_MAP_MAX_ENTRIES",
            value: "nope".to_string(),
            reason: "must be a positive integer",
        })
    );
}
