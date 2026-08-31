use huginn_proxy::ebpf::config::{
    capture_poll_secs_from_env, capture_stale_ticks_from_env, reconnect_poll_secs_from_env,
    ParseError, DEFAULT_CAPTURE_POLL_SECS, DEFAULT_CAPTURE_STALE_TICKS,
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
fn capture_poll_defaults_to_one_and_rejects_zero() {
    assert_eq!(capture_poll_secs_from_env(None), Ok(DEFAULT_CAPTURE_POLL_SECS));
    assert_eq!(
        capture_poll_secs_from_env(Some("0".to_string())),
        Err(ParseError::Invalid {
            name: "HUGINN_EBPF_CAPTURE_POLL_SECS",
            value: "0".to_string(),
            reason: "must be a positive integer",
        })
    );
    assert_eq!(capture_poll_secs_from_env(Some("2".to_string())), Ok(2));
}

#[test]
fn capture_stale_ticks_defaults_and_rejects_zero() {
    assert_eq!(capture_stale_ticks_from_env(None), Ok(DEFAULT_CAPTURE_STALE_TICKS));
    assert!(capture_stale_ticks_from_env(Some("0".to_string())).is_err());
}
