use huginn_proxy::ebpf::config::{reconnect_poll_secs, DEFAULT_RECONNECT_POLL_SECS};

#[test]
fn reconnect_poll_uses_default_when_unset_or_invalid() {
    assert_eq!(reconnect_poll_secs(None), DEFAULT_RECONNECT_POLL_SECS);
    assert_eq!(reconnect_poll_secs(Some("invalid")), DEFAULT_RECONNECT_POLL_SECS);
}

#[test]
fn reconnect_poll_accepts_zero_and_positive_values() {
    assert_eq!(reconnect_poll_secs(Some("0")), 0);
    assert_eq!(reconnect_poll_secs(Some("17")), 17);
}
