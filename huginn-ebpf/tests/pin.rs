//! T2.4 — Tests for pin path construction.
//! Ensures path helpers produce the expected filenames so agent and proxy agree on map locations.

use std::path::Path;

use huginn_ebpf::pin;

#[test]
fn test_syn_map_v4_path_ends_with_map_name() {
    let path = pin::syn_map_v4_path("/sys/fs/bpf/huginn");
    assert_eq!(path.file_name().and_then(|p| p.to_str()), Some(pin::SYN_MAP_V4_NAME));
}

#[test]
fn test_syn_map_v4_path_joins_base() {
    let base = "/tmp/custom";
    let path = pin::syn_map_v4_path(base);
    assert!(path.starts_with(Path::new(base)));
    assert!(path.ends_with(pin::SYN_MAP_V4_NAME));
}

#[test]
fn test_counter_path_ends_with_map_name() {
    let path = pin::counter_path("/sys/fs/bpf/huginn");
    assert_eq!(path.file_name().and_then(|p| p.to_str()), Some(pin::COUNTER_NAME));
}

#[test]
fn test_insert_failures_path_ends_with_map_name() {
    let path = pin::insert_failures_path("/sys/fs/bpf/huginn");
    assert_eq!(path.file_name().and_then(|p| p.to_str()), Some(pin::SYN_INSERT_FAILURES_NAME));
}

#[test]
fn test_constant_names_match_expected() {
    assert_eq!(pin::SYN_MAP_V4_NAME, "tcp_syn_map_v4");
    assert_eq!(pin::COUNTER_NAME, "syn_counter");
    assert_eq!(pin::SYN_INSERT_FAILURES_NAME, "syn_insert_failures");
}

#[test]
fn test_default_pin_base() {
    assert_eq!(pin::DEFAULT_PIN_BASE, "/sys/fs/bpf/huginn");
}
