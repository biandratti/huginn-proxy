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
    let path = pin::insert_failures_v4_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_INSERT_FAILURES_V4_NAME)
    );
}

#[test]
fn test_syn_captured_path_ends_with_map_name() {
    let path = pin::syn_captured_v4_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_CAPTURED_V4_NAME)
    );
}

#[test]
fn test_syn_malformed_path_ends_with_map_name() {
    let path = pin::syn_malformed_v4_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_MALFORMED_V4_NAME)
    );
}

#[test]
fn test_constant_names_match_expected() {
    assert_eq!(pin::SYN_MAP_V4_NAME, "tcp_syn_map_v4");
    assert_eq!(pin::COUNTER_NAME, "syn_counter");
    assert_eq!(pin::SYN_INSERT_FAILURES_V4_NAME, "syn_insert_failures_v4");
    assert_eq!(pin::SYN_CAPTURED_V4_NAME, "syn_captured_v4");
    assert_eq!(pin::SYN_MALFORMED_V4_NAME, "syn_malformed_v4");
}

#[test]
fn test_default_pin_base() {
    assert_eq!(pin::DEFAULT_PIN_BASE, "/sys/fs/bpf/huginn");
}

// ── IPv6 paths ────────────────────────────────────────────────────────────────

#[test]
fn test_syn_map_v6_path_ends_with_map_name() {
    let path = pin::syn_map_v6_path("/sys/fs/bpf/huginn");
    assert_eq!(path.file_name().and_then(|p| p.to_str()), Some(pin::SYN_MAP_V6_NAME));
}

#[test]
fn test_insert_failures_v6_path_ends_with_map_name() {
    let path = pin::insert_failures_v6_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_INSERT_FAILURES_V6_NAME)
    );
}

#[test]
fn test_syn_captured_v6_path_ends_with_map_name() {
    let path = pin::syn_captured_v6_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_CAPTURED_V6_NAME)
    );
}

#[test]
fn test_syn_malformed_v6_path_ends_with_map_name() {
    let path = pin::syn_malformed_v6_path("/sys/fs/bpf/huginn");
    assert_eq!(
        path.file_name().and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_MALFORMED_V6_NAME)
    );
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn test_v6_constant_names_match_expected() {
    assert_eq!(pin::SYN_MAP_V6_NAME, "tcp_syn_map_v6");
    assert_eq!(pin::SYN_INSERT_FAILURES_V6_NAME, "syn_insert_failures_v6");
    assert_eq!(pin::SYN_CAPTURED_V6_NAME, "syn_captured_v6");
    assert_eq!(pin::SYN_MALFORMED_V6_NAME, "syn_malformed_v6");
}

#[test]
fn test_v4_and_v6_map_names_differ() {
    assert_ne!(pin::SYN_MAP_V4_NAME, pin::SYN_MAP_V6_NAME);
    assert_ne!(pin::SYN_INSERT_FAILURES_V4_NAME, pin::SYN_INSERT_FAILURES_V6_NAME);
    assert_ne!(pin::SYN_CAPTURED_V4_NAME, pin::SYN_CAPTURED_V6_NAME);
    assert_ne!(pin::SYN_MALFORMED_V4_NAME, pin::SYN_MALFORMED_V6_NAME);
}

#[test]
fn test_all_v6_paths_start_with_base() {
    let base = "/tmp/test-bpf";
    assert!(pin::syn_map_v6_path(base).starts_with(Path::new(base)));
    assert!(pin::insert_failures_v6_path(base).starts_with(Path::new(base)));
    assert!(pin::syn_captured_v6_path(base).starts_with(Path::new(base)));
    assert!(pin::syn_malformed_v6_path(base).starts_with(Path::new(base)));
}

// ── SYN rate-limit counters ───────────────────────────────────────────────────

#[test]
fn test_syn_rate_skipped_paths_end_with_map_name() {
    let base = "/sys/fs/bpf/huginn";
    assert_eq!(
        pin::syn_rate_skipped_v4_path(base)
            .file_name()
            .and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_RATE_SKIPPED_V4_NAME)
    );
    assert_eq!(
        pin::syn_rate_skipped_v6_path(base)
            .file_name()
            .and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_RATE_SKIPPED_V6_NAME)
    );
}

#[test]
fn test_syn_rate_allowed_paths_end_with_map_name() {
    let base = "/sys/fs/bpf/huginn";
    assert_eq!(
        pin::syn_rate_allowed_v4_path(base)
            .file_name()
            .and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_RATE_ALLOWED_V4_NAME)
    );
    assert_eq!(
        pin::syn_rate_allowed_v6_path(base)
            .file_name()
            .and_then(|p: &std::ffi::OsStr| p.to_str()),
        Some(pin::SYN_RATE_ALLOWED_V6_NAME)
    );
}

#[test]
fn test_all_syn_rate_paths_start_with_base() {
    let base = "/tmp/test-bpf";
    assert!(pin::syn_rate_skipped_v4_path(base).starts_with(Path::new(base)));
    assert!(pin::syn_rate_skipped_v6_path(base).starts_with(Path::new(base)));
    assert!(pin::syn_rate_allowed_v4_path(base).starts_with(Path::new(base)));
    assert!(pin::syn_rate_allowed_v6_path(base).starts_with(Path::new(base)));
}

#[test]
fn test_syn_rate_constant_names_match_expected() {
    assert_eq!(pin::SYN_RATE_SKIPPED_V4_NAME, "syn_rate_skipped_v4");
    assert_eq!(pin::SYN_RATE_SKIPPED_V6_NAME, "syn_rate_skipped_v6");
    assert_eq!(pin::SYN_RATE_ALLOWED_V4_NAME, "syn_rate_allowed_v4");
    assert_eq!(pin::SYN_RATE_ALLOWED_V6_NAME, "syn_rate_allowed_v6");
}

#[test]
fn test_syn_rate_v4_and_v6_names_differ() {
    assert_ne!(pin::SYN_RATE_SKIPPED_V4_NAME, pin::SYN_RATE_SKIPPED_V6_NAME);
    assert_ne!(pin::SYN_RATE_ALLOWED_V4_NAME, pin::SYN_RATE_ALLOWED_V6_NAME);
    assert_ne!(pin::SYN_RATE_SKIPPED_V4_NAME, pin::SYN_RATE_ALLOWED_V4_NAME);
}

// ── ALL_NAMES ─────────────────────────────────────────────────────────────────

// The loader pins exactly `ALL_NAMES`, and the agent's readiness probe checks a subset of it
// (`REQUIRED_PINS` in `huginn-ebpf-agent/src/healthchecks.rs`). A name constant that is not in the
// list is never pinned; a list entry that is not a real map name is never pinned either, and if
// that name is also in `REQUIRED_PINS` it makes `/ready` fail forever. Both directions are
// asserted here.

#[test]
fn test_all_names_contains_every_name_constant() {
    for name in [
        pin::SYN_MAP_V4_NAME,
        pin::SYN_MAP_V6_NAME,
        pin::COUNTER_NAME,
        pin::SYN_META_NAME,
        pin::SYN_INSERT_FAILURES_V4_NAME,
        pin::SYN_INSERT_FAILURES_V6_NAME,
        pin::SYN_CAPTURED_V4_NAME,
        pin::SYN_CAPTURED_V6_NAME,
        pin::SYN_MALFORMED_V4_NAME,
        pin::SYN_MALFORMED_V6_NAME,
        pin::SYN_RATE_SKIPPED_V4_NAME,
        pin::SYN_RATE_SKIPPED_V6_NAME,
        pin::SYN_RATE_ALLOWED_V4_NAME,
        pin::SYN_RATE_ALLOWED_V6_NAME,
        pin::CAPTURE_STATE_NAME,
    ] {
        assert!(
            pin::ALL_NAMES.contains(&name),
            "{name} is not in ALL_NAMES, so the loader never pins it"
        );
    }
    assert_eq!(
        pin::ALL_NAMES.len(),
        15,
        "ALL_NAMES has an entry with no matching name constant, or one was not listed above"
    );
}

#[test]
fn test_all_names_has_no_duplicates() {
    let mut sorted: Vec<&str> = pin::ALL_NAMES.to_vec();
    let total = sorted.len();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), total, "ALL_NAMES has a duplicate entry: {:?}", pin::ALL_NAMES);
}

#[test]
fn test_rate_limit_sketches_are_not_pinned() {
    // Ephemeral per-CPU state, deliberately never pinned: it must reset on every agent reload,
    // and the proxy never reads it.
    for name in ["syn_rate_sketch_v4", "syn_rate_sketch_v6"] {
        assert!(!pin::ALL_NAMES.contains(&name), "{name} must not be pinned");
    }
}

#[test]
fn test_capture_link_is_not_a_map_name() {
    assert!(!pin::ALL_NAMES.contains(&pin::CAPTURE_LINK_NAME));
}

#[test]
fn test_capture_link_path_joins_base() {
    let path = pin::capture_link_path("/sys/fs/bpf/huginn");
    assert_eq!(path.file_name().and_then(|p| p.to_str()), Some(pin::CAPTURE_LINK_NAME));
    assert_eq!(pin::CAPTURE_LINK_NAME, "capture_link");
}

#[test]
fn test_capture_mode_labels() {
    use huginn_ebpf::CaptureMode;
    assert_eq!(CaptureMode::Tcx.as_str(), "tcx");
    assert_eq!(CaptureMode::Netlink.as_str(), "netlink");
    assert_eq!(CaptureMode::XdpNative.as_str(), "xdp-native");
    assert_eq!(CaptureMode::XdpSkb.as_str(), "xdp-skb");
}
