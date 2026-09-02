use std::path::{Path, PathBuf};

pub const DEFAULT_PIN_BASE: &str = "/sys/fs/bpf/huginn";

pub const SYN_MAP_V4_NAME: &str = "tcp_syn_map_v4";
pub const COUNTER_NAME: &str = "syn_counter";
pub const SYN_META_NAME: &str = "syn_meta";
pub const SYN_INSERT_FAILURES_V4_NAME: &str = "syn_insert_failures_v4";
pub const SYN_CAPTURED_V4_NAME: &str = "syn_captured_v4";
pub const SYN_MALFORMED_V4_NAME: &str = "syn_malformed_v4";

pub const SYN_MAP_V6_NAME: &str = "tcp_syn_map_v6";
pub const SYN_INSERT_FAILURES_V6_NAME: &str = "syn_insert_failures_v6";
pub const SYN_CAPTURED_V6_NAME: &str = "syn_captured_v6";
pub const SYN_MALFORMED_V6_NAME: &str = "syn_malformed_v6";

pub const SYN_RATE_SKIPPED_V4_NAME: &str = "syn_rate_skipped_v4";
pub const SYN_RATE_SKIPPED_V6_NAME: &str = "syn_rate_skipped_v6";
pub const SYN_RATE_ALLOWED_V4_NAME: &str = "syn_rate_allowed_v4";
pub const SYN_RATE_ALLOWED_V6_NAME: &str = "syn_rate_allowed_v6";

/// Pin basename for the capture `bpf_link` (TCX / XDP fd-link). Not a BPF map: must not appear
/// in [`ALL_NAMES`] (the loader only passes that list to `map_pin_path`).
pub const CAPTURE_LINK_NAME: &str = "capture_link";

/// Userspace-owned lifecycle map: generation heartbeat, drain flag, agent boot id.
pub const CAPTURE_STATE_NAME: &str = "capture_state";
pub const CAPTURE_STATE_SLOT_GENERATION: u32 = 0;
pub const CAPTURE_STATE_SLOT_LIFECYCLE: u32 = 1;
pub const CAPTURE_STATE_SLOT_BOOT_ID: u32 = 2;
pub const CAPTURE_LIFECYCLE_CAPTURING: u64 = 0;
pub const CAPTURE_LIFECYCLE_DRAINING: u64 = 1;

/// Every map the agent pins and the proxy opens, in no particular order.
pub const ALL_NAMES: [&str; 15] = [
    SYN_MAP_V4_NAME,
    SYN_MAP_V6_NAME,
    COUNTER_NAME,
    SYN_META_NAME,
    SYN_INSERT_FAILURES_V4_NAME,
    SYN_CAPTURED_V4_NAME,
    SYN_MALFORMED_V4_NAME,
    SYN_INSERT_FAILURES_V6_NAME,
    SYN_CAPTURED_V6_NAME,
    SYN_MALFORMED_V6_NAME,
    SYN_RATE_SKIPPED_V4_NAME,
    SYN_RATE_SKIPPED_V6_NAME,
    SYN_RATE_ALLOWED_V4_NAME,
    SYN_RATE_ALLOWED_V6_NAME,
    CAPTURE_STATE_NAME,
];

pub fn syn_map_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MAP_V4_NAME)
}

pub fn counter_path(base: &str) -> PathBuf {
    Path::new(base).join(COUNTER_NAME)
}

pub fn syn_meta_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_META_NAME)
}

pub fn insert_failures_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_INSERT_FAILURES_V4_NAME)
}

pub fn syn_captured_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_CAPTURED_V4_NAME)
}

pub fn syn_malformed_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MALFORMED_V4_NAME)
}

pub fn syn_map_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MAP_V6_NAME)
}

pub fn insert_failures_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_INSERT_FAILURES_V6_NAME)
}

pub fn syn_captured_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_CAPTURED_V6_NAME)
}

pub fn syn_malformed_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MALFORMED_V6_NAME)
}

pub fn syn_rate_skipped_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_RATE_SKIPPED_V4_NAME)
}

pub fn syn_rate_skipped_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_RATE_SKIPPED_V6_NAME)
}

pub fn syn_rate_allowed_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_RATE_ALLOWED_V4_NAME)
}

pub fn syn_rate_allowed_v6_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_RATE_ALLOWED_V6_NAME)
}

/// Default path of the pinned capture link: `{base}/capture_link`.
pub fn capture_link_path(base: &str) -> PathBuf {
    Path::new(base).join(CAPTURE_LINK_NAME)
}

pub fn capture_state_path(base: &str) -> PathBuf {
    Path::new(base).join(CAPTURE_STATE_NAME)
}
