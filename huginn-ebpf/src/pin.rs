use std::path::{Path, PathBuf};

pub const DEFAULT_PIN_BASE: &str = "/sys/fs/bpf/huginn";

// ── IPv4 map / counter names ──────────────────────────────────────────────────
pub const SYN_MAP_V4_NAME: &str = "tcp_syn_map_v4";
pub const COUNTER_NAME: &str = "syn_counter";
pub const SYN_INSERT_FAILURES_V4_NAME: &str = "syn_insert_failures_v4";
pub const SYN_CAPTURED_V4_NAME: &str = "syn_captured_v4";
pub const SYN_MALFORMED_V4_NAME: &str = "syn_malformed_v4";

// ── IPv6 map / counter names ──────────────────────────────────────────────────
pub const SYN_MAP_V6_NAME: &str = "tcp_syn_map_v6";
pub const SYN_INSERT_FAILURES_V6_NAME: &str = "syn_insert_failures_v6";
pub const SYN_CAPTURED_V6_NAME: &str = "syn_captured_v6";
pub const SYN_MALFORMED_V6_NAME: &str = "syn_malformed_v6";

// ── IPv4 path helpers ─────────────────────────────────────────────────────────

pub fn syn_map_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MAP_V4_NAME)
}

pub fn counter_path(base: &str) -> PathBuf {
    Path::new(base).join(COUNTER_NAME)
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

// ── IPv6 path helpers ─────────────────────────────────────────────────────────

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
