use std::path::{Path, PathBuf};

pub const DEFAULT_PIN_BASE: &str = "/sys/fs/bpf/huginn";
pub const SYN_MAP_V4_NAME: &str = "tcp_syn_map_v4";
pub const COUNTER_NAME: &str = "syn_counter";
pub const SYN_INSERT_FAILURES_NAME: &str = "syn_insert_failures";

pub fn syn_map_v4_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MAP_V4_NAME)
}

pub fn counter_path(base: &str) -> PathBuf {
    Path::new(base).join(COUNTER_NAME)
}

pub fn insert_failures_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_INSERT_FAILURES_NAME)
}
