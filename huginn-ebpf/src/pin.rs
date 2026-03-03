use std::path::{Path, PathBuf};

pub const DEFAULT_PIN_BASE: &str = "/sys/fs/bpf/huginn";
pub const SYN_MAP_NAME: &str = "tcp_syn_map";
pub const COUNTER_NAME: &str = "syn_counter";

pub fn syn_map_path(base: &str) -> PathBuf {
    Path::new(base).join(SYN_MAP_NAME)
}

pub fn counter_path(base: &str) -> PathBuf {
    Path::new(base).join(COUNTER_NAME)
}
