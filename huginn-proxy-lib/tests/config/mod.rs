mod audit;
mod effective;
mod header_manipulation;
mod loader;
mod parser;
mod reload;
mod secret;
mod types;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Unique temp-file path for config fixtures, shared across the `config` test submodules.
pub(crate) fn tmp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    std::env::temp_dir().join(format!("huginn-{nanos}-{name}.toml"))
}
