use std::path::PathBuf;

/// Options controlling filesystem watching and hot reload.
#[derive(Debug, Clone)]
pub struct WatchOptions {
    /// Path to the TOML config file, required for SIGHUP reload and `--watch` TOML watching.
    /// `None` disables config hot-reload (reload attempts are silently skipped).
    pub config_path: Option<PathBuf>,
    /// Enable filesystem watching for TLS certificate and config hot reload.
    pub watch: bool,
    /// Debounce delay in seconds before applying a reload after a file-change event.
    pub watch_delay_secs: u32,
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self { config_path: None, watch: false, watch_delay_secs: 60 }
    }
}
