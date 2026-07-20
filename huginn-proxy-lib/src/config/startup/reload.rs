use serde::{Deserialize, Serialize};

/// Hot-reload / filesystem-watch configuration (`[reload]`).
///
/// Static: read once at startup (changing it requires a restart). Controls whether the proxy watches
/// the config file and TLS certificate files for changes and applies them without a restart. SIGHUP
/// reload works regardless of this setting.
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ReloadConfig {
    /// Watch the config file and TLS certificate files, hot-reloading them on change. Default `true`.
    #[serde(default = "default_watch")]
    pub watch: bool,
    /// Debounce delay in seconds: after a file-change event, wait until changes have been quiet for
    /// this long before applying the reload (a burst of writes triggers a single reload). Default `60`.
    #[serde(default = "default_debounce_secs")]
    pub debounce_secs: u32,
}

fn default_watch() -> bool {
    true
}

fn default_debounce_secs() -> u32 {
    60
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self { watch: default_watch(), debounce_secs: default_debounce_secs() }
    }
}

/// Allowlisted effective-config view of [`ReloadConfig`]. Field names are the JSON keys.
#[derive(Serialize)]
pub(crate) struct ReloadView {
    watch: bool,
    debounce_secs: u32,
}

impl ReloadConfig {
    pub(crate) fn effective_view(&self) -> ReloadView {
        ReloadView { watch: self.watch, debounce_secs: self.debounce_secs }
    }
}
