//! Verbosity control for the in-kernel `aya-log` datapath logging.

/// Verbosity of the in-kernel `aya-log` datapath logging.
///
/// The numeric values match `log::LevelFilter` so the loader can patch the program's `log_level`
/// global directly. A datapath macro at level *L* runs only when the configured level is `>= L`,
/// so [`Off`](Self::Off) is genuinely zero-cost on the hot path and, e.g., [`Warn`](Self::Warn)
/// avoids the per-SYN `debug!` write entirely.
///
/// The capture pipelines currently emit only `debug!` (on capture) and `warn!` (on map-insert
/// failure); the other levels are accepted for completeness and simply never fire today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfLogLevel {
    /// No logging (default). The `aya-log` code is compiled in but never executed.
    #[default]
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl EbpfLogLevel {
    /// Numeric encoding patched into the program's `log_level` global (matches `log::LevelFilter`).
    pub fn as_u8(self) -> u8 {
        match self {
            EbpfLogLevel::Off => 0,
            EbpfLogLevel::Error => 1,
            EbpfLogLevel::Warn => 2,
            EbpfLogLevel::Info => 3,
            EbpfLogLevel::Debug => 4,
            EbpfLogLevel::Trace => 5,
        }
    }

    /// Parse a case-insensitive level name (`off`/`error`/`warn`/`info`/`debug`/`trace`).
    /// Returns `None` for unknown values so callers can build their own error.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "disabled" => Some(EbpfLogLevel::Off),
            "error" => Some(EbpfLogLevel::Error),
            "warn" | "warning" => Some(EbpfLogLevel::Warn),
            "info" => Some(EbpfLogLevel::Info),
            "debug" => Some(EbpfLogLevel::Debug),
            "trace" => Some(EbpfLogLevel::Trace),
            _ => None,
        }
    }

    /// Lowercase canonical name, e.g. for defaulting `RUST_LOG` or logging the resolved config.
    pub fn as_str(self) -> &'static str {
        match self {
            EbpfLogLevel::Off => "off",
            EbpfLogLevel::Error => "error",
            EbpfLogLevel::Warn => "warn",
            EbpfLogLevel::Info => "info",
            EbpfLogLevel::Debug => "debug",
            EbpfLogLevel::Trace => "trace",
        }
    }
}
