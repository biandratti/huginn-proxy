//! In-kernel `aya-log` verbosity. Values match `log::LevelFilter`; patched into the `log_level` global at load time.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfLogLevel {
    #[default]
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl EbpfLogLevel {
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
