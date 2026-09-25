use super::{ConfigError, env};
use huginn_ebpf::EbpfLogLevel;

pub(super) fn resolve_log_level(
    get_var: &impl Fn(&str) -> Option<String>,
) -> Result<EbpfLogLevel, ConfigError> {
    let Some(raw) = get_var(env::LOG_LEVEL) else {
        return Ok(EbpfLogLevel::Off);
    };
    EbpfLogLevel::parse(&raw).ok_or_else(|| {
        ConfigError::invalid(
            env::LOG_LEVEL,
            raw,
            "must be one of: off, error, warn, info, debug, trace (case-insensitive)",
        )
    })
}
